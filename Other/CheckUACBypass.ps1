<#
.SYNOPSIS
    UAC Bypass Posture & Artifact Auditor.

.DESCRIPTION
    Audits a Windows host for (a) configuration that makes it susceptible to
    known UAC bypass techniques and (b) on-disk / registry artifacts left behind
    by common bypass primitives (fodhelper, eventvwr, sdclt, computerdefaults,
    slui, DiskCleanup/windir, mscfile).

    Findings are emitted as structured objects so they can be piped to
    Export-Csv / ConvertTo-Json for reporting. Use -AsJson for machine output.

    Read-only by design: the script never writes to the registry or filesystem
    and never loads untrusted binaries into the process.

.NOTES
    Author : Johto Robbie
    License: GPLv3

    Severity legend:
        Critical / High / Medium / Low / Info

.EXAMPLE
    .\UAC-BypassAudit.ps1

.EXAMPLE
    .\UAC-BypassAudit.ps1 -AsJson | Out-File audit.json -Encoding utf8
#>

[CmdletBinding()]
param(
    [switch]$AsJson,
    # Suspicious command-string patterns used to flag hijacked shell commands.
    [string[]]$SuspiciousCommandPatterns = @(
        'cmd(\.exe)?', 'powershell', 'pwsh', 'wscript', 'cscript', 'mshta',
        'rundll32', 'regsvr32', '\\temp\\', '%temp%', '\\appdata\\',
        '\\users\\public\\', 'certutil', 'bitsadmin', '-enc', '-e\s', 'FromBase64'
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Helpers -----------------------------------------------------------------

$script:Findings = [System.Collections.Generic.List[object]]::new()

function New-Finding {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [string]$Detail,
        [object]$Evidence
    )
    $script:Findings.Add([PSCustomObject]@{
        Timestamp = (Get-Date).ToString('o')
        Category  = $Category
        Severity  = $Severity
        Title     = $Title
        Detail    = $Detail
        Evidence  = $Evidence
    })
}

function Test-IsAdministrator {
    # True only when the current process token is actually elevated (High IL+).
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($id)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ProcessIntegrityLevel {
    # Resolve the integrity level of the current token from its mandatory-label SID,
    # which is language-independent (unlike parsing `whoami /groups` text).
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $labelSid = ($id.Groups | Where-Object {
            $_.Value -like 'S-1-16-*'
        } | Select-Object -First 1).Value

        switch ($labelSid) {
            'S-1-16-4096'  { 'Low' }
            'S-1-16-8192'  { 'Medium' }
            'S-1-16-8448'  { 'MediumPlus' }
            'S-1-16-12288' { 'High' }
            'S-1-16-16384' { 'System' }
            default        { "Unknown ($labelSid)" }
        }
    } catch {
        'Unknown'
    }
}

function Get-EmbeddedManifestText {
    # Extract the embedded RT_MANIFEST (resource type 24) text from a PE without
    # executing it, by loading the file as a resource-only module.
    param([Parameter(Mandatory)][string]$Path)

    $signature = @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class ManifestReader {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr LoadLibraryEx(string f, IntPtr h, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool FreeLibrary(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr FindResource(IntPtr h, IntPtr name, IntPtr type);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr LoadResource(IntPtr h, IntPtr res);
    [DllImport("kernel32.dll")]
    static extern IntPtr LockResource(IntPtr data);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint SizeofResource(IntPtr h, IntPtr res);

    const uint LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020;
    const uint LOAD_LIBRARY_AS_DATAFILE       = 0x00000002;

    public static string Read(string path) {
        IntPtr hMod = LoadLibraryEx(path, IntPtr.Zero,
            LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE);
        if (hMod == IntPtr.Zero) return null;
        try {
            // RT_MANIFEST = 24, CREATEPROCESS_MANIFEST_RESOURCE_ID = 1
            IntPtr hRes = FindResource(hMod, (IntPtr)1, (IntPtr)24);
            if (hRes == IntPtr.Zero) return string.Empty;
            uint size = SizeofResource(hMod, hRes);
            IntPtr hData = LoadResource(hMod, hRes);
            if (hData == IntPtr.Zero || size == 0) return string.Empty;
            IntPtr p = LockResource(hData);
            byte[] buf = new byte[size];
            Marshal.Copy(p, buf, 0, (int)size);
            return Encoding.UTF8.GetString(buf);
        } finally {
            FreeLibrary(hMod);
        }
    }
}
'@
    if (-not ('ManifestReader' -as [type])) {
        Add-Type -TypeDefinition $signature -ErrorAction Stop
    }
    try { return [ManifestReader]::Read($Path) } catch { return $null }
}

function Test-FileMicrosoftSigned {
    param([Parameter(Mandatory)][string]$Path)
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        return ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'Microsoft')
    } catch {
        return $false
    }
}

#endregion Helpers --------------------------------------------------------------

#region Checks ------------------------------------------------------------------

function Invoke-UACLevelCheck {
    $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    try {
        $s = Get-ItemProperty -Path $path -ErrorAction Stop
    } catch {
        New-Finding -Category 'UAC Config' -Severity 'Info' `
            -Title 'Cannot read UAC policy' -Detail $_.Exception.Message
        return
    }

    function Get-Prop($obj, $name) {
        $p = $obj.PSObject.Properties[$name]
        if ($p) { $p.Value } else { $null }
    }
    $enableLUA     = Get-Prop $s 'EnableLUA'
    $consentAdmin  = Get-Prop $s 'ConsentPromptBehaviorAdmin'
    $secureDesktop = Get-Prop $s 'PromptOnSecureDesktop'

    if ($enableLUA -eq 0) {
        New-Finding -Category 'UAC Config' -Severity 'Critical' `
            -Title 'UAC fully disabled (EnableLUA=0)' `
            -Detail 'All processes for admins run at High IL; UAC provides no boundary.' `
            -Evidence @{ EnableLUA = $enableLUA }
    }
    # ConsentPromptBehaviorAdmin: 0 = elevate without prompting (vulnerable),
    # 2 = prompt on secure desktop (strongest), 5 = default (prompt for non-Windows binaries)
    if ($consentAdmin -eq 0) {
        New-Finding -Category 'UAC Config' -Severity 'High' `
            -Title 'Admin consent prompt disabled (ConsentPromptBehaviorAdmin=0)' `
            -Detail 'Elevation occurs silently; auto-elevate bypasses are trivial.' `
            -Evidence @{ ConsentPromptBehaviorAdmin = $consentAdmin }
    }
    if ($secureDesktop -eq 0) {
        New-Finding -Category 'UAC Config' -Severity 'Medium' `
            -Title 'Secure desktop disabled (PromptOnSecureDesktop=0)' `
            -Detail 'Consent prompt is spoofable from the user desktop.' `
            -Evidence @{ PromptOnSecureDesktop = $secureDesktop }
    }
    if ($enableLUA -ne 0 -and $consentAdmin -ne 0 -and $secureDesktop -ne 0) {
        New-Finding -Category 'UAC Config' -Severity 'Info' `
            -Title 'UAC configured sensibly' `
            -Evidence @{ EnableLUA=$enableLUA; ConsentPromptBehaviorAdmin=$consentAdmin; PromptOnSecureDesktop=$secureDesktop }
    }
}

function Invoke-ElevationContextCheck {
    $isAdmin = Test-IsAdministrator
    $il      = Get-ProcessIntegrityLevel

    if ($isAdmin -and $il -eq 'Medium') {
        New-Finding -Category 'Context' -Severity 'Medium' `
            -Title 'Admin user running at Medium IL' `
            -Detail 'Member of Administrators but not elevated. UAC bypass would be the path to High IL. Also: many checks below need elevation to be reliable.' `
            -Evidence @{ IsAdmin=$isAdmin; IntegrityLevel=$il }
    } else {
        New-Finding -Category 'Context' -Severity 'Info' `
            -Title 'Elevation context' `
            -Evidence @{ IsAdmin=$isAdmin; IntegrityLevel=$il }
    }

    if (-not $isAdmin) {
        New-Finding -Category 'Context' -Severity 'Info' `
            -Title 'Running without elevation — results may be incomplete' `
            -Detail 'Scheduled tasks, some services and HKLM reads may be partial. Re-run elevated for full coverage.'
    }
}

function Invoke-BypassArtifactCheck {
    # Hijack points are HKCU shell-command / env keys that known bypasses write.
    # A *normal* system does NOT have these user-level overrides, so their
    # presence is itself suspicious; a suspicious command string raises severity.
    $targets = @(
        @{ Technique='mscfile (eventvwr)';        Path='HKCU:\Software\Classes\mscfile\Shell\Open\command';     Value='(default)' }
        @{ Technique='ms-settings (fodhelper/computerdefaults)'; Path='HKCU:\Software\Classes\ms-settings\Shell\Open\command'; Value='(default)' }
        @{ Technique='ms-settings DelegateExecute'; Path='HKCU:\Software\Classes\ms-settings\Shell\Open\command'; Value='DelegateExecute' }
        @{ Technique='Folder (sdclt)';            Path='HKCU:\Software\Classes\Folder\shell\open\command';      Value='(default)' }
        @{ Technique='exefile (slui)';            Path='HKCU:\Software\Classes\exefile\Shell\Open\command';     Value='(default)' }
        @{ Technique='windir env (DiskCleanup)';  Path='HKCU:\Environment';                                     Value='windir' }
    )

    foreach ($t in $targets) {
        try {
            if (-not (Test-Path $t.Path)) { continue }
            $item = Get-ItemProperty -Path $t.Path -ErrorAction Stop
            $prop = $item.PSObject.Properties[$t.Value]
            if ($null -eq $prop) { continue }
            $data = [string]$prop.Value

            # windir normally resolves to C:\Windows; anything else is a classic hijack.
            $looksHijacked =
                ($t.Value -eq 'windir' -and $data -and $data -notmatch '^[A-Za-z]:\\Windows\\?$') -or
                ($t.Value -ne 'windir')

            if (-not $looksHijacked) { continue }

            $suspicious = $false
            foreach ($p in $SuspiciousCommandPatterns) {
                if ($data -match $p) { $suspicious = $true; break }
            }

            New-Finding -Category 'Bypass Artifact' `
                -Severity ($(if ($suspicious) { 'Critical' } else { 'High' })) `
                -Title "Hijack key present: $($t.Technique)" `
                -Detail "HKCU override exists where a clean system has none$(if($suspicious){'; command string matches a suspicious pattern'})." `
                -Evidence @{ Path=$t.Path; Value=$t.Value; Data=$data }
        } catch {
            New-Finding -Category 'Bypass Artifact' -Severity 'Info' `
                -Title "Error reading $($t.Path)" -Detail $_.Exception.Message
        }
    }
}

function Invoke-AutoElevateManifestCheck {
    # Correctly detect auto-elevate binaries by reading the embedded manifest,
    # NOT by inspecting .NET attributes. Scope to System32 and skip giant/
    # already-known-signed noise by only reporting the elevated set.
    $dir = Join-Path $env:WINDIR 'System32'
    $exes = Get-ChildItem -Path $dir -Filter '*.exe' -File -ErrorAction SilentlyContinue
    $count = 0
    foreach ($exe in $exes) {
        try {
            $manifest = Get-EmbeddedManifestText -Path $exe.FullName
            if ([string]::IsNullOrEmpty($manifest)) { continue }
            if ($manifest -match '<autoElevate>\s*true\s*</autoElevate>') {
                $count++
                # These are legitimate Windows auto-elevate binaries; list them so
                # the analyst can cross-check them against the hijack keys above.
                New-Finding -Category 'AutoElevate' -Severity 'Info' `
                    -Title "Auto-elevate binary: $($exe.Name)" `
                    -Detail 'Legitimate OS binary that auto-elevates; a candidate target for registry-hijack bypasses.' `
                    -Evidence @{ Path=$exe.FullName; Signed=(Test-FileMicrosoftSigned $exe.FullName) }
            }
        } catch { continue }
    }
    if ($count -eq 0) {
        New-Finding -Category 'AutoElevate' -Severity 'Info' `
            -Title 'No auto-elevate manifests found (or insufficient privileges to read)'
    }
}

function Invoke-ServiceCheck {
    # LocalSystem auto/manual services are an attack surface for privilege abuse.
    # Flag only those whose binary path is unquoted-with-spaces or non-system,
    # which is the condition that actually matters — not merely "runs as SYSTEM".
    try {
        $services = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
            Where-Object { $_.StartName -eq 'LocalSystem' -and $_.StartMode -in @('Auto','Manual') }
    } catch {
        New-Finding -Category 'Services' -Severity 'Info' `
            -Title 'Cannot enumerate services' -Detail $_.Exception.Message
        return
    }

    foreach ($svc in $services) {
        $pathName = $svc.PathName
        if ([string]::IsNullOrWhiteSpace($pathName)) { continue }

        # Extract the executable path (handles quoted and unquoted).
        $exePath = if ($pathName -match '^\s*"([^"]+)"') { $matches[1] }
                   elseif ($pathName -match '^\s*(\S+\.exe)') { $matches[1] }
                   else { $pathName }

        $unquotedWithSpaces = ($pathName -notmatch '^\s*"') -and ($exePath -match '\s')

        if ($unquotedWithSpaces) {
            New-Finding -Category 'Services' -Severity 'High' `
                -Title "Unquoted service path: $($svc.Name)" `
                -Detail 'LocalSystem service with unquoted path containing spaces — classic privilege escalation vector.' `
                -Evidence @{ Service=$svc.Name; PathName=$pathName }
        }
    }
}

function Invoke-PhantomDllCheck {
    # Real DLL-hijack detection for auto-elevate flows: check whether DLLs that
    # elevated binaries are known to probe are ABSENT from System32 (phantom),
    # which would let an attacker plant one. Presence of a legit system DLL is
    # NOT a finding (this is the bug in the original script).
    $phantomCandidates = @('wow64log.dll')  # not present on normal systems; loadable by 64-bit elevated procs
    $sys32 = Join-Path $env:WINDIR 'System32'

    foreach ($dll in $phantomCandidates) {
        $full = Join-Path $sys32 $dll
        if (-not (Test-Path $full)) {
            New-Finding -Category 'DLL Hijack' -Severity 'Info' `
                -Title "Phantom DLL slot available: $dll" `
                -Detail 'Absent from System32 and probed by elevated processes. Not an active compromise, but monitor System32 write access to this name.' `
                -Evidence @{ ExpectedPath=$full }
        } else {
            # It exists — only interesting if it is NOT Microsoft-signed.
            if (-not (Test-FileMicrosoftSigned $full)) {
                New-Finding -Category 'DLL Hijack' -Severity 'Critical' `
                    -Title "Unsigned DLL in System32: $dll" `
                    -Detail 'A normally-absent DLL exists here and is not Microsoft-signed — strong indicator of a planted hijack DLL.' `
                    -Evidence @{ Path=$full }
            }
        }
    }
}

function Invoke-HighPrivTaskCheck {
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop |
            Where-Object { $_.Principal.RunLevel -eq 'Highest' }
    } catch {
        New-Finding -Category 'Scheduled Tasks' -Severity 'Info' `
            -Title 'Cannot enumerate scheduled tasks' -Detail $_.Exception.Message
        return
    }
    foreach ($t in $tasks) {
        New-Finding -Category 'Scheduled Tasks' -Severity 'Info' `
            -Title "Highest-privilege task: $($t.TaskName)" `
            -Detail 'Runs with highest privileges; review the action/trigger and the principal for abuse potential.' `
            -Evidence @{ TaskPath=$t.TaskPath; TaskName=$t.TaskName; UserId=$t.Principal.UserId }
    }
}

#endregion Checks ---------------------------------------------------------------

#region Main --------------------------------------------------------------------

Invoke-ElevationContextCheck
Invoke-UACLevelCheck
Invoke-BypassArtifactCheck
Invoke-AutoElevateManifestCheck
Invoke-ServiceCheck
Invoke-PhantomDllCheck
Invoke-HighPrivTaskCheck

if ($AsJson) {
    $script:Findings | ConvertTo-Json -Depth 6
} else {
    $order = @{ Critical=0; High=1; Medium=2; Low=3; Info=4 }
    $script:Findings |
        Sort-Object { $order[$_.Severity] }, Category |
        Format-Table Severity, Category, Title -AutoSize -Wrap

    $summary = $script:Findings | Group-Object Severity |
        Sort-Object { $order[$_.Name] } |
        ForEach-Object { "$($_.Name): $($_.Count)" }
    Write-Host ""
    Write-Host ("Summary -> " + ($summary -join '  |  '))
}

#endregion Main -----------------------------------------------------------------
