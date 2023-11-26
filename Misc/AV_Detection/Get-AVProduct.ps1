function Get-LHSAntiVirusProduct 
{
<#
.SYNOPSIS
    Get the status of Antivirus Product on local and Remote Computers.
 
.DESCRIPTION
    It works with MS Security Center and detects the status for most AV products.
 
    Note that this script will only work on Windows XP SP2, Vista, 7, 8.x, 10 
    operating systems as Windows Servers does not have 
    the required WMI SecurityCenter\SecurityCenter(2) name spaces.
 
.PARAMETER ComputerName
    The computer name(s) to retrieve the info from. 
 
.EXAMPLE
    Get-LHSAntiVirusProduct
 
    ComputerName             : Localhost
    Name                     : Kaspersky Endpoint Security 10 für Windows
    ProductExecutable        : C:\Program Files (x86)\Kaspersky Lab\Kaspersky Endpoint 
                               Security 10 for Windows SP1\wmiav.exe
    DefinitionStatus         : UP_TO_DATE
    RealTimeProtectionStatus : ON
    ProductState             : 266240
 
.EXAMPLE
    Get-LHSAntiVirusProduct –ComputerName PC1,PC2,PC3
 
    ComputerName             : PC1
    Name                     : Kaspersky Endpoint Security 10 für Windows
    ProductExecutable        : C:\Program Files (x86)\Kaspersky Lab\Kaspersky Endpoint 
                               Security 10 for Windows SP1\wmiav.exe
    DefinitionStatus         : UP_TO_DATE
    RealTimeProtectionStatus : ON
    ProductState             : 266240
    (..)
 
.EXAMPLE
    (get-content PClist.txt) | Get-LHSAntiVirusProduct
 
 .INPUTS
    System.String, you can pipe ComputerNames to this Function
 
.OUTPUTS
    Custom PSObjects 
 
.NOTE
    WMI query to get anti-virus infor­ma­tion has been changed.
    Pre-Vista clients used the root/SecurityCenter name­space, 
    while Post-Vista clients use the root/SecurityCenter2 name­space.
    But not only the name­space has been changed, The properties too. 
 
 
    More info at http://neophob.com/2010/03/wmi-query-windows-securitycenter2/
    and from this MSDN Blog 
    http://blogs.msdn.com/b/alejacma/archive/2008/05/12/how-to-get-antivirus-information-with-wmi-vbscript.aspx
 
 
    AUTHOR: Pasquale Lantella 
    LASTEDIT: 23.06.2016
    KEYWORDS: Antivirus
    Version :1.1
    History :1.1 support for Win 10, changed the use of WMI productState   
 
.LINK
    WSC_SECURITY_PRODUCT_STATE enumeration
    https://msdn.microsoft.com/en-us/library/jj155490%28v=vs.85%29
 
.LINK
    Windows Security Center
    https://msdn.microsoft.com/en-us/library/gg537273%28v=vs.85%29
 
.LINK
    http://neophob.com/2010/03/wmi-query-windows-securitycenter2/
 
#Requires -Version 2.0
#>
 
 
[CmdletBinding()]
 
param (
    [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [Alias('CN')]
    [String[]]$ComputerName=$env:computername
)
 
BEGIN {
 
    Set-StrictMode -Version Latest
    ${CmdletName} = $Pscmdlet.MyInvocation.MyCommand.Name
 
} # end BEGIN
 
PROCESS {
 
    ForEach ($Computer in $computerName) 
    {
        IF (Test-Connection -ComputerName $Computer -count 2 -quiet) 
        { 
            Try
            {
                [system.Version]$OSVersion = (Get-WmiObject win32_operatingsystem -computername $Computer).version
 
                IF ($OSVersion -ge [system.version]'6.0.0.0') 
                {
                    Write-Verbose "OS Windows Vista/Server 2008 or newer detected."
                    $AntiVirusProduct = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ComputerName $Computer -ErrorAction Stop
                } 
                Else 
                {
                    Write-Verbose "Windows 2000, 2003, XP detected" 
                    $AntiVirusProduct = Get-WmiObject -Namespace root\SecurityCenter -Class AntiVirusProduct  -ComputerName $Computer -ErrorAction Stop
                }
 
                <#
                it appears that if you convert the productstate to HEX then you can read the 1st 2nd or 3rd block 
                to get whether product is enabled/disabled and whether definitons are up-to-date or outdated
                #>
                $productState = $AntiVirusProduct.productState
 
                # convert to hex, add an additional '0' left if necesarry
                #$hex = [Convert]::ToString($productState, 16).PadLeft(6,'0')
    			$hex = [convert]::ToString($productState[0], 16).PadLeft(6,'0')
 
 
                # Substring(int startIndex, int length)  
                $WSC_SECURITY_PROVIDER = $hex.Substring(0,2)
                $WSC_SECURITY_PRODUCT_STATE = $hex.Substring(2,2)
                $WSC_SECURITY_SIGNATURE_STATUS = $hex.Substring(4,2)
 
                #n ot used yet
                $SECURITY_PROVIDER = switch ($WSC_SECURITY_PROVIDER)
                {
                    0  {"NONE"}
                    1  {"FIREWALL"}
                    2  {"AUTOUPDATE_SETTINGS"}
                    4  {"ANTIVIRUS"}
                    8  {"ANTISPYWARE"}
                    16 {"INTERNET_SETTINGS"}
                    32 {"USER_ACCOUNT_CONTROL"}
                    64 {"SERVICE"}
                    default {"UNKNOWN"}
                }
 
 
                $RealTimeProtectionStatus = switch ($WSC_SECURITY_PRODUCT_STATE)
                {
                    "00" {"OFF"} 
                    "01" {"EXPIRED"}
                    "10" {"ON"}
                    "11" {"SNOOZED"}
                    default {"UNKNOWN"}
                }
 
                $DefinitionStatus = switch ($WSC_SECURITY_SIGNATURE_STATUS)
                {
                    "00" {"UP_TO_DATE"}
                    "10" {"OUT_OF_DATE"}
                    default {"UNKNOWN"}
                }  
 
<#  
                # Switch to determine the status of antivirus definitions and real-time protection.
                # The values in this switch-statement are retrieved from the following website: http://community.kaseya.com/resources/m/knowexch/1020.aspx
                switch ($AntiVirusProduct.productState) {
                     #AVG Internet Security 2012 (from antivirusproduct WMI)
                     "262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
                     "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
 
                     "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
                     "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
                     "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
                     "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
                     "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
                     "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
                     "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
                     #Windows Defender
                     "393472" {$defstatus = "Up to date" ;$rtstatus = "Disabled"} 
                     "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
                     "397568" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
 
                     default {$defstatus = "Unknown" ;$rtstatus = "Unknown"}
                }
#>
 
 
                # Output PSCustom Object
                $AV = $Null
                $AV = New-Object -TypeName PSObject -ErrorAction Stop -Property @{
 
                    ComputerName = $AntiVirusProduct.__Server;
                    Name = $AntiVirusProduct.displayName;
                    ProductExecutable = $AntiVirusProduct.pathToSignedProductExe;
                    ReportingExecutable = $AntiVirusProduct.pathToSignedReportingExe;
                    DefinitionStatus = $DefinitionStatus;
                    RealTimeProtectionStatus = $RealTimeProtectionStatus;
                    ProductState = $productState;
 
                } | Select-Object ComputerName,Name,ProductExecutable,ReportingExecutable,DefinitionStatus,RealTimeProtectionStatus,ProductState  
 
                Write-Output $AV 
            }
            Catch 
            {
                Write-Error "\\$Computer : WMI Error"
                Write-Error $_
            }                              
        } 
        Else 
        {
            Write-Warning "\\$computer DO NOT reply to ping" 
        } # end IF (Test-Connection -ComputerName $Computer -count 2 -quiet)
 
    } # end ForEach ($Computer in $computerName)
 
} # end PROCESS
 
END { Write-Verbose "Function Get-LHSAntiVirusProduct finished." } 
} # end function Get-LHSAntiVirusProduct
 
Get-LHSAntiVirusProduct