# Privilege Escalation

## ToC

| Application | Output | Notes |
| ----------- | ------ | ----- |
| `PrintSpoofer.NET` | EXE | Creates a pipe and impersonates tokens to run a binary |
| `SpoolSample.exe` | N/A | Coerce Windows hosts to authenticate to other machines via the MS-RPRN RPC interface |
| `UACBypass.ps1` | PS | FODhelper UAC Bypass script |
| `shakeitoff` | EXE | CVE-2021-43883. Replace a target privilege binary with a binary of your choice then run it with SYSTEM privileges |

## `PrintSpoofer.NET`

Steals the token of the incoming authentication forced with the PrintSpooler exploit, and use that token to run a given binary. *Modified to not require an interactive logon session*. Takes arguments for the pipe name and binary to run.

Requires another tool (`SpoolSample.exe`) to trigger the pipe authentication from our target process.

## `SpoolSample.exe`

Precompiled binary of the [SpoolSample](https://github.com/leechristensen/SpoolSample) tool to coerce Windows hosts authenticate to other machines via the MS-RPRN RPC interface. For use with the `PrintSpoofer.NET` binary.

## `UACBypass.ps1`

UAC bypass using FODhelper covered in PEN-300 Section 7.5.1 to elevate privileges on a user account who has *Administrator* privs but is running in a medium integrity process.

### Usage
Obviously there are many ways, but you can just load it as a module. 
```ps1
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass;. .\UACBypass.ps1
```

## `shakeitoff`

Modification of [jbaines-r7/shakeitoff](https://github.com/jbaines-r7/shakeitoff) (CVE-2021-41379 variant) that allows a user to specify a file to replace a malicious binary with and then starts the Microsoft Edge Elevation Service in order to execute the malicous binary.

You need both the `shakeitoff.exe` and the `shakeitoff.msi` on target.  Note that this will replace the `elevation_service.exe` so make a copy of it if you need to restore! This of course requires that edge is installed on the target machine, and that the service exists. 

Tested successfully on Windows 10, 11, Server 2016, and Server 2019. This is patched as of Dec 14th 2021 (KB5008212) and was assigned the new CVE-2021-43883. Additionally a switch was added to allow the user to specify what file they wish to overwrite the target file with (as opposed to the original POC's which overwrote the target file with the POC).

Check out [its own README](./shakeitoff/README.md) or the above linked repo for more information on the exploit and how to use it. More details on the underlying vulnerability at [AttackerKB-CVE-2021-41379](https://attackerkb.com/topics/7LstI2clmF/cve-2021-41379/rapid7-analysis).

### Usage
```
shakeitoff.exe -m c:\users\user\shakeitoff\shakeitoff.msi -i c:\users\user\write\ -c c:\users\user\source\repos\d_invoke\inject.exe -p "C:\Program Files (x86)\Microsoft\Edge\Application\96.0.1054.53\elevation_service.exe"
```
