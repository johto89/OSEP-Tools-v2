# Miscellaneous

## ToC

| Application | Output | Notes |
| ----------- | ------ | ----- |
| `Autos` | N/A | Scripts to automate things I found myself doing a lot |
| `AV_Detection` | PS | Basic scripts for AV/Applocker Enumertion |
| `Fileless_Lateral_Movement` | EXE | PSExec-like tool utilizing remote service configuration for lateral movement |
| `MiniDump` | EXE/PS | A simple binary to Dump LSASS to a file for offline examination |


## `Autos`
Scripts to automate things I found myself doing a lot

### Tools
- `Create-Admin.ps1`
    - Create a local Administrator user on the box and enable RDP
    - Requires: High Integrity process

## `AV_Detection`
Basic scripts for AV/Applocker Enumertion that I created myself / found online. They're super basic right now, but I plan to fix them up soon.

### Tools
- `Get-AVProduct.ps1` 
    - Get the status of Antivirus Product on local and Remote Computers
    - Credits: `SyncroMSP` at [mspscripts.com](https://mspscripts.com/get-installed-antivirus-information-2/)
- `Get-AVProduct.min.ps1`
    - A more concise `Get-AVProduct.ps1` for active use

## `Fileless_Lateral_Movement`

Wipes Windows Defender signatures on the *remote host* and uses a `PSExec`-like method (except using an existing process) to achieve lateral movement. Takes arguments for the target, the target service, and the target binary to run. Note that a non-critical service should be chosen, such as `SensorService`.

### Usage

```
Usage:   PSLessExec.exe [Target] [Service]     [BinaryToRun]
Example: PSLessExec.exe appsrv01 SensorService notepad.exe
```

## `MiniDump`
A simple binary to Dump LSASS to `C:\Windows\Tasks\lsass.dmp`. Also provided as a native PowerShell script.
