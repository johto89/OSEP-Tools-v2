# Loaders - Memory

Tools that aid in loading shellcode into memory, *from memory*. Usually scripts fetched remotely in powershell.

## ToC

| Application | Output | Notes |
| ----------- | ------ | ----- |
| `Powerinject.py` | PS | Python3 script to generate .PS1 payloads that perform process injection. |
| `Powerhollow.py` | PS | Python3 script to generate .PS1 payloads that perform process hollowing with PPID spoofing |


## [powerhollow.py](./powerhollow.py) and [powerinject.py](./powerinject.py)

These python scripts call `msfvenom` to generate shellcode, AES encrypt it, and then embed it within hardcoded powershell code in order to dynamically produce *.PS1* payloads according to user supplied options.  These *.PS1* payloads are modeled after the OSEP *.PS1* that utilizes dynamic lookup rather than `add-type` in order to prevent writing to disk when calling `csc`.  

`Powerinject.py` payloads succeed here; however I was unable to find a way to define the structs necessary for doing PPID spoofing with Process hollowing, so **add-type IS called in the `Powerhollow.py`** *.PS1* payloads, however this is only done for the necessesary structs and the `createproces()` Win32API. All other required API's are resolved dynamically.

Run the appropriate python script for the kind of payload you want to use and then place the produced files in your webserver directory and use the supplied PS one liner in order to call them. If you see in the debug output that its failing to open a process, try a couple times more. Sometimes there just isn't a suitable process to inject into but after a couple tries it finds one.

### Updates from OSEP-Tools version
- `powerinject.py` payloads now detect if they are being run in a 32-bit PS context, and auto download-and-execute themselves in a 64-bit process.
  - This is useful if your stager is ran from a 32-bit process (Word Macros), resulting in a 32-bit PS process.
- You can now use the `-D` argument to have the payload output useful debugging statements and help you determine where in the process of setting up the reverse shell it is failing.
- You no longer have to specify the integrity of your target process, as the script will determine the current process's permissions and lookup processes based on it, going for SYSTEM if elevated.
- You may now specify "`any`" as an argument for the target process, to increase the odds of finding a suitable process to inject into.
  - Useful when targetting servers where there are few to zero processes where you can inject into (i.e. they're all running elevated and you're attempting to get initial access with low privs)
  - **NOTE**: You may inject into some interesting processes which could lead to unstable shells (if you inject into ephemeral procs), or unstable systems (if you inject into a sensitive important proc). I've had good results with it though.
