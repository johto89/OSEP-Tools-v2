# Linux Tools

## ToC

| Application | Output | Notes |
| ----------- | ------ | ----- |
| `Linux_Shellcode_Loaders` | ELF/SO | Various C-based shellcode loaders, including base binaries for library hijacking. |
| `Linux_Shellcode_Encoder` | ASCII | Utility scripts to encode C# payloads from Linux, either ingesting a raw shellcode payload (.bin), or automatically feeding from 'msfvenom'. |


## `Linux_Shellcode_Loaders`

Various C-based shellcode loaders, including base binaries for library hijacking.

`sharedLibrary_LD_LIBRARY_PATH.c` covers the LIBRARY_PATH exploit technique covered in PEN-300 Section 10.3.2 and you have to add in the symbols for your target library yourself.

`sharedLibrary_LD_PRELOAD.c` covers the PRELOAD exploit technique covered in PEN-300 Section 10.3.3 and by default hooks the `geteuid()` method like in the course.

`simpleLoader.c` covers the simple shellcode loader covered in PEN-300 Section 10.2.1 but it has an XOR-encoded payload. You have to edit it to change IP/Port etc, then run the msfvenom output through `simpleXORencoder.c` before putting it in this loader.

`simpleXORencoder.c` is what you can use to take a standard msfvenom payload and XOR it with a key of your choice.

## `Linux_Shellcode_Encoders`

Utility scripts to encode C#/CPP payloads from Linux. `shellcodeCrypter-bin.py` ingests a raw shellcode payload from a *.bin* file. `shellcodeCrypter-msfvenom.py` creates the `msfvenom` payload itself, then encodes it.

Supports XOR and ROT encoding with an arbitrary key, and prints the decoding function. Can be used to replace the C#/CPP ROT/XOR encoder scripts.

