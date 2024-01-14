# Binaries

## ToC

| Application | Output | Notes |
| ----------- | ------ | ----- |
| `bins/x64_met_staged_reversetcp_inject.exe` | N/A | Command line args: IP PORT PROCESS_TO_INJECT(explorer) |
| `bins/x64_met_staged_reversetcp_hollow.exe` | N/A | Command line args: IP PORT PROCESS_TO_HOLLOW(c:\\windows\\system32\\svchost.exe) PPID_SPOOF(explorer) |
| `bins/x64_met_staged_reversehttps_inject.exe` | N/A | Command line args: IP PORT PROCESS_TO_INJECT(explorer) |
| `bins/x64_met_staged_reversehttps_hollow.exe` | N/A | Command line args: IP PORT PROCESS_TO_HOLLOW(c:\\windows\\system32\\svchost.exe) PPID_SPOOF(explorer)  |


This directory just holds precompiled binaries created with the `clhollow` and `clinject` projects using `windows/x64/meterpreter/reverse_https` and `windows/x64/meterpreter/reverse_tcp` payloads.
