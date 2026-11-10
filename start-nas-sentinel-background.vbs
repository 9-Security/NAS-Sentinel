Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
strCurrentDir = fso.GetParentFolderName(WScript.ScriptFullName)

' Resolve pythonw: env override → portable runtime → common installs → PATH name
strPythonw = ""
envOverride = WshShell.ExpandEnvironmentStrings("%NAS_SENTINEL_PYTHONW%")
If envOverride <> "%NAS_SENTINEL_PYTHONW%" And envOverride <> "" Then
    If fso.FileExists(envOverride) Then strPythonw = envOverride
End If

portable = strCurrentDir & "\runtime\python\pythonw.exe"
portablePy = strCurrentDir & "\runtime\python\python.exe"
If strPythonw = "" And fso.FileExists(portable) Then strPythonw = portable
If strPythonw = "" And fso.FileExists(portablePy) Then strPythonw = portablePy

userProfile = WshShell.ExpandEnvironmentStrings("%USERPROFILE%")
candidate1 = userProfile & "\AppData\Local\Programs\Python\Python313\pythonw.exe"
candidate2 = userProfile & "\AppData\Local\Programs\Python\Python312\pythonw.exe"
candidate3 = userProfile & "\AppData\Local\Programs\Python\Python311\pythonw.exe"
candidate4 = userProfile & "\AppData\Local\Programs\Python\Python310\pythonw.exe"

If strPythonw = "" Then
    If fso.FileExists(candidate1) Then
        strPythonw = candidate1
    ElseIf fso.FileExists(candidate2) Then
        strPythonw = candidate2
    ElseIf fso.FileExists(candidate3) Then
        strPythonw = candidate3
    ElseIf fso.FileExists(candidate4) Then
        strPythonw = candidate4
    Else
        strPythonw = "pythonw.exe"
    End If
End If

strServerPy = strCurrentDir & "\nas-sentinel\server.py"
strCmd = """" & strPythonw & """ """ & strServerPy & """"

' Set working directory to nas-sentinel so relative imports and data dir are found
WshShell.CurrentDirectory = strCurrentDir & "\nas-sentinel"

' Launch server detached with window hidden (0 = hidden, False = return immediately)
WshShell.Run strCmd, 0, False
