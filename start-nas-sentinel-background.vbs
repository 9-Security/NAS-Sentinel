Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
strCurrentDir = fso.GetParentFolderName(WScript.ScriptFullName)

Function IsWindowsAppsStub(path)
    IsWindowsAppsStub = False
    If path = "" Then Exit Function
    If InStr(1, LCase(path), "\windowsapps\", vbTextCompare) > 0 Then IsWindowsAppsStub = True
End Function

' Resolve pythonw: env override → portable runtime → common installs (never bare PATH / WindowsApps)
strPythonw = ""
envOverride = WshShell.ExpandEnvironmentStrings("%NAS_SENTINEL_PYTHONW%")
If envOverride <> "%NAS_SENTINEL_PYTHONW%" And envOverride <> "" Then
    If fso.FileExists(envOverride) And Not IsWindowsAppsStub(envOverride) Then strPythonw = envOverride
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
    End If
End If

' Do not fall back to bare "pythonw.exe" — Windows Store stubs break silent launch.
If strPythonw = "" Or IsWindowsAppsStub(strPythonw) Then
    WScript.Quit 1
End If

strServerPy = strCurrentDir & "\nas-sentinel\server.py"
strCmd = """" & strPythonw & """ """ & strServerPy & """"

' Set working directory to nas-sentinel so relative imports and data dir are found
WshShell.CurrentDirectory = strCurrentDir & "\nas-sentinel"

' Launch server detached with window hidden (0 = hidden, False = return immediately)
WshShell.Run strCmd, 0, False
