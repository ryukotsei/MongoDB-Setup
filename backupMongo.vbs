' do the backup of the mongo database
Set oShell = CreateObject("Shell.Application")

oShell.ShellExecute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -Command ""& 'SCRIPTHERE' 'PORTHERE'""", "", "runas", 1