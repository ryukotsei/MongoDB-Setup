#param($port)
$port = "27017"
Function Write-Log { # output to logFile
    param($message)
    If ($consoleOutput -eq $true) {
        Write-Host $message
    }
    $logDate = Get-Date -UFormat "%m/%d/%Y %H:%M:%S%p"
    $message = $message -replace "`n","" -replace "`t",""
    "$logDate   $message" | Out-File $logFile -NoClobber -Confirm:$false -Force -Append
}

Function Confirm-Directory { # create dir if not exist
    param($dir)
    If (!(Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Confirm:$false -Force
    }
}

Function Backup-Cleanup {
    Write-Log "Cleaning up old backups..."

    $tooOld = (Get-Date).AddDays($backupAge) # 1 month ago
    $backups = Get-ChildItem -Path "$backupDir\*" -Directory
    $backups | ForEach-Object {
        $backup = $_.Name.Replace("bak_","")
        $day = $backup.Substring(0,2) # position 0,forward 2 characters
        $month = $backup.Substring(2,2)
        $year = $backup.Substring(4,4)

        $bakDate = [datetime]"$day/$month/$year"
        If (!($bakDate -gt $tooOld)) { # if Folder date NOT -gt 1month ago   | example Sunday, January 1, 2017 12:00:00 AM (IS NOT) -gt Friday, May 12, 2017 1:54:40 PM = True | not earlier than the ealiest date it can be
            Remove-Item $_ -Recurse -Confirm:$false -Force
            Write-Log "Removed old backup directory: $_"
        }
    }
    Write-Log "Cleanup done."
}

# creates snapshot or --oplog: located in top lvl of output dir, called: oplog.bson
# only required on primary?


# variables - change to enviro
$global:defaultRoot = "C:\MongoOthers"
$global:consoleOutput = $true # output logging to console
$global:rsName = "rs0" # replicaSet name
$global:mongoRoot = "C:\Program Files\MongoDB\Server\3.4\bin"
$global:backupAge = -8 # negative days in the past for how long to keep backups
# $database = "chartis"
# $collections = @("incidents","bookmarks","markups")
$computerName = $env:COMPUTERNAME # probably ok



# variables - leave!
#$scriptDir = Split-Path $script:MyInvocation.MyCommand.Path
$global:mongoBackup = Join-Path -Path $mongoRoot -ChildPath "mongodump.exe"
$global:backupDir =  Join-Path -Path $defaultRoot -ChildPath "backups"
$global:logFile = Join-Path -Path $backupDir -ChildPath "backupLog.log"
# $env:COMPUTERNAME

Write-Log "Starting backup process..."

$now = Get-Date -Format "MMddyyyy"
$dailyBackupDir = Join-Path -Path $backupDir -ChildPath "bak_$now"

Confirm-Directory -dir $backupDir

# setup the backup directory
If ((Test-Path $dailyBackupDir)) { # delete if already exist for some reason
    Remove-Item -Path "$dailyBackupDir\*" -Recurse -Confirm:$false -Force
}
Else {New-Item -Path $dailyBackupDir -ItemType Directory -Confirm:$false -Force | Out-Null}


# clean up!
Backup-Cleanup

# back up!
$params = @("--host $computerName", "--port $port", "--out ""$dailyBackupDir""","--oplog") # entire node
$block ="""$mongoBackup"" $params"
Write-Host "Backing up database with: $block"
try {
    Invoke-Expression -Command "cmd /c $block" -ErrorAction Ignore
}

Catch{
    write-host "All good"
    $Error = $null
}

write-Log "Backup done. Location: $dailyBackupDir"


#Start-Process -FilePath "$mongoBackup" -ArgumentList ("$params") -WindowStyle Normal -Verb RunAs -Wait


write-Log "Backup complete."
Exit
# remote backups: https://docs.mongodb.com/manual/tutorial/restore-replica-set-from-backup/
# mongodump --out C:\whateverbuddy --collection myCollection --db test
# restore point in time of database: mongodump --oplog. then mongorestore --oplogReplay
# mongorestore --port <port number> <path to the backup>