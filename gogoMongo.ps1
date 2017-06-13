# create mongo DB nodes and other stuff 
# methods: https://docs.mongodb.com/manual/reference/method/


Function Write-Log { # output to logFile
    param($message)
    If ($consoleOutput -eq $true) {
        Write-Host $message
    }
    $logDate = Get-Date -UFormat "%m/%d/%Y %H:%M:%S%p"
    $message = $message -replace "`n","" -replace "`t",""
    "$logDate   $message" | Out-File $logFile -Append
}

Function Confirm-Dir { # create the directory if not exist
    param($dir)
    If (!(Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory
    }
}

Function Create-Mongo {
    Write-Host "`nInstall a new mongo node server to this machine."
    Write-Host "Existing Mongo services on this machine:`n"
    Get-WmiObject Win32_Service | Where-Object {$_.Description -eq 'MongoDB Server'} | Select-Object Name | ForEach-Object {Write-Host $_.Name}
    Confirm-Dir -dir $defaultRoot
    $srvcName = Read-Host "`nNew Service name"
    $prt = Read-Host "Port(default: 27017)"
    If ($prt -eq ""){$prt = "27017"}
    If ($prt.Length -gt 5) {
        Write-Host "`nPort can only be 5 characters long! Try again."
        Create-Mongo
    }
    
    $dbDir = join-path -Path $defaultRoot -ChildPath $srvcName
    Confirm-Dir -dir $dbDir

    #Copy-Item -Path $keyFile -Destination $dbDir -Confirm:$false -Force
    #$keyCode = "$keyFile\$key"

    Do-FirewallRules -srvcName $srvcName -prt $prt

    $params = @("--dbpath ""$dbDir""", "--replSet $rsName", "--rest", "--logpath ""$dbDir\log.log""", "--port $prt", "--serviceName ""$srvcName""", "--serviceDisplayName ""$srvcName""", "--install")
    Write-Log "Executing DB creation with params: $params"
    $block ="""$mongoEXE"" $params"
    
    # alternates?
    #Invoke-Command -ScriptBlock {cmd /c $block}
    # & $mongoEXE $params
    Try {
        Invoke-Expression -Command "cmd /c $block"
    }
    Catch {
        Write-Log "Try restarting this server or any existing Mongo nodes that are part of this replica set: $rsName"
    }
    Write-Log "Complete. Starting service..."
    Start-Service -Name $srvcName -Confirm:$false
    Write-Log "Done."
    Write-Log "Mongo node: $srvcName - service location: $dbDir"

}



Function Load-MongoShell {
    $primaryNode = Get-Primary

    Write-Host "`nLoading Mongo shell: $mongoShell`nConnecting to node: $primaryNode"
    Write-Host "`nClose the shell when done by typing: exit"
    
    Start-Process -FilePath "$mongoShell" -ArgumentList ($primaryNode) -WindowStyle Normal -Verb RunAs -Wait
}


Function Create-User { # not working yet
    $primary = Get-Primary
    $userConfig = @{ "user" = "geocomm"; "pwd" = "geocomm"; "roles"=@{"role" = "userAdminAnyDatabase"; "db" = "admin" }}
    $configJSON = $userConfig |ConvertTo-Json 

      
    $command = "db.createUser($configJSON)"
    Invoke-Expression -Command "cmd.exe /c ""$mongoShell"" $primary --eval $command"
    Start-Process -FilePath "$mongoShell" -ArgumentList ($primary, $command) -WindowStyle Normal -Verb RunAs -Wait
}

Function Authenticate { # not working yet

    #mongo --port 27017 -u "myUserAdmin" -p "abc123" --authenticationDatabase "admin"

}


Function Restore-Backup { # restores to the primary only
    param($srvcName=$null, $prt=$nulls)
    
    $primary = Get-Primary
    $prt = $primary.Split(":")[1]
    If ($prt -eq $null){
        $prt = Read-Host "Mongo node's Port on this server to restore too"
    }

    $backups = Get-ChildItem -Path $backupDir -Directory | Select-Object Name
    Write-Host "`nAvailable backup dates: "
    $backups.Name
    $backupTime = Read-Host "`nWhich backup would you like?"
    If ($backupTime -notin $backups.Name){
        Write-Host "Invalid backup choice. Try again."
        Restore-Backup -srvcName $srvcName -node $prt
        Return # stupid powershell
    }
    $backupRestore = Join-Path -Path $backupDir -ChildPath $backupTime
    $proceed = Read-Host "`nAre you sure you want to proceed. No going back.(yes/no)"
    If ($proceed.ToLower() -ne "yes") {
        Write-Host "`You chose not to proceed."
        Return        
    }
    Write-Log "Restoring backup: $backupRestore, to Node: $prt"

    # mongo --port 27017 -u myUserAdmin -p 'abc123' --authenticationDatabase 'admin'

    Invoke-Expression -Command "cmd.exe /c ""$mongoRestore"" --port $prt ""$backupRestore"" --oplogReplay"
    Write-Log "Done."
}

Function Setup-Auth { # not working yet
    $primaryNode = Get-Primary
    Write-Host "Found Primar node: $primaryNode"
    # setup replicas first?
    Write-Host "Create an admin user credential first.`nModify the text in notepad then paste/run it in the mongo shell that has popped up. `n"

    $auth = "use admin
db.createUser(
  {
    user: ""myUserAdmin"",
    pwd: ""abc123"",
    roles: [ { role: ""userAdminAnyDatabase"", db: ""admin"" } ]
  }
)"
    $userName = Read-Host "Administrator username"
    $password = Read-host "Administrator password:"

    $auth = $auth -replace "myUserAdmin",$userName -replace "abc123",$password
    # bring up notepad with the text
    $process = Start-Process $mongoShell -PassThru
    $process = Start-Process notepad -PassThru
    $null = $process.WaitForInputIdle()
    $sig = '
      [DllImport("user32.dll", EntryPoint = "FindWindowEx")]public static extern IntPtr FindWindowEx(IntPtr hwndParent, IntPtr hwndChildAfter, string lpszClass, string lpszWindow);
      [DllImport("User32.dll")]public static extern int SendMessage(IntPtr hWnd, int uMsg, int wParam, string lParam);
    '
    $type = Add-Type -MemberDefinition $sig -Name APISendMessage -PassThru
    $hwnd = $process.MainWindowHandle
    [IntPtr]$child = $type::FindWindowEx($hwnd, [IntPtr]::Zero, "Edit", $null)
    $null = $type::SendMessage($child, 0x000C, 0, $auth)


    Start-Process -FilePath "$mongoShell" -ArgumentList ($primaryNode) -WindowStyle Normal -Verb RunAs -Wait
    
    $enableAuth = Read-Host "If you command succeeded then enter 'y' to activate."
    If ($enableAuth.ToLower() -ne "y"){Return}

    
    Write-Host "Enabling authentication..."
    $block ="""$mongoEXE"" --dbpath C:\MongoOthers\mongo1 --auth"
    Invoke-Expression -Command "cmd /c $block"
}

Function Add-ToReplica { # add a node to the initated replica set
    Write-Host "`nThis is for adding to an existing replica set.`nThis will require connecting to the primary node.`n"
    
    $primaryNode = Get-Primary
    $server = $primaryNode.Split(":")[0]
    $port = $primaryNode.Split(":")[1]
    $nodeString = "--host $server --port $port"
   
    Write-Host "Connected to primary node: $primaryNode"
    Write-Host "IMPORTANT: The node:port string specificed below is extremely case sensitive."
    $newReplicaNode = Read-Host "`nNew node's computername:port" # get node to be added

    # create javascript file to run command
    $addReplicaJS = "$defaultRoot\addReplica.js"
    New-Item -Path $addReplicaJS -ItemType File -Confirm:$false -Force # create the javascript file
    "rs.add(""$newReplicaNode"")" | Set-Content -Path $addReplicaJS # add the replica set command to it with server:port parameter

    Write-Log "Adding node: $newReplicaNode to replica set: $rsName..."
    $block ="""$mongoShell"" $nodeString '$javaScript'"
    $result = Invoke-Expression -Command "cmd /c $block"

    Write-Log "Issued command to add node to replica set: $newReplicaNode. `nCheck replica config for confirmation"
    Remove-Item -Path $addReplicaJS -Confirm:$false -Force # delete the file
    $throwAway = Read-Host "Press ENTER to continue"
}

Function Remove-FromReplica {
    Write-Host "`nThis is for removing a replica set member node from the replica set.`nThis will require connecting to the primary node.`n"
    
    $primaryNode = Get-Primary
    $server = $primaryNode.Split(":")[0]
    $port = $primaryNode.Split(":")[1]
    $nodeString = "--host $server --port $port"
   
    Write-Host "Connected to primary node: $primaryNode"
    Write-Host "IMPORTANT: The node:port string specificed below is extremely case sensitive."
    $newReplicaNode = Read-Host "`nNode to remove computername:port" # get node to be added

    # create javascript file to run command
    $addReplicaJS = "$defaultRoot\removeReplica.js"
    New-Item -Path $addReplicaJS -ItemType File -Confirm:$false -Force # create the javascript file
    "rs.remove(""$newReplicaNode"")" | Set-Content -Path $addReplicaJS # add the replica set command to it with server:port parameter

    Write-Log "Removing node: $newReplicaNode from replica set: $rsName..."
    $block ="""$mongoShell"" $nodeString '$javaScript'"
    $result = Invoke-Expression -Command "cmd /c $block"

    Write-Log "Issued command to remove node from replica set: $newReplicaNode. `nCheck replica config for confirmation"
    Remove-Item -Path $addReplicaJS -Confirm:$false -Force # delete the file
    $throwAway = Read-Host "Press ENTER to continue" 
}

Function Get-ReplicaStatus { # retrieve the status of the replica
    param($wait=$false, $node=$currentNode)

    Write-Host "Current node: $node"
    If ($node -ne "" -or $node -ne $null){
        $node = "$env:COMPUTERNAME" + ":" + "27017"
        $server = $node.Split(":")[0]
        $port = $node.Split(":")[1]
        $nodeString = "--host $server --port $port"
    }

    Write-Host "`nRetrieving replica status...`n"
    $params = @("rs.status()") # "localhost:$port/admin", 
    $block ="""$mongoShell"" $nodeString --eval '$params'"
    # example: Invoke-Expression -Command "cmd /c ""C:\Program Files\MongoDB\Server\3.4\bin\mongo.exe"" --host srv-cm-3 --port 27019 --eval 'rs.status()'"

    $result = Invoke-Expression -Command "cmd /c $block"

    $status = $result -match """ok"" : 1"

    If ($status.Count -le 0) {
        Write-Host "Unable to retrieve node status from the default local node."
        $altNode = Read-Host "Please Input an alternate NODE:PORT"
        Set-Variable -Name currentNode -Value $altNode -Scope Global
        $result = Get-ReplicaStatus -node $altNode
        #$currentNode = $altNode
        Return $result

    }
    Set-Variable -Name currentNode -Value $altNode -Scope Global
    If($wait -eq $true){ # print read out and wait
        $result | ForEach-Object {Write-Host $_}
        $throwAway = Read-Host "`n Press ENTER to continue"
    }
    Else {Return $result}
}

Function Get-ReplicaConfig { # retrieve replica configuration
    param($wait=$false, $node=$currentNode)
    
    Write-Host "Current node: $node"
    If ($node -ne ""){
        $server = $node.Split(":")[0]
        $port = $node.Split(":")[1]
        $nodeString = "--host $server --port $port"
    }
    Write-Host "`nRetrieving replica configuration...`n"
    $params = @("rs.conf()") # "localhost:$port/admin", 
    $block ="""$mongoShell"" $nodeString --eval '$params'"
    # example: Invoke-Expression -Command "cmd /c ""C:\Program Files\MongoDB\Server\3.4\bin\mongo.exe"" --host srv-cm-3 --port 27019 --eval 'rs.status()'"

    $result = Invoke-Expression -Command "cmd /c $block"

    $status = $result -match "Failed to connect"

    If ($status.Count -gt 0) {
        Write-Host "Unable to retrieve node status from the default local node."
        $altNode = Read-Host "Please Input an alternate NODE:PORT"
        $currentNode = $altNode
        Set-Variable -Name currentNode -Value $altNode -Scope Global
        $result = Get-ReplicaStatus -node $altNode
        Return $result

    }

    Set-Variable -Name currentNode -Value $altNode -Scope Global
    If($wait -eq $true) { # print read out and wait
        $result | ForEach-Object {Write-Host $_}
        $throwAway = Read-Host "`n Press ENTER to continue"
    }
    Else {Return $result}
}


Function Initiate-Replica { # initiates the replica

    Write-Host "`nEnter the Computername:Port of the node to initiate the replica set on. All other nodes will be added to this, Primary, node."
    $node = Read-Host "Node computername:port"

    Write-Host "Initiating replica for node: ..."
    $command = "rs.initiate()" # "localhost:$port/admin", 
    Start-Process -FilePath $mongoShell -ArgumentList ($node, "-eval", $command) -WindowStyle Normal -Verb RunAs -Wait
    Write-Host "Complete.`n"
}


Function Do-FirewallRules { # add firewall rules
    param($srvcName, $prt)

    If ((Get-NetFirewallRule -Name "MongoDB $srvcName" -erroraction Ignore) -eq $null) { # improve to query for port exception not name
        Write-Host "Creating firewall exceptions for TCP port: $port"
        New-NetFirewallRule -LocalPort $prt -Name "$srvcName Inbound $prt" -DisplayName "$srvcName Inbound $prt" -Enabled True -Direction Inbound -Protocol TCP -Confirm:$false -ErrorAction Ignore | Out-Null
        New-NetFirewallRule -LocalPort $prt -Name "$srvcName Outbound $prt" -DisplayName "$srvcName Outbound $prt" -Enabled True -Direction Outbound -Protocol TCP -Confirm:$false -ErrorAction Ignore | Out-Null
    }
}

Function Create-ScheduledBackup { # creates Windows scheduled task to backup

    $taskTest = Get-ScheduledTask -TaskName $taskName -ErrorAction Ignore
    If ($taskTest -ne $null) { # task already exists
        Write-Host "`nAutomatic backup scheduled task already exists!`nDetails:"
        Write-Host $taskTest.Actions.Arguments
        $taskStart = [datetime]$taskTest.Triggers.StartBoundary
        Write-Host "Runs daily @: $taskStart"
        $redo = Read-Host "`nRedo backup scheduled task(y/n)?"
        If ($redo.ToLower() -ne 'y') {
            Write-Host "Returning..."
            Return
        }
        Else { 
            Write-Host "Removing existing scheduled task..."
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        }
    }

    Confirm-Dir -dir $backupDir # setup/confirm backups root dir
    $newBackupScriptPath = Join-Path -Path $backupDir -childPath $backupScriptName # .ps1
    $newBackupTaskScript = Join-Path -Path $backupDir -ChildPath $backupTaskScriptName # .vbs
    If (!(Test-Path -Path $newBackupScriptPath )) { # move backup ps1 script to local backups root dir
        Copy-Item -Path $backupScript -Destination $backupDir -Confirm:$false -Force
    }

    Write-Host "`nThis will setup the mongo DB to automatically backup daily. You can change these settings at any time under Windows Task Scheduler."
    Write-Host "This script will setup the backups to happen daily.`nTask name: $taskName"
    $prt = Read-Host "Mongo node port"
    $time = Read-Host "Enter the time of day should we backup (e.g. 3:30am)"

    # copy over vbs script that calls the powershell script with admin priveleges
    Copy-Item -Path $backupTaskScript -Destination $backupDir -Confirm:$false -Force
    (Get-Content $newBackupTaskScript) -replace "SCRIPTHERE",$newBackupScriptPath -replace "PORTHERE",$prt | Set-Content $newBackupTaskScript # modify the .vbs script to have to correct .ps1 script and port
    
    $action = New-ScheduledTaskAction -Execute "C:\Windows\System32\cscript.exe" -Argument """$newBackupTaskScript"""
    
    $trigger =  New-ScheduledTaskTrigger -Daily -At $time
    $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Write-Log "Registering scheduled task: $taskName..."
    Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName $taskName -Description "Daily backup of MongoDB node" -Force

    Write-Log "Scheduled task: $taskName is now registered and will run every day at: $time"
}

Function Get-Primary { # gets replica set stats and determines the primary
    $rsStatus = Get-ReplicaStatus
    Write-Host "Searching for primary in replica set..."
    $rsStatus | ForEach-Object {
        If ($_ -match """name"" : "){
            $nodeStored = $_
        }
        If ($_ -match """stateStr"" : ""PRIMARY"""){
            $primary = $nodeStored
        }
    }
    $primary = $primary -replace """name"" : """,""  -replace """," -replace "	",""
    $currentPrimary = $primary
    Write-host "`nPrimary identified as: $primary"
    return $primary
}

Function Get-Nodes { # gets replica set stats and determines the primary
    param($altNode="")
    $rsStatus = Get-ReplicaStatus -node $altNode
    
    #$allNodes = @{}
    Write-Host "Evaluating nodes..."
    $allNodes = @()
    $rsStatus | ForEach-Object{g
        If ($_ -match """_id"" : ") {
            $nodeID = $_ -replace """_id"" : ",""  -replace "," -replace "	",""
        }
        If ($_ -match """name"" : "){
            $nodeName = $_ -replace """name"" : """,""  -replace """," -replace "	",""
        }
        If ($_ -match """stateStr"" : "){
            $state = $_ -replace """stateStr"" : """,""  -replace """," -replace "	",""
            #$allNodes.Add($nodeName, $state)
            $nodes = [PSCustomObject] @{Id=$nodeID;NodeName=$nodeName;State=$state}
            $allNodes += $nodes
        }
    }

    #$node = Select-Node -nodeList $allNodes

    Return $allNodes
}
 
Function Generate-ConnectionString { # build and output connection string for the replica and its nodes
    # https://docs.mongodb.com/manual/reference/connection-string/
    # connection string format: mongodb://[username:password@]host1[:port1][,host2[:port2],...[,hostN[:portN]]][/[database][?options]]
    
    $nodes = Get-Nodes # get all nodes
    $connectionStr = "mongodb://"
    $hostNum = 1
    $nodes | ForEach-Object { # construct connetion string
        $node = $_.NodeName
        
        $connectionStr += "$node,"
        
    }
    $connectionStr = $connectionStr.Substring(0,$connectionStr.Length-1)
    $connectionStr += "/?replicaSet=$rsName" # finalize
    
    Write-Log "`nConnection string:`n`t$connectionStr"
    $throwAway = Read-Host "`nPress ENTER to continue"
}


Function Get-OptionList { # &"MyFunctionName" $arg1 $arg2
    $options = [ordered]@{"New Mongo node                    " = 1; `
                          "Initiate replica set              " = 2; `
                          "Add server to replica set         " = 3; `
                          "Remove node from replica set      " = 4; `
                          "View replica status               " = 5; `
                          "View replica config               " = 6; `
                          "Load MongoShell                   " = 7; `
                          "Setup automatic backups           " = 8; `
                          "Restore backup from date          " = 9; `
                          "Generate connection string        " = "c"; `
                          "Exit                              " = "x"}

    Write-Host "`nOptions ---`n"

    $options.GetEnumerator() | ForEach-Object {Write-host $_.Key " - " $_.value}

    $slct = Read-Host "`nSelect"
    If ($slct -notin $options.Values){
        Write-host "Invalid input. Try again...`n"
        Get-OptionList
    }
    ElseIf ($slct -eq "1") { # 1
        Create-Mongo
        Get-OptionList # return to options
    }
    ElseIf ($slct -eq "2") { # 1
        Initiate-Replica
        Get-OptionList # return to options
    }
    ElseIf ($slct -eq "3") {
        Add-ToReplica
        Get-OptionList # return to options
    }
    ElseIf ($slct -eq "4") {
        Remove-FromReplica
        Get-OptionList # return to options
    }
    ElseIf ($slct -eq "5") {
        Get-ReplicaConfig -wait $true
        Get-OptionList # return to options
    }
    ElseIf ($slct -eq "6") {
        Get-ReplicaStatus -wait $true
        Get-OptionList # return to options
    }
    ElseIf ($slct -eq "7") {
        Load-MongoShell
        Get-OptionList # return to options
    }
    ElseIf ($slct -eq "8") {
        Create-ScheduledBackup
        Get-OptionList # return to options
    }
    ElseIf ($slct -eq 9) {
        Restore-Backup
        Exit # done
    }
    ElseIf ($slct.ToLower() -eq "c") {
        Generate-ConnectionString
        Get-OptionList # return to options
    }
    ElseIf ($slct.ToLower() -eq "x") {
        Write-Host "`nFarewell.... you monster"
        Exit # done
    }
    Else {
        Write-Host "Unknown option. Try again..."
        Get-OptionList
    }
}

# gogo Mongo DB!

# variables - change to enviro

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$global:defaultRoot = "C:\MongoOthers"
$global:consoleOutput = $true # output logging to console
$global:rsName = "rs0" # replicaSet name
$global:backupScriptName = "gogoMDBBackup.ps1"
$global:backupTaskScriptName = "backupMongo.vbs"
$global:backupScript = Join-Path -Path $scriptDir -ChildPath $backupScriptName
$global:backupTaskScript = Join-Path -Path $scriptDir -ChildPath $backupTaskScriptName
$taskName = "MongoDB Backup"

# variables - leave!
$global:logFile = $scriptDir + "\scriptLog.log"
$global:mongoRoot = "C:\Program Files\MongoDB\Server\3.4\bin"
$global:mongoEXE = Join-Path -Path $mongoRoot -ChildPath "mongod.exe"
$global:mongoShell = Join-Path -Path $mongoRoot -ChildPath "mongo.exe" # shell methods: https://docs.mongodb.com/manual/reference/method/
$global:mongoBackup = Join-Path -Path $mongoRoot -ChildPath "mongodump.exe"
$global:mongoRestore = Join-Path -Path $mongoRoot -ChildPath "mongorestore.exe"
$global:backupDir =  Join-Path -Path $defaultRoot -ChildPath "backups"

$global:keyFile = "$scriptDir\keyfile"
$global:key = "F823589A578B5613M9656J585ED84"
$global:currentPrimary = ""
$global:currentNode = ""
# configure as desired


Write-Host "`nMongoDB Setup Script!`nComputerName: $env:COMPUTERNAME"
Write-Host "Log path: $logFile"

Get-OptionList

Exit

# Fin