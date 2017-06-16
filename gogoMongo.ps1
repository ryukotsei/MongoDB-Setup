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
    Write-Host "`nPlease enter the following service parameters or (blank to go back).`n"
    $srvcName = Read-Host "New Service name"
    If ($srvcName -eq ""){Return}
    $prt = Read-Host "Port(default: 27017)"
    If ($prt -eq ""){Return}

    If ($prt -eq ""){$prt = "27017"}
    If ($prt.Length -gt 5) {
        Write-Host "`nPort can only be 5 characters long! Try again."
        Create-Mongo
    }
    
    $dbDir = Join-Path -Path $defaultRoot -ChildPath $srvcName
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
    $backupTime = Read-Host "`nWhich backup would you like(blank to go back)?"
    If ($backupTime -eq "") {Return}
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
    $block ="""$mongoEXE"" --dbpath $defaultRoot\$serviceName --auth"
    Invoke-Expression -Command "cmd /c $block"
}

Function Run-JavaScript { # run any javascript
    param($command)

    # get dat primary node!
    $primaryNode = Get-Primary
    $server = $primaryNode.Split(":")[0]
    $port = $primaryNode.Split(":")[1]
    $nodeString = "--host $server --port $port"
    Write-Host "Connected to primary node: $primaryNode"

    # do the thing where we type into a file and run it as a script thing to do stuff
    $tempJS = "$defaultRoot\tempJS.js"
    New-Item -Path $tempJS -ItemType File -Confirm:$false -Force | Out-Null # create the javascript file
    $command | Set-Content -Path $tempJS # add the replica set command to it with server:port parameter

    Write-Log "`nExecuting command as Javascript: $command"
    $block ="""$mongoShell"" $nodeString '$tempJS'"
    $result = Invoke-Expression -Command "cmd /c $block"

    Remove-Item -Path $tempJS -Confirm:$false -Force # delete the file

}

Function Print-ReplicaStatus { # show more formatted view of the replica members
    param($wait=$false,$quiet=$false)
    $nodes = Get-Nodes -quiet $true
    $headers = ""
    $nodes | GM | Where MemberType -eq "NoteProperty" | Select-Object Name | ForEach-Object {$headers += $_.Name + "      "}
    Write-Host "`n"$headers
    $nodes | ForEach-Object {Write-Host $_.Id "   " $_.NodeName "   " $_.State}
    If ($wait -eq $true){$throwAway = Read-Host "`nPress Enter to continue"}
}

Function Evaluate-NodeCount { # determine if there is an even number of nodes. If so, notify that an arbiter should be added
    $nodes = Get-Nodes
    $nodeCount = $nodes.Count
    If ($nodeCount%2 -eq 0){
        Write-Host "`nNOTICE: You have an even amount of nodes: $nodeCount. If this is your final node, please create another and add it to the replica set as an arbiter."
    }
}

Function Add-ToReplica { # add a node to the initated replica set
    Write-Host "`nThis is for adding to an existing replica set.`nThis will require connecting to the primary node.`n"
    Write-Host "Retrieving existing nodes...`n"
    Print-ReplicaStatus
    
    Write-Host "`nIMPORTANT: The node:port string specificed below is case sensitive."
    Write-Host "New nodes COMPUTERNAME:PORT (blank to go back).`n"
    $replicaNode = Read-Host "COMPUTERNAME:PORT" # get node to be added
    If ($replicaNode -eq ""){Return}

    Write-Log "`nAdding node: $replicaNode to replica set: $rsName..."
    $jsCommand = "rs.add(""$replicaNode"")"

    Run-JavaScript -command $jsCommand
       
    Write-Log "`nIssued command to add node to replica set: $replicaNode `nCheck replica config for confirmation"
    Evaluate-NodeCount
    $throwAway = Read-Host "Press ENTER to continue"
}

Function Remove-FromReplica { # remove node from replica
    param($quiet=$false,$replicaNode="")
    
    If ($quiet -eq $false) {
        Write-Host "`nThis is for removing a replica set member node from the replica set.`nThis will require connecting to the primary node.`n"
        Write-Host "Retrieving exiting nodes...`n"

        Print-ReplicaStatus

        Write-Host "`nIMPORTANT: The node:port string specificed below is case sensitive."
        Write-Host "Node to remove NODE:PORT (blank to go back).`n"
    }
    
    If ($replicaNode -eq ""){$replicaNode = Read-Host "NODE:PORT"} # get node to be removed
    If ($replicaNode -eq ""){Return}
    
    $jsCommand = "rs.remove(""$replicaNode"")"

    Write-Log "`nRemoving node: $replicaNode from replica set: $rsName..."
    Run-JavaScript -command $jsCommand
    If ($quiet -eq $false) {
        Write-Log "`nIssued command to remove node from replica set: $replicaNode `nCheck replica config for confirmation"
        Evaluate-NodeCount
        $throwAway = Read-Host "Press ENTER to continue"
    }
}

Function Add-Arbiter { # add a node to a replica as an arbiter
    Write-Host "`n     ----------- ADD ARBITER - READ THIS ! -----------"
    Write-Host "`nThis will add a node to the replica set as an arbiter. Arbiter nodes are added when you have an even # of nodes in a replica set to break ties."
    Write-Host "`nIf your replica set has an even number of nodes and you are done deploying nodes:`nAdd a second node to one of your machines and use this to add it to the replica set as an arbiter.`n"
    Write-Host "Remove the arbiter like another replica set member if you choose to add another node in the future. Adding another node would make the set have an even number."
    Write-Host "Retrieving exiting nodes...`n"
    Print-ReplicaStatus
    Write-Host "`nIMPORTANT: The node:port string specificed below is case sensitive."

    Write-Host "NODE:PORT to add as arbiter (blank to go back).`n"

    $replicaNode = Read-Host "NODE:PORT" # get node to be removed
    If ($replicaNode -eq ""){Return}

    $jsCommand = "rs.addArb(""$replicaNode"")"

    Write-Log "`nAdding arbiter node: $replicaNode to replica set: $rsName..."
    Run-JavaScript -command $jsCommand

    Write-Log "`nIssued command to add node as arbiter to replica set: $replicaNode `nCheck replica config for confirmation"
    Evaluate-NodeCount
    $throwAway = Read-Host "Press ENTER to continue" 
}

Function Get-ReplicaStatus { # retrieve the status of the replica
    param($wait=$false, $node=$currentNode,$quiet=$false)
    
    If ($node -eq "" -or $node -eq $null){
        $node = "$env:COMPUTERNAME" + ":" + "27017"
        Set-Variable -Name "currentNode" -Value $node -Scope Global
    }
    $server = $node.Split(":")[0]
    $port = $node.Split(":")[1]
    $nodeString = "--host $server --port $port"
    If ($quiet -eq $false) {write-host "Initial node value: $node"}
    If ($quiet -eq $false) {Write-Host "Current node: $node"}
    If ($quiet -eq $false) {Write-Host "`nRetrieving replica status...`n"}

    $params = @("rs.status()") # "localhost:$port/admin", 
    $block ="""$mongoShell"" $nodeString --eval '$params'"
    # example: Invoke-Expression -Command "cmd /c ""C:\Program Files\MongoDB\Server\3.4\bin\mongo.exe"" --host srv-cm-3 --port 27019 --eval 'rs.status()'"
    If ($quiet -eq $false) {Write-Host "Attempting connection: $block"}
    $result = Invoke-Expression -Command "cmd /c $block"

    $status = $result -match """ok"" : 1"

    If ($status.Count -le 0) {
        Write-Host "Unable to retrieve node status from the default node.`nPlease Input an alternate NODE:Port (blank to go back)"

        $altNode = Read-Host "NODE:PORT"
        Set-Variable -Name "currentNode" -Value $altNode -Scope Global -Option AllScope -Confirm:$false -Force
        #$global:currentNode = $altNode
        Write-Host "New currentNode: $currentNode"
        #$global:currentNode = $altNode
        $result = Get-ReplicaStatus -quiet $quiet
        #$currentNode = $altNode
        Return $result
    }
    #Set-Variable -Name currentNode -Value $altNode -Scope Global
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
        Write-Host "Unable to retrieve node config from the default node.`nPlease Input an alternate NODE:Port (blank to go back)"

        $altNode = Read-Host "NODE:PORT"
        If ($altNode -eq ""){Return}
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
    Write-Host "`nNODE:PORT of a mongo instance to initiate replica set on (blank to go back).`n"
    $node = Read-Host "NODE:PORT"
    If ($node -eq ""){Return}

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
        Write-Host "`nAutomatic backup scheduled task already exists!`nTask action:"$taskTest.Actions.Arguments
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
    Print-ReplicaStatus -quiet $true
    
    Write-Host "`nThis script will setup Mongo daily backups as a Windows Scheduled Task."
    Write-Host "You can change these settings at any time under Windows Task Scheduler.`nTask name: $taskName`n"
    
    $prt = Read-Host "Enter a LOCAL Mongo node PORT from above"
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
    param($quiet=$false)
    $rsStatus = Get-ReplicaStatus -quiet $quiet
    If ($quiet -eq $false) {Write-Host "Searching for primary in replica set..."}
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
    If ($quiet -eq $false) {Write-host "`nPrimary identified as: $primary"}
    return $primary
}

Function Get-Nodes { # gets replica set stats and determines the primary
    param($altNode=$currentNode,$quiet=$false)
    $rsStatus = Get-ReplicaStatus -node $altNode -quiet $quiet
    
    #$allNodes = @{}
    If ($quiet -eq $false) {Write-Host "Evaluating nodes..."}
    $allNodes = @()
    $rsStatus | ForEach-Object{
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

Function Get-InitialCurrentNode { # try to find a node on the local computer
    
    $initialNode = ""
    Write-Host "Searching for an available local node..."
    $nodeFolders = Get-Item -Path "$defaultRoot\*\log.log"
    If ($nodeFolders.Count -le 0){Return ""} # no nodes found

    $logFiles = $nodeFolders.FullName  # ENSURE IT finds the last process start in the log
    # cant get out of a foreach-object loop in powershell for some reason so i wrote the below workaround
    $logDef = 0
    Do {
        $logContent = Get-Content $logFiles[$logDef]
        $logContent | ForEach-Object {
            If ($_ -match "MongoDB starting"){
                $nodeLine = $_
                Return
            }
        }
        $nodeLine.split(" ") | ForEach-Object {
            If ($_ -match "port="){ # log the port
                $initialPort = $_ -replace "port=",""
            }
            If ($_ -match "pid=") { # log the process id
                $processID = $_ -replace "pid=",""
            }
        }
        $processStatus = Get-Process -Id $processID -ErrorAction Ignore
        If ($processStatus -ne $null) { # is this process running? If so then send back the port
            $initialNode = $env:COMPUTERNAME + ":" + $initialPort # found one!
            $found = $true
        }
        $logDef++
    } Until (($found -eq $true) -or $logDef -eq ($logFiles.Count - 1))

    Return $initialNode
}

Function Delete-Node {
    Write-Host "`nThis will delete a node on the local machine. This includes: service, database and replica membership.`n`nMongo service(s) on this machine:"
    
    $services = Get-WmiObject Win32_Service | Where-Object {$_.Description -eq 'MongoDB Server'} | Select-Object Name
    $services | ForEach-Object {Write-Host $_.Name}

    Write-Host "`nEnter a service name from above to DELETE it (blank to go back).`n"
    $serviceName = Read-Host "Service name"
    If ($serviceName -eq ""){Return}

    If ($serviceName -notin $services.Name) {
        write-host "Invalid service name. Try again."
        Delete-Node
        Return
    }

    # find service's node:port and remove it from the replica
    $serviceDir = "$defaultRoot\$serviceName"
    $nodeLog = Get-Item -Path "$serviceDir\log.log"
    $logContent = Get-Content $nodeLog.FullName
    $logContent | ForEach-Object {
        If ($_ -match "MongoDB starting"){
            $nodeLine = $_
        }
    }
    $nodeLine.split(" ") | ForEach-Object {
        If ($_ -match "port="){ # log the port
            $nodePort = $_ -replace "port=",""
        }
    }
    $node = $env:COMPUTERNAME + ":" + $nodePort
    Write-Host "Found node:port to remove from replica: $node"
    Remove-FromReplica -quiet $true -replicaNode $node # remove the node from the replica
    
    Write-Host "Stopping service: $serviceName" # stop the service
    Stop-Service -Name $serviceName -Confirm:$false -Force -ErrorAction Ignore

    Write-Host "Deleting service: $serviceName" # delete the service
    Invoke-Expression "cmd /c sc delete ""$serviceName"""

    
    Write-Host "Deleting service directory: $serviceDir"
    Remove-Item -Path $serviceDir -Recurse -Confirm:$false -Force # delete the service directory's folder

    Write-Host "Removing Windows Firewall rules for the service..." # remove the inbound and outbound firewall rules
    Get-NetFirewallRule -DisplayName "$serviceName Outbound $nodePort" | Remove-NetFirewallRule -Confirm:$false
    Get-NetFirewallRule -DisplayName "$serviceName Inbound $nodePort" | Remove-NetFirewallRule -Confirm:$false

    Write-host "`nDone."
    Print-ReplicaStatus -wait $true # show us what you got!
}


Function Get-DefaultRoot {
    If ($env:GC_MONGO_HOME -ne $null){Return $env:GC_MONGO_HOME}
    Else {Return $altRoot}
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
    $connectionStr += "/?replicaSet=$rsName&w=$writeConcern&connectTimeoutMS=$conTimeout" # finalize, write concern
    
    Write-Log "`nConnection string:`n`t$connectionStr"
    $throwAway = Read-Host "`nPress ENTER to continue"
}

Function Get-OptionList { # &"MyFunctionNameb" $arg1 $arg2
    $options = [ordered]@{"New Mongo node                    " = 1; `
                          "Initiate replica set              " = 2; `
                          "Add node to replica set           " = 3; `
                          "Add arbiter to replica set        " = 4; `
                          "Remove node from replica set      " = 5; `
                          "View replica status               " = 6; `
                          "View replica config               " = 7; `
                          "Load MongoShell                   " = 8; `
                          "Setup automatic backups           " = 9; `
                          "Restore backup from date          " = "r"; `
                          "Delete mongo node                 " = "d"; `
                          "Generate connection string        " = "c"; `
                          "View replica set (pretty)         " = "v"; `
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
        Add-Arbiter
        Get-OptionList # return to options
    }
    ElseIf ($slct -eq "5") {
        Remove-FromReplica
        Get-OptionList # return to options
    }
    ElseIf ($slct -eq "6") {
        Get-ReplicaConfig -wait $true
        Get-OptionList # return to options
    }
    ElseIf ($slct -eq "7") {
        Get-ReplicaStatus -wait $true
        Get-OptionList # return to options
    }
    ElseIf ($slct -eq "8") {
        Load-MongoShell
        Get-OptionList # return to options
    }
    ElseIf ($slct -eq "9") {
        Create-ScheduledBackup
        Get-OptionList # return to options
    }
    ElseIf ($slct.ToLower() -eq "r") {
        Restore-Backup
        Exit # done
    }
    ElseIf ($slct.ToLower() -eq "d") {
        Delete-Node
        Get-OptionList # return to options
    }
    ElseIf ($slct.ToLower() -eq "c") {
        Generate-ConnectionString
        Get-OptionList # return to options
    }
    ElseIf ($slct.ToLower() -eq "v") {
        Print-ReplicaStatus -wait $true
        Get-OptionList # return to options
    }
    ElseIf ($slct.ToLower() -eq "x") {
        Write-Host "`nFarewell.... you monster"
        Exit # done
    }
    Else {
        Write-Host "Unknown selection. Try again..."
        Get-OptionList
    }
}

# gogo Mongo DB!

# variables - change to enviro
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$global:consoleOutput = $true # output logging to console
$global:altRoot = "C:\MongoOthers"
$global:defaultRoot = Get-DefaultRoot
$global:rsName = "dispatchmap" # replicaSet name
$global:backupScriptName = "gogoMDBBackup.ps1"
$global:backupTaskScriptName = "backupMongo.vbs"
$global:backupScript = Join-Path -Path $scriptDir -ChildPath $backupScriptName
$global:backupTaskScript = Join-Path -Path $scriptDir -ChildPath $backupTaskScriptName
$taskName = "MongoDB Backup"
$writeConcern = 1 # write concern, 1 = wait for confirmation of write
$conTimeout = "3000" # connection string write concern in milliseconds

# variables - leave!
$global:logFile = $scriptDir + "\scriptLog.log"
$global:mongoRoot = "C:\Program Files\MongoDB\Server\3.4\bin"
$global:mongoEXE = Join-Path -Path $mongoRoot -ChildPath "mongod.exe"
$global:mongoShell = Join-Path -Path $mongoRoot -ChildPath "mongo.exe" # shell methods: https://docs.mongodb.com/manual/reference/method/
$global:mongoBackup = Join-Path -Path $mongoRoot -ChildPath "mongodump.exe"
$global:mongoRestore = Join-Path -Path $mongoRoot -ChildPath "mongorestore.exe"
$global:backupDir =  Join-Path -Path $defaultRoot -ChildPath "backups"
$global:replicaLimit = $false # tagged as true when get-nodes finds 7 or more nodes in the replica set as

$global:keyFile = "$scriptDir\keyfile"
$global:key = "F823589A578B5613M9656J585ED84"
$global:currentPrimary = ""


If ($currentNode -eq $null) { # so we dont get an error after stopping the script and running it again
    $localNode = Get-InitialCurrentNode # find the local node by searching the defaultRoot for a service's log file content
    New-Variable -Name "currentNode" -Visibility Public -Value $localNode -Option AllScope
    $currentPrimary = Get-Primary -quiet $true # now that we have found a local node that's part of the replica, we can use it to hop to the primary and set it as the de facto node
    $currentNode = $currentPrimary 
}
Else {
    $currentPrimary = Get-Primary -quiet $true # now that we have found a local node that's part of the replica, we can use it to hop to the primary and set it as the de facto node
    $currentNode = $currentPrimary 
}

# configure as desired

Write-Host "`nMongoDB Setup Script!`nComputerName: $env:COMPUTERNAME"
Write-Host "Default node: $currentNode"
Write-Host "Root service path: $defaultRoot"
Write-Host "Log path: $logFile"

Get-OptionList

Exit

# Fin

#NOTES:
# parameterize the backup location in the setup backup auto function and the restore function
