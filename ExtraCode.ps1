# extra code i made that may be useful down the road... or not

$exe = "C:\Program Files\MongoDB\Server\3.4\bin\mongo.exe"

$params = @(" --dbpath ""$dbDir""", " --logpath ""$dbDir\log.log""", " --port $prt", " --serviceName ""$srvName""", " --serviceDisplayName ""$srvName""", " --install")
write-Host "Executing params: $params"
& $exe $params



Function Configure-Replica {
    # mongod --port 27017 --dbpath /srv/mongodb/db0 --replSet rs0
    param([string]$srvcName, [string]$dir, [string]$prt)
    
    $dbDir = "$dir\$srvcName"
    #Stop-Service -Name $srvcName -Confirm:$false
    $params = @("--dbpath ""$dbDir""", "--port $prt", "--replSet $rsName")
    Write-Host "Executing DB creation with params: $params"
    # & $mongoEXE $params
    $block ="""$mongoEXE"" $params"
    #Invoke-Command -ScriptBlock {cmd /c $block}
    Invoke-Expression -Command "cmd /c $block"

    # Start-Service -Name $srvcName -Confirm:$false

}

Function Construct-ReplicaConfig {
    params($svrs,$prt)

    $config = "{ _id: """"$rsName"""", members:[{ _id : 0, host : """"$env:COMPUTERNAME" + ":" + "$prt""""}"
    $id = 1
    $svrs | ForEach-Object {
        $config += ",{ _id : $id, host : """"$_""""}"
        $id++
    }
    $config += "]}"

    $configR = "rs.initiate($config)"
    Return $configR
}

Function add-toreplica {

    
    #Write-Host "`nPrimary instance details: $primaryNode"
    #$remoteNode = Read-Host "ComputerName:Port of existing Mongo instance"
    #$remotePort = Read-Host "Port that Mongo is using on that computer:"
    #$remoteNode = "$remoteServer" + ":" + "$primaryPort"
    
    #Write-Host "`nChecking remote server:port connectivity..."
    #$netTest = Test-NetConnection -ComputerName $remoteServer -Port $remotePort
    #If ($netTest.TcpTestSucceeded -ne $true) {
    #    Write-Host "Failed! Details:"
    #    $netTest
    #    Write-Host "Please confirm your input and that Mongo is installed/running on this server and the port is open to inbound traffic."
    #    Return
    #}

    # do it!
    #Write-Log("Adding $remoteNode to replica set: $rsName")
    #$command = "rs.add(""$remoteNode"")" # "localhost:$port/admin", 
    #Write-Log -message "Executing: $command"
    #Invoke-Expression -Command "cmd.exe /c ""$mongoShell"" $primaryNode --eval $command"

    #$execute = new-object System.Diagnostics.ProcessStartInfo
    #$execute.FileName = $mongoShell
    #$execute.Arguments = ("$primaryNode", "-eval", "rs.add(""$remoteNode"")","& PAUSE")
    #$p = [System.Diagnostics.Process]::Start($execute)
    #$p.WaitForExit()
    

    #file

    #connect("srv-cm-3:27017")


    #Invoke-Expression -Command "cmd.exe /c ""$mongoShell"" $primaryNode --eval Mongo()"
    #"Mongo()", 
    # alt -
    #Start-Process "cmd.exe" "/c `"`"$mongoShell`" $primaryNode --eval $command & timeout /T 2 & PAUSE`""
}

Function Replica-Configuration { # retrieve configuration details about the replica
    Write-Host "`nRetrieving replica configuration...`n"
    $params = @("rs.conf()") # "localhost:$port/admin", 
    $block ="""$mongoShell"" --eval '$params'"
    write-Host $block
    Invoke-Expression -Command "cmd /c $block"
    $throwAway = Read-Host "`n Press ENTER to continue"
}

Function Initiate-ReplicaConfig {
    param($node, $config)

    Write-Host "Configuring  replica for node: $node "
    $command = "rs.initiate({ _id: $rsName, members: [{ _id : 0, host : ""$node"" } ] })" # "localhost:$port/admin", 
    Start-Process -FilePath $mongoShell -ArgumentList ($node, "-eval", $config) -WindowStyle Normal -Verb RunAs -Wait
    Write-Host "Complete.`n"
    Replica-Configuration
    #Invoke-Expression -Command "cmd.exe /c ""$mongoShell"" $node --eval ('$command'" # requires single quotes
    #rs.initiate({ _id: "rs0", members: [{ _id : 0, host : "SRV-CM-3:27017"} ] })
    #test
    #$command = "rs.initiate($config)" # "localhost:$port/admin", 
    #Invoke-Expression -Command "cmd.exe /c ""$mongoShell"" --eval '$command'"   
}

Function Configure-Replica{
    Write-Host "`nInitiate Replica Config --`nYou must have 3 nodes running to be able to initiate the replica.`nThis node will become the PRIMARY node to the replica set.`n"
    
    $primaryNode = Read-Host "This host's (computername:port)"
    $rsConfig = @{
        "_id" = "$rsName";
        "version" = 1;
        "members" = New-Object System.Collections.ArrayList; 
    }
    $rsConfig["members"].Add( @{ "_id" = 0; "host" = $primaryNode; "priority" = 1; } )
    Write-Host "`nWARNING: This will create a primary instance of MongoDB and configure the replica set. Do NOT run this command for another instance after.`n"
    $done = $false
    $nodes = @()
    Write-Host "Enter in at least 2 other nodes for this replica set (server:port)"
    Write-Host "Leave blank when done."

    Do {
        $newNode = read-host "(server:port)(BLANK for done)"
        If ($newNode -ne ""){
            $nodes += $newNode
        }
        Else {$done = $true}

    } Until ($done)
    $memberId = 1
    ForEach($node in $nodes){

        $rsConfig["members"].Add( @{ "_id" = $memberId; "host" = $node; "priority" = 1; } ) | Out-Null
        $memberId = $memberId + 1
    }

    $rsConfigJson = $rsConfig | ConvertTo-Json
    $rsCommand = @"

var rsConfig = $rsConfigJson

rs.initiate(rsConfig)

"@ # this line must stay spaced here
    $rsCommand = "rs.initiate($rsConfigJson)"

    Initiate-ReplicaConfig -node $primaryNode -config $rsCommand
}





$config = Construct-ReplicaConfig -svrs $servers -prt $port

#$config = "rsconf = { _id: """"$rsName"""", members: [{ _id : 0, host : """"$server" + ':' + "$port""""} ]  };"
$config = "{ _id: """"$rsName"""", members: [{ _id : 0, host : """"$server" + ':' + "$port""""} ] }"

# mongo --eval 'db.collection.find().forEach(printjson)'
# delete replicaset: rs.remove('host:port')

$params = @("localhost:27017/admin","rs.Status()")

$test = & $mongoShell $params

# que? configure das replica set de extraordinaire?
$servers = @("localhost:27018", "localhost:27019")


Add-Type -Path $fullBSON
Add-Type -Path $fullMDB

$client = New-Object -TypeName MongoDB.Driver.MongoClient -ArgumentList "mongodb://localhost:$port"
$server = $client.GetServer()

$server.CreateDatabaseSettings('admin')

$server.ReplicaSetName

$test = New-Object -COMObject MongoDB.Driver



# done
$server.Disconnect()



$otherNodes = Read-Host "Other nodes:port(e.g 192.168.50.13:27018, 192.168.50.25:27019)" 
rsconf = {
    _id: rs0,
    members: [
        {
        _id : 0,
        host : localhost:27017},
        { _id : 1,
        host : localhost:27018},
        { _id : 2,
        host : localhost:27019}
    ]
}

Function Select-Node {
    param($nodeList)
    Write-Host ""
    Write-host ($allNodes |GM | Where-Object Membertype -eq NoteProperty | Select-Object Name).Name
    $allNodes | ForEach-Object {Write-Host $_.Id "   " $_.NodeName "   " $_.State} # print out node list
    $nodeSelection = Read-Host "`nEnter in a node ID of the node you want"
    
    If ($nodeList.Id -notcontains $nodeSelection) { # not a valid node id
        Write-Host "`nInvalid node selection. Try again."
        $node = Select-Node -nodeList $nodeList
        Return $node
    }
    $findNode = $nodeList | Where Id -eq $nodeSelection
    $node = $findNode.NodeName
    Write-Host "Node selected: $node"
    Return $node
}





