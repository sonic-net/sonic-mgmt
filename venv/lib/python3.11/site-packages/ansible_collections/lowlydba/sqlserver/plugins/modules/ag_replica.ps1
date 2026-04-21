#!powershell
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ansible_collections.lowlydba.sqlserver.plugins.module_utils._SqlServerUtils
#Requires -Modules @{ ModuleName="dbatools"; ModuleVersion="2.0.0" }

$ErrorActionPreference = "Stop"

$spec = @{
    supports_check_mode = $true
    options = @{
        sql_instance_replica = @{type = 'str'; required = $true }
        sql_username_replica = @{type = 'str'; required = $false }
        sql_password_replica = @{type = 'str'; required = $false; no_log = $true }
        ag_name = @{type = 'str'; required = $true }
        endpoint = @{type = 'str'; required = $false; default = 'hadr_endpoint' }
        endpoint_url = @{type = 'str'; required = $false }
        backup_priority = @{type = 'int'; required = $false; default = 50 }
        failover_mode = @{
            type = 'str'
            required = $false
            default = 'Manual'
            choices = @('Manual', 'Automatic')
        }
        availability_mode = @{
            type = 'str'
            required = $false; default = 'AsynchronousCommit'
            choices = @('SynchronousCommit', 'AsynchronousCommit')
        }
        seeding_mode = @{
            type = 'str'
            required = $false
            default = 'Automatic'
            choices = @('Manual', 'Automatic')
        }
        connection_mode_in_primary_role = @{
            type = 'str'
            required = $false
            default = 'AllowAllConnections'
            choices = @('AllowReadIntentConnectionsOnly', 'AllowAllConnections')
        }
        connection_mode_in_secondary_role = @{
            type = 'str'
            required = $false
            default = 'AllowNoConnections'
            choices = @('AllowNoConnections', 'AllowReadIntentConnectionsOnly', 'AllowAllConnections')
        }
        read_only_routing_connection_url = @{
            type = 'str'
            required = $false
        }
        read_only_routing_list = @{
            type = 'str'
            required = $false
        }
        cluster_type = @{
            type = 'str'
            required = $false
            default = 'Wsfc'
            choices = @('Wsfc', 'External', 'None')
        }
        configure_xe_session = @{ type = 'bool'; required = $false; default = $false }
        session_timeout = @{ type = 'int'; required = $false }
        state = @{type = 'str'; required = $false; default = 'present'; choices = @('present', 'absent') }
    }
    required_together = @(
        , @('sql_username_replica', 'sql_password_replica')
    )
}
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$readOnlyRoutingConnectionUrl = $module.params.read_only_routing_connection_url
$readOnlyRoutingList = $module.Params.read_only_routing_list
$failoverMode = $module.Params.failover_mode
$seedingMode = $module.Params.seeding_mode
$agName = $module.Params.ag_name
$clusterType = $module.Params.cluster_type
$availabilityMode = $module.Params.availability_mode
$replicaSqlInstance = $module.Params.sql_instance_replica
$connectionModeInPrimaryRole = $module.Params.connection_mode_in_primary_role
$connectionModeInSecondaryRole = $module.Params.connection_mode_in_secondary_role
$configureXESession = $module.Params.configure_xe_session
$state = $module.Params.state
[nullable[int]]$sessionTimeout = $module.Params.session_timeout
$endpoint = $module.Params.endpoint
$endpointUrl = $module.Params.endpoint_url
$backupPriority = $module.Params.backup_priority

if ($null -ne $module.Params.sql_username_replica) {
    [securestring]$replicaSecPassword = ConvertTo-SecureString $Module.Params.sql_password_replica -AsPlainText -Force
    [pscredential]$replicaSqlCredential = New-Object System.Management.Automation.PSCredential ($Module.Params.sql_username_replica, $replicaSecPassword)
}
if ($null -eq $replicaSqlCredential) {
    $replicaSqlCredential = $sqlCredential
}
$module.Result.changed = $false
$checkMode = $module.CheckMode
$PSDefaultParameterValues = @{ "*:EnableException" = $true; "*:Confirm" = $false; "*:WhatIf" = $checkMode }

try {
    $replicaInstance = Connect-DbaInstance -SqlInstance $replicaSqlInstance -SqlCredential $replicaSqlCredential
    $allReplicas = Get-DbaAgReplica -SqlInstance $replicaSqlInstance -SqlCredential $replicaSqlCredential -AvailabilityGroup $agName
    $existingReplica = $allReplicas | Where-Object Name -eq $replicaInstance.DomainInstanceName

    if ($state -eq "present") {
        $addReplicaSplat = @{
            SqlInstance = $replicaSqlInstance
            SqlCredential = $replicaSqlCredential
            Endpoint = $endpoint
            AvailabilityMode = $availabilityMode
            FailoverMode = $failoverMode
            BackupPriority = $backupPriority
            ConnectionModeInPrimaryRole = $connectionModeInPrimaryRole
            ConnectionModeInSecondaryRole = $connectionModeInSecondaryRole
            SeedingMode = $seedingMode
            ClusterType = $clusterType
        }
        if ($null -ne $readOnlyRoutingList) {
            $addReplicaSplat.Add("ReadOnlyRoutingList", $readOnlyRoutingList)
        }
        if ($null -ne $readOnlyRoutingConnectionUrl) {
            $addReplicaSplat.Add("ReadOnlyRoutingConnectionUrl", $readOnlyRoutingConnectionUrl)
        }
        if ($null -ne $endpointUrl) {
            $addReplicaSplat.Add("EndpointUrl", $endpointUrl)
        }
        if ($configureXESession -eq $true) {
            $addReplicaSplat.Add("ConfigureXESession", $true)
        }
        if ($null -ne $sessionTimeout) {
            $addReplicaSplat.Add("SessionTimeout", $sessionTimeout)
        }

        if ($null -eq $existingReplica) {
            $availabilityGroup = Get-DbaAvailabilityGroup -SqlInstance $sqlInstance -SqlCredential $sqlCredential -AvailabilityGroup $agName
            $output = $availabilityGroup | Add-DbaAgReplica @addReplicaSplat
            $module.Result.changed = $true
        }
        else {
            $compareReplicaProperty = @(
                'AvailabilityMode'
                'FailoverMode'
                'BackupPriority'
                'ConnectionModeInPrimaryRole'
                'ConnectionModeInSecondaryRole'
                'SeedingMode'
                'SessionTimeout'
                'EndpointUrl'
            )
            $setReplicaSplat = @{}
            $addReplicaSplat.GetEnumerator() | Where-Object Key -in $compareReplicaProperty | ForEach-Object { $setReplicaSplat.Add($_.Key, $_.Value) }
            [string[]]$compareProperty = $setReplicaSplat.Keys
            $replicaDiff = Compare-Object -ReferenceObject $setReplicaSplat -DifferenceObject $existingReplica -Property $compareProperty
            $setReplicaSplat.Add("SqlInstance", $sqlInstance)
            $setReplicaSplat.Add("SqlCredential", $sqlCredential)
            $setReplicaSplat.Add("Replica", $existingReplica.Name)
            $setReplicaSplat.Add("AvailabilityGroup", $agName)
            if ($replicaDiff) {
                $output = Set-DbaAgReplica @setReplicaSplat
                $module.Result.changed = $true
            }
        }
    }
}
catch {
    $module.FailJson("Configuring Availability Group replica failed: $($_.Exception.Message)")
}
try {
    if ($state -eq "absent") {
        if ($null -ne $existingReplica) {
            $output = $existingReplica | Remove-DbaAgReplica
            $module.Result.changed = $true
        }
    }
}
catch {
    $module.FailJson("Removing Availability Group replica failed: $($_.Exception.Message)")
}

try {
    if ($output) {
        $resultData = ConvertTo-SerializableObject -InputObject $output
        $module.Result.data = $resultData
    }
    $module.ExitJson()
}
catch {
    $module.FailJson("Error parsing results - operation likely completed: $($_.Exception.Message)")
}
