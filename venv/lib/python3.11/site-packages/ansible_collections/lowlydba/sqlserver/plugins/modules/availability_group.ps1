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
        sql_instance_secondary = @{type = "str"; required = $false }
        sql_username_secondary = @{type = 'str'; required = $false }
        sql_password_secondary = @{type = 'str'; required = $false; no_log = $true }
        database = @{type = "str"; required = $false; aliases = @('database_name') }
        ag_name = @{type = "str"; required = $true }
        all_ags = @{type = "bool"; required = $false; }
        shared_path = @{type = "str"; required = $false; default = $null }
        dtc_support_enabled = @{type = "bool"; required = $false; }
        basic_availability_group = @{type = "bool"; required = $false; }
        contained_availability_group = @{type = "bool"; required = $false; }
        database_health_trigger = @{type = "bool"; required = $false; }
        is_distributed_ag = @{type = "bool"; required = $false; }
        use_last_backup = @{type = "bool"; required = $false; }
        healthcheck_timeout = @{type = "int"; required = $false; }
        availability_mode = @{
            type = "str"
            required = $false
            default = "SynchronousCommit"
            choices = @("SynchronousCommit", "AsynchronousCommit")
        }
        failure_condition_level = @{
            type = "str"
            required = $false
            choices = @(
                "OnAnyQualifiedFailureCondition",
                "OnCriticalServerErrors",
                "OnModerateServerErrors",
                "OnServerDown",
                "OnServerUnresponsive"
            )
        }
        failover_mode = @{
            type = "str"
            required = $false
            default = "Automatic"
            choices = @("Manual", "Automatic")
        }
        seeding_mode = @{
            type = "str"
            required = $false
            default = "Manual"
            choices = @("Manual", "Automatic")
        }
        automated_backup_preference = @{
            type = "str"
            required = $false
            default = "Secondary"
            choices = @("None", "Primary", "Secondary", "SecondaryOnly")
        }
        cluster_type = @{
            type = "str"
            required = $false
            default = "Wsfc"
            choices = @("Wsfc", "External", "None")
        }
        allow_null_backup = @{type = "bool"; required = $false }
        force = @{type = "bool"; required = $false }
        state = @{type = "str"; required = $false; default = "present"; choices = @("present", "absent") }
    }
    required_together = @(
        , @('sql_username_secondary', 'sql_password_secondary')
    )
}

# Setup var
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$ProgressPreference = "SilentlyContinue"

# Var
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$secondary = $module.Params.sql_instance_secondary
if ($null -ne $module.Params.sql_username_secondary) {
    [securestring]$secondarySecPassword = ConvertTo-SecureString $Module.Params.sql_password_secondary -AsPlainText -Force
    [pscredential]$secondarySqlCredential = New-Object System.Management.Automation.PSCredential ($Module.Params.sql_username_secondary, $secondarySecPassword)
}
$agName = $module.Params.ag_name
$database = $module.Params.database
$seedingMode = $module.Params.seeding_mode
$sharedPath = $module.Params.shared_path
$healthCheckTimeout = $module.Params.healthcheck_timeout
$availabilityMode = $module.Params.availability_mode
$failureConditionLevel = $module.Params.failure_condition_level
$failoverMode = $module.Params.failover_mode
$automatedBackupPreference = $module.Params.automated_backup_preference
$clusterType = $module.Params.cluster_type
$state = $module.Params.state
[nullable[bool]]$all_ags = $module.Params.all_ags
[nullable[bool]]$useLastBackup = $module.Params.use_last_backup
[nullable[bool]]$dtcSupportEnabled = $module.Params.dtc_support_enabled
[nullable[bool]]$basicAvailabilityGroup = $module.Params.basic_availability_group
[nullable[bool]]$containedAvailabilityGroup = $module.Params.contained_availability_group
[nullable[bool]]$databaseHealthTrigger = $module.Params.database_health_trigger
[nullable[bool]]$isDistributedAg = $module.Params.is_distributed_ag
[nullable[bool]]$force = $module.Params.force
[nullable[bool]]$allowNullBackup = $module.Params.allow_null_backup
$checkMode = $module.CheckMode
$module.Result.changed = $false
$PSDefaultParameterValues = @{ "*:EnableException" = $true; "*:Confirm" = $false; "*:WhatIf" = $checkMode }

try {
    $existingAG = Get-DbaAvailabilityGroup -SqlInstance $sqlInstance -SqlCredential $sqlCredential -AvailabilityGroup $agName

    if ($state -eq "present") {
        $agSplat = @{
            Primary = $sqlInstance
            PrimarySqlCredential = $sqlCredential
            Name = $agName
            SeedingMode = $seedingMode
            FailoverMode = $failoverMode
            AvailabilityMode = $availabilityMode
            AutomatedBackupPreference = $automatedBackupPreference
            ClusterType = $clusterType
        }
        if ($null -ne $sharedPath -and $seedingMode -eq "Manual") {
            $agSplat.Add("SharedPath", $sharedPath)
        }
        if ($useLastBackup -eq $true) {
            $agSplat.Add("UseLastBackup", $useLastBackup)
        }
        if ($dtcSupportEnabled -eq $true) {
            $agSplat.Add("DtcSupport", $dtcSupportEnabled)
        }
        if ($basicAvailabilityGroup -eq $true) {
            $agSplat.Add("Basic", $basicAvailabilityGroup)
        }
        if ($containedAvailabilityGroup -eq $true) {
            $agSplat.Add("IsContained", $containedAvailabilityGroup)
        }
        if ($databaseHealthTrigger -eq $true) {
            $agSplat.Add("DatabaseHealthTrigger", $databaseHealthTrigger)
        }
        if ($null -ne $healthCheckTimeout) {
            $agSplat.Add("HealthCheckTimeout", $healthCheckTimeout)
        }
        if ($null -ne $failureConditionLevel) {
            $agSplat.Add("FailureConditionLevel", $failureConditionLevel)
        }
        if ($null -ne $database) {
            $agSplat.Add("Database", $database)
        }
        if ($null -ne $secondary) {
            $agSplat.Add("Secondary", $secondary)
        }
        if ($null -ne $secondarySqlCredential) {
            $agSplat.Add("SecondarySqlCredential", $secondarySqlCredential)
        }
        if ($force -eq $true) {
            $agSplat.Add("Force", $force)
        }

        # Create the AG with initial replica(s)
        if ($null -eq $existingAG) {
            # Full backup requirement for new AG via automatic seeding
            if ($seedingMode -eq "automatic" -and $null -ne $database) {
                $dbBackup = Get-DbaLastBackup -SqlInstance $sqlInstance -SqlCredential $sqlCredential -Database $database
                if ($null -eq $dbBackup.LastFullBackup -and $allowNullBackup -eq $true) {
                    $backupSplat = @{
                        SqlInstance = $sqlInstance
                        SqlCredential = $sqlCredential
                        Database = $database
                        FilePath = "NUL"
                        Type = "Full"
                    }
                    $null = Backup-DbaDatabase @backupSplat
                }
            }
            $output = New-DbaAvailabilityGroup @agSplat
            $module.Result.changed = $true
        }
        # Configure existing AG
        else {
            $setAgSplat = @{
                AutomatedBackupPreference = $automatedBackupPreference
                ClusterType = $clusterType
            }
            if ($all_ags -eq $true) {
                $setAgSplat.Add("AllAvailabilityGroups", $all_ags)
            }
            if ($dtcSupportEnabled -eq $true) {
                $setAgSplat.Add("DtcSupportEnabled", $dtcSupportEnabled)
            }
            if ($basicAvailabilityGroup -eq $true) {
                $setAgSplat.Add("BasicAvailabilityGroup", $basicAvailabilityGroup)
            }
            if ($databaseHealthTrigger -eq $true) {
                $setAgSplat.Add("DatabaseHealthTrigger", $databaseHealthTrigger)
            }
            if ($null -ne $failureConditionLevel) {
                $setAgSplat.Add("FailureConditionLevel", $failureConditionLevel)
            }
            if ($null -ne $healthCheckTimeout) {
                $setAgSplat.Add("HealthCheckTimeout", $healthCheckTimeout)
            }
            if ($isDistributedAg -eq $true) {
                $setAgSplat.Add("IsDistributedAvailabilityGroup", $isDistributedAg)
            }
            $compareProperty = ($existingAG.Properties | Where-Object Name -in $setAgSplat.Keys).Name
            $agDiff = Compare-Object -ReferenceObject $existingAG -DifferenceObject $setAgSplat -Property $compareProperty
            if ($null -ne $agDiff) {
                $output = $existingAG | Set-DbaAvailabilityGroup @setAgSplat
                $module.Result.changed = $true
            }
        }
    }
    elseif ($state -eq "absent") {
        if ($null -ne $existingAG) {
            if ($all_ags -eq $true) {
                $existingAG | Remove-DbaAvailabilityGroup -AllAvailabilityGroups
            }
            else {
                $existingAG | Remove-DbaAvailabilityGroup
            }
            $module.Result.changed = $true
        }
    }

    if ($output) {
        $resultData = ConvertTo-SerializableObject -InputObject $output
        $module.Result.data = $resultData
    }
    $module.ExitJson()
}
catch {
    $module.FailJson("Configuring Availability Group failed: $($_.Exception.Message)", $_)
}
