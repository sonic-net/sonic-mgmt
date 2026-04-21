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
        database = @{type = 'str'; required = $true }
        recovery_model = @{type = 'str'; required = $false; choices = @('Full', 'Simple', 'BulkLogged') }
        data_file_path = @{type = 'str'; required = $false }
        log_file_path = @{type = 'str'; required = $false }
        owner = @{type = 'str'; required = $false; }
        maxdop = @{type = 'int'; required = $false; }
        secondary_maxdop = @{type = 'int'; required = $false; }
        compatibility = @{type = 'str'; required = $false; }
        rcsi = @{type = 'bool'; required = $false; }
        only_accessible = @{type = 'bool'; default = 'true' }
        state = @{type = 'str'; required = $false; default = 'present'; choices = @('present', 'absent') }
    }
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$database = $module.Params.database
$recoveryModel = $module.Params.recovery_model
$dataFilePath = $module.Params.data_file_path
$logFilePath = $module.Params.log_file_path
$owner = $module.Params.owner
$compatibility = $module.Params.compatibility
[nullable[bool]]$rcsiEnabled = $module.Params.rcsi
[nullable[bool]]$onlyAccessible = $module.Params.only_accessible
[nullable[int]]$maxDop = $module.Params.maxdop
[nullable[int]]$secondaryMaxDop = $module.Params.secondary_maxdop
$state = $module.Params.state
$checkMode = $module.CheckMode

try {
    # Get database status
    try {
        $server = Connect-DbaInstance -SqlInstance $sqlInstance -SqlCredential $sqlCredential
        $getDatabaseSplat = @{
            SqlInstance = $sqlInstance
            SqlCredential = $sqlCredential
            Database = $database
            OnlyAccessible = $onlyAccessible
            ExcludeSystem = $true
            EnableException = $true
        }
        $existingDatabase = Get-DbaDatabase @getDatabaseSplat
        $output = $existingDatabase
    }
    catch {
        $module.FailJson("Error checking database status.", $_.Exception.Message)
    }

    if ($state -eq "absent") {
        if ($null -ne $existingDatabase) {
            try {
                $droppedDatabase = $existingDatabase | Remove-DbaDatabase -WhatIf:$checkMode -EnableException -Confirm:$false
                if ($droppedDatabase.Status -eq "Dropped") {
                    $module.Result.changed = $true
                }
                elseif ($droppedDatabase.Status -ne "Dropped") {
                    $module.FailJson("Database [$database] was not dropped. " + $droppedDatabase.Status)
                }
            }
            catch {
                $module.FailJson("An exception occurred while trying to drop database [$database].", $_)
            }
        }
        $module.ExitJson()
    }
    elseif ($state -eq "present") {
        # Create database
        if ($null -eq $existingDatabase) {
            try {
                $newDbParams = @{
                    SqlInstance = $sqlInstance
                    SqlCredential = $sqlCredential
                    Database = $database
                    WhatIf = $checkMode
                    EnableException = $true
                }
                if ($null -ne $dataFilePath) {
                    $newDbParams.Add("DataFilePath", $dataFilePath)
                }
                if ($null -ne $logFilePath) {
                    $newDbParams.Add("LogFilePath", $logFilePath)
                }
                if ($null -ne $owner) {
                    $newDbParams.Add("Owner", $owner)
                }
                $output = New-DbaDatabase @newDbParams
                $module.Result.changed = $true
            }
            catch {
                $module.FailJson("Creating database [$database] failed.", $_)
            }
        }
        # Set Owner
        elseif ($null -ne $owner) {
            try {
                if ($existingDatabase.Owner -ne $owner) {
                    $setDbParams = @{
                        SqlInstance = $sqlInstance
                        SqlCredential = $sqlCredential
                        Database = $database
                        TargetLogin = $owner
                        WhatIf = $checkMode
                        EnableException = $true
                    }
                    $null = Set-DbaDbOwner @setDbParams
                    $output = Get-DbaDatabase @getDatabaseSplat
                    $module.Result.changed = $true
                }
            }
            catch {
                $module.FailJson("Setting database owner for [$database] failed.", $_)
            }
        }

        # Add non-standard fields to output
        if ($null -ne $output) {
            # Secondary MaxDop
            [int]$existingSecondaryMaxDop = $server.Databases[$database].SecondaryMaxDop
            $output | Add-Member -MemberType NoteProperty -Name "SecondaryMaxDop" -Value $existingSecondaryMaxDop
            $output.PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames.Add("SecondaryMaxDop")

            # MaxDop (exists, but is not in default display)
            $existingMaxDop = $server.Databases[$database].MaxDop
            $output.PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames.Add("MaxDop")

            # RCSI
            $existingRCSI = $server.Databases[$database].IsReadCommittedSnapshotOn
            $output | Add-Member -MemberType NoteProperty -Name "RCSI" -Value $existingRCSI
            $output.PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames.Add("RCSI")
        }

        # Recovery Model
        if ($null -ne $recoveryModel) {
            try {
                if ($recoveryModel -ne $output.RecoveryModel) {
                    $recoveryModelSplat = @{
                        SqlInstance = $sqlInstance
                        SqlCredential = $sqlCredential
                        Database = $database
                        RecoveryModel = $recoveryModel
                        WhatIf = $checkMode
                        EnableException = $true
                        Confirm = $false
                    }
                    $null = Set-DbaDbRecoveryModel @recoveryModelSplat
                    $output.RecoveryModel = $recoveryModel
                    $module.Result.changed = $true
                }
            }
            catch {
                $module.FailJson("Setting recovery model for [$database] failed.", $_)
            }
        }

        # Compatibility Mode
        if ($null -ne $compatibility) {
            try {
                $existingCompatibility = $output.Compatibility
                if ($compatibility -ne $existingCompatibility) {
                    $compatSplat = @{
                        SqlInstance = $sqlInstance
                        SqlCredential = $sqlCredential
                        Database = $database
                        Compatibility = $compatibility
                        WhatIf = $checkMode
                        EnableException = $true
                    }
                    $null = Set-DbaDbCompatibility @compatSplat
                    $output.Compatibility = $compatibility
                    $module.Result.changed = $true
                }
            }
            catch {
                $module.FailJson("Setting Compatibility for [$database] failed.", $_)
            }
        }

        # RCSI
        if ($null -ne $rcsiEnabled) {
            try {
                if ($rcsiEnabled -ne $existingRCSI) {
                    if (-not $checkMode) {
                        $server.Databases[$database].IsReadCommittedSnapshotOn = $rcsiEnabled
                        $server.Databases[$database].Alter()
                        $output.RCSI = $rcsiEnabled
                    }
                    $module.Result.changed = $true
                }
            }
            catch {
                $module.FailJson("Setting Read Commmitted Snapshot Isolation for [$database] failed.", $_)
            }
        }

        # Configure MAXDOPs
        ## Database Scoped MaxDop
        if ($null -ne $MaxDop) {
            try {
                if ($MaxDop -ne $existingMaxDop) {
                    if (-not $checkMode) {
                        $server.Databases[$database].MaxDop = $maxDop
                        $server.Databases[$database].Alter()
                        $output.MaxDop = $MaxDOP
                    }
                    $module.Result.changed = $true
                }
            }
            catch {
                $module.FailJson("Setting MAXDOP for [$database] failed.", $_)
            }
        }

        ## Secondary Mode MaxDop
        if ($null -ne $secondaryMaxDOP) {
            try {
                if ($secondaryMaxDop -ne $existingSecondaryMaxDop) {
                    if (-not $checkMode) {
                        $server.Databases[$database].MaxDopForSecondary = $secondaryMaxDOP
                        $server.Databases[$database].Alter()
                        $output.SecondaryMaxDop = $secondaryMaxDop
                    }
                    $module.Result.changed = $true
                }
            }
            catch {
                $module.FailJson("Setting MaxDop for secondary mode failed.", $_)
            }
        }
    }

    if ($null -ne $output) {
        $resultData = ConvertTo-SerializableObject -InputObject $output
        $module.Result.data = $resultData
    }
    $module.ExitJson()
}
catch {
    $module.FailJson("Configuring database failed: $($_.Exception.Message)", $_)
}
