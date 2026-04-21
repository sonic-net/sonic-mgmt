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
        backup_location = @{type = 'str'; required = $false }
        cleanup_time = @{type = 'int'; required = $false; default = 0 }
        output_file_dir = @{type = 'str'; required = $false }
        replace_existing = @{type = 'bool'; required = $false; }
        log_to_table = @{type = 'bool'; required = $false; default = $false }
        solution = @{type = 'str'; required = $false; choices = @('All', 'Backup', 'IntegrityCheck', 'IndexOptimize'); default = 'All' }
        install_jobs = @{type = 'bool'; required = $false; default = $false }
        local_file = @{type = 'str'; required = $false }
        database = @{type = 'str'; required = $true }
        force = @{type = 'bool'; required = $false; default = $false }
        install_parallel = @{type = 'bool'; required = $false; default = $false }
    }
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$database = $module.Params.database
$backupLocation = $module.Params.backup_location
$outputFileDirectory = $module.Params.output_file_dir
$cleanupTime = $module.Params.cleanup_time
$replaceExisting = $module.Params.replace_existing
$solution = $module.Params.solution
$installJobs = $module.Params.install_jobs
$installParallel = $module.Params.install_parallel
$logToTable = $module.Params.log_to_table
$localFile = $module.Params.local_file
$force = $module.Params.force
$checkMode = $module.CheckMode
$module.Result.changed = $false

try {
    $maintenanceSolutionSplat = @{
        SqlInstance = $sqlInstance
        SqlCredential = $sqlCredential
        Database = $database
        LogToTable = $logToTable
        Solution = $solution
        InstallJobs = $installJobs
        InstallParallel = $installParallel
        WhatIf = $checkMode
        Force = $force
        Confirm = $false
        EnableException = $true
    }
    if ($null -ne $localFile) {
        $maintenanceSolutionSplat.LocalFile = $localFile
    }
    if ($null -ne $backupLocation) {
        $maintenanceSolutionSplat.BackupLocation = $backupLocation
    }
    if ($null -ne $outputFileDirectory) {
        $maintenanceSolutionSplat.OutputFileDirectory = $outputFileDirectory
    }
    if ($installJobs -eq $true -and $null -ne $cleanupTime) {
        $maintenanceSolutionSplat.CleanupTime = $cleanupTime
    }
    # Only pass if true, otherwise removes warning that is used to track changed=$false
    if ($replaceExisting -eq $true) {
        $maintenanceSolutionSplat.ReplaceExisting = $replaceExisting
    }

    try {
        $output = Install-DbaMaintenanceSolution @maintenanceSolutionSplat
        $module.Result.changed = $true
    }
    catch {
        $errMessage = $_.Exception.Message
        if ($errMessage -like "*Maintenance Solution already exists*") {
            $server = Connect-DbaInstance -SqlInstance $sqlInstance -SqlCredential $sqlCredential
            $output = [PSCustomObject]@{
                ComputerName = $server.ComputerName
                InstanceName = $server.ServiceName
                SqlInstance = $server.DomainInstanceName
                Results = "Success"
            }
        }
        else {
            Write-Error -Message $errMessage
        }
    }

    if ($null -ne $output) {
        $resultData = ConvertTo-SerializableObject -InputObject $output
        $module.Result.data = $resultData
    }
    $module.ExitJson()
}
catch {
    $module.FailJson("Installing Maintenance Solution failed.", $_)
}
