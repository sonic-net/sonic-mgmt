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
        database = @{type = 'str'; required = $false }
        path = @{type = 'str'; required = $true }
        destination_data_directory = @{type = 'str'; required = $false }
        destination_log_directory = @{type = 'str'; required = $false }
        destination_filestream_directory = @{type = 'str'; required = $false }
        restore_time = @{type = 'str'; required = $false }
        with_replace = @{type = 'bool'; required = $false; default = $false }
        keep_replication = @{type = 'bool'; required = $false; default = $false }
        xp_dirtree = @{type = 'bool'; required = $false }
        no_xp_dir_recurse = @{type = 'bool'; required = $false; default = $false }
        verify_only = @{type = 'bool'; required = $false; default = $false }
        maintenance_solution_backup = @{type = 'bool'; required = $false; default = $false }
        ignore_log_backup = @{type = 'bool'; required = $false; default = $false }
        ignore_diff_backup = @{type = 'bool'; required = $false; default = $false }
        use_destination_default_directories = @{type = 'bool'; required = $false }
        reuse_source_folder_structure = @{type = 'bool'; required = $false }
        destination_file_prefix = @{type = 'str'; required = $false }
        restored_database_name_prefix = @{type = 'str'; required = $false }
        directory_recurse = @{type = 'bool'; required = $false; default = $false }
        standby_directory = @{type = 'str'; required = $false }
        replace_db_name_in_file = @{type = 'bool'; required = $false }
        destination_file_suffix = @{type = 'str'; required = $false }
        keep_cdc = @{type = 'bool'; required = $false }
        stop_before = @{type = 'bool'; required = $false; default = $false }
        stop_mark = @{type = 'str'; required = $false }
        stop_after_date = @{type = 'str'; required = $false }
        no_recovery = @{type = 'bool'; required = $false; default = $false }
        max_transfer_size = @{type = 'int'; required = $false; default = 0 }
        block_size = @{type = 'str'; required = $false; choices = @('0.5kb', '1kb', '2kb', '4kb', '8kb', '16kb', '32kb', '64kb') }
        buffer_count = @{type = 'int'; required = $false; default = 0 }
        azure_credential = @{type = 'str'; required = $false }
    }
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$database = $module.Params.database
$path = $module.Params.path
$destinationDataDirectory = $module.Params.destination_data_directory
$destinationLogDirectory = $module.Params.destination_log_directory
$destinationFilestreamDirectory = $module.Params.destination_filestream_directory
$restoreTime = $module.Params.restore_time
$withReplace = $module.Params.with_replace
$keepReplication = $module.Params.keep_replication
$xpDirTree = $module.Params.xp_dirtree
$noXpDirRecurse = $module.Params.no_xp_dir_recurse
$verifyOnly = $module.Params.verify_only
$maintenanceSolutionBackup = $module.Params.maintenance_solution_backup
$ignoreLogBackup = $module.Params.ignore_log_backup
$ignoreDiffBackup = $module.Params.ignore_diff_backup
$useDestinationDefaultDirectories = $module.Params.use_destination_default_directories
$reuseSourceFolderStructure = $module.Params.reuse_source_folder_structure
$destinationFilePrefix = $module.Params.destination_file_prefix
$restoredDatabaseNamePrefix = $module.Params.restored_database_name_prefix
$directoryRecurse = $module.Params.directory_recurse
$standbyDirectory = $module.Params.standby_directory
$replaceDbNameInFile = $module.Params.replace_db_name_in_file
$destinationFileSuffix = $module.Params.destination_file_suffix
$keepCDC = $module.Params.keep_cdc
$stopBefore = $module.Params.stop_before
$stopMark = $module.Params.stop_mark
$stopAfterDate = $module.Params.stop_after_date
$noRecovery = $module.Params.no_recovery
$maxTransferSize = $module.Params.max_transfer_size
$blockSize = $module.Params.block_size
$bufferCount = $module.Params.buffer_count
$azureCredential = $modules.Param.azure_credential
$checkMode = $module.CheckMode
$module.Result.changed = $false
$PSDefaultParameterValues = @{ "*:EnableException" = $true; "*:Confirm" = $false; "*:WhatIf" = $checkMode }

try {
    $restoreSplat = @{
        SqlInstance = $sqlInstance
        SqlCredential = $sqlCredential
        Path = $path
        WithReplace = $withReplace
        KeepReplication = $keepReplication
        NoXpDirRecurse = $noXpDirRecurse
        VerifyOnly = $verifyOnly
        MaintenanceSolutionBackup = $maintenanceSolutionBackup
        IgnoreLogBackup = $ignoreLogBackup
        IgnoreDiffBackup = $ignoreDiffBackup
        DirectoryRecurse = $directoryRecurse
        StopBefore = $stopBefore
        NoRecovery = $noRecovery
        MaxTransferSize = $maxTransferSize
        BufferCount = $bufferCount
    }
    if ($null -ne $database) {
        $restoreSplat.Add("DatabaseName", $database)
    }
    if ($null -ne $destinationDataDirectory) {
        $restoreSplat.Add("DestinationDataDirectory", $destinationDataDirectory)
    }
    if ($null -ne $destinationLogDirectory) {
        $restoreSplat.Add("DestinationLogDirectory", $destinationLogDirectory)
    }
    if ($null -ne $destinationFilestreamDirectory) {
        $restoreSplat.Add("DestinationFilestreamDirectory", $destinationFilestreamDirectory)
    }
    if ($null -ne $restoreTime) {
        $restoreSplat.Add("RestoreTime", $restoreTime)
    }
    if ($null -ne $destinationFilePrefix) {
        $restoreSplat.Add("DestinationFilePrefix", $destinationFilePrefix)
    }
    if ($null -ne $restoredDatabaseNamePrefix) {
        $restoreSplat.Add("RestoredDatabaseNamePrefix", $restoredDatabaseNamePrefix)
    }
    if ($null -ne $standbyDirectory) {
        $restoreSplat.Add("StandbyDirectory", $standbyDirectory)
    }
    if ($null -ne $destinationFileSuffix) {
        $restoreSplat.Add("DestinationFileSuffix", $destinationFileSuffix)
    }
    if ($null -ne $stopAfterDate) {
        $restoreSplat.Add("StopAfterDate", $stopAfterDate)
    }
    if ($null -ne $stopMark) {
        $restoreSplat.Add("StopMark", $stopMark)
    }
    if ($null -ne $blockSize) {
        $restoreSplat.Add("BlockSize", ($blockSize / 1))
    }
    if ($null -ne $azureCredential) {
        $restoreSplat.Add("AzureCredential", $azureCredential)
    }
    if ($null -ne $xpDirTree) {
        $restoreSplat.Add("xpDirTree", $xpDirTree)
    }
    if ($null -ne $reuseSourceFolderStructure) {
        $restoreSplat.Add("reuseSourceFolderStructure", $reuseSourceFolderStructure)
    }
    if ($null -ne $replaceDbNameInFile) {
        $restoreSplat.Add("replaceDbNameInFile", $replaceDbNameInFile)
    }
    if ($null -ne $useDestinationDefaultDirectories) {
        $restoreSplat.Add("useDestinationDefaultDirectories", $useDestinationDefaultDirectories)
    }
    if ($null -ne $keepCDC) {
        $restoreSplat.Add("KeepCDC", $keepCDC)
    }
    $output = Restore-DbaDatabase @restoreSplat -WarningVariable warnings

    if ($null -ne $output) {
        $resultData = ConvertTo-SerializableObject -InputObject $output
        $module.Result.data = $resultData
        $module.Result.changed = $true
    }
    $module.ExitJson()
}
catch {
    # Restore command hides relevant error info as warnings, so append warning logs to any failures
    $warningMessage = ""
    if ($warnings) {
        $warningMessage = " Additional warnings: $warnings."
    }
    $module.FailJson("Error restoring database: $($_.Exception.Message).$warningMessage", $_)
}
