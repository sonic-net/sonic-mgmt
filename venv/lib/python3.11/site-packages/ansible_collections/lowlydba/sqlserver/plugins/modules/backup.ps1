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
        path = @{type = 'str'; required = $false }
        file_path = @{type = 'str'; required = $false }
        increment_prefix = @{type = 'bool'; required = $false; default = $false }
        replace_in_name = @{type = 'bool'; required = $false; default = $false }
        copy_only = @{type = 'bool'; required = $false; default = $false }
        type = @{type = 'str'; required = $false; default = 'database'; choices = @('full', 'log', 'differential', 'diff', 'database') }
        timestamp_format = @{type = 'str'; required = $false }
        encryption_certificate = @{type = 'str'; required = $false }
        encryption_algorithm = @{type = 'str'; required = $false; choices = @('AES128', 'AES192', 'AES256', 'TRIPLEDES') }
        create_folder = @{type = 'bool'; required = $false; default = $false }
        file_count = @{type = 'int'; required = $false; default = 0 }
        compress = @{type = 'bool'; required = $false; default = $false }
        checksum = @{type = 'bool'; required = $false; default = $false }
        verify = @{type = 'bool'; required = $false; default = $false }
        no_recovery = @{type = 'bool'; required = $false; default = $false }
        build_path = @{type = 'bool'; required = $false; default = $false }
        max_transfer_size = @{type = 'int'; required = $false; default = 0 }
        with_format = @{type = 'bool'; required = $false; default = $false }
        initialize = @{type = 'bool'; required = $false; default = $false }
        ignore_file_checks = @{type = 'bool'; required = $false; default = $false }
        block_size = @{type = 'str'; required = $false; choices = @('0.5kb', '1kb', '2kb', '4kb', '8kb', '16kb', '32kb', '64kb') }
        buffer_count = @{type = 'int'; required = $false; default = 0 }
        azure_base_url = @{type = 'str'; required = $false }
        azure_credential = @{type = 'str'; required = $false }
    }
    mutually_exclusive = @(
        , @('path', 'azure_base_url')
    )
    required_together = @(
        , @('encryption_algorithm', 'encryption_certificate')
    )
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$database = $module.Params.database
$path = $module.Params.path
$filePath = $module.Params.file_path
$incrementPrefix = $module.Params.increment_prefix
$replaceInName = $module.Params.replace_in_name
$copyOnly = $module.Params.copy_only
$type = $module.Params.type
$createFolder = $module.Params.create_folder
$fileCount = $module.Params.file_count
$compressBackup = $module.Params.compress_backup
$checkSum = $module.Params.checksum
$verify = $module.Params.verify
$maxTransferSize = $module.Params.max_transfer_size
$blockSize = $module.Params.block_size
$bufferCount = $module.Params.buffer_count
$noRecovery = $module.Params.no_recovery
$buildPath = $module.Params.build_path
$withFormat = $module.Params.with_format
$initialize = $module.Params.initialize
$timestampFormat = $module.Params.timestamp_format
$ignoreFileChecks = $module.Params.ignore_file_checks
$encryptionAlgorithm = $module.Params.encryption_algorithm
$encryptionCertificate = $modules.Params.encryption_certificate
$azureBaseUrl = $modules.Params.azure_base_url
$azureCredential = $modules.Param.azure_credential
$checkMode = $module.CheckMode
$module.Result.changed = $false
$PSDefaultParameterValues = @{ "*:EnableException" = $true; "*:Confirm" = $false; "*:WhatIf" = $checkMode }

try {
    $backupSplat = @{
        SqlInstance = $sqlInstance
        SqlCredential = $sqlCredential
        Database = $database
        IncrementPrefix = $incrementPrefix
        ReplaceInName = $replaceInName
        CopyOnly = $copyOnly
        Type = $type
        CreateFolder = $createFolder
        FileCount = $fileCount
        CompressBackup = $compressBackup
        Checksum = $checkSum
        Verify = $verify
        MaxTransferSize = $maxTransferSize
        BufferCount = $bufferCount
        NoRecovery = $noRecovery
        BuildPath = $buildPath
        WithFormat = $withFormat
        Initialize = $initialize
        IgnoreFileChecks = $ignoreFileChecks
    }
    if ($null -ne $path) {
        $backupSplat.Add("Path", $path)
    }
    if ($null -ne $filePath) {
        $backupSplat.Add("FilePath", $filePath)
    }
    if ($null -ne $blockSize) {
        $backupSplat.Add("BlockSize", ($blockSize / 1))
    }
    if ($null -ne $timestampFormat) {
        $backupSplat.Add("TimestampFormat", $timestampFormat)
    }
    if ($null -ne $encryptionAlgorithm) {
        $backupSplat.Add("EncryptionAlgorithm", $encryptionAlgorithm)
    }
    if ($null -ne $encryptionCertificate) {
        $backupSplat.Add("EncryptionCertificate", $encryptionCertificate)
    }
    if ($null -ne $azureBaseUrl) {
        $backupSplat.Add("AzureBaseURL", $azureBaseUrl)
    }
    if ($null -ne $azureCredential) {
        $backupSplat.Add("AzureCredential", $azureCredential)
    }
    $output = Backup-DbaDatabase @backupSplat

    if ($null -ne $output) {
        $resultData = ConvertTo-SerializableObject -InputObject $output
        $module.Result.data = $resultData
        $module.Result.changed = $true
    }
    $module.ExitJson()
}
catch {
    $module.FailJson("Error backing up database: $($_.Exception.Message).", $_)
}
