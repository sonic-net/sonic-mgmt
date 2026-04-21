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
        branch = @{type = 'str'; required = $false; choices = @('master', 'development') }
        local_file = @{type = 'str'; required = $false }
        database = @{type = 'str'; required = $true }
        force = @{type = 'bool'; required = $false; default = $false }
    }
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$database = $module.Params.database
$branch = $module.Params.branch
$localFile = $module.Params.local_file
$force = $module.Params.force
$checkMode = $module.Checkmode
$PSDefaultParameterValues = @{ "*:EnableException" = $true; "*:Confirm" = $false; "*:WhatIf" = $checkMode }

$multiToolSplat = @{
    SqlInstance = $sqlInstance
    SqlCredential = $sqlCredential
    Database = $database
    Force = $force
}
if ($null -ne $localFile) {
    $multiToolSplat.LocalFile = $localFile
}
if ($null -ne $branch) {
    $multiToolSplat.Branch = $branch
}

try {
    $output = Install-DbaMultiTool @multiToolSplat
    $module.Result.changed = $true

    # output is an array for each stored proc,
    # rollup output into a single result
    $errorProcs = $output | Where-Object Status -eq "Error"
    if ($errorProcs) {
        $output = $errorProcs[0] | Select-Object -ExcludeProperty Name
    }
    else {
        $output = $output[0] | Select-Object -ExcludeProperty Name
    }
    if ($null -ne $output) {
        $resultData = ConvertTo-SerializableObject -InputObject $output
        $module.Result.data = $resultData
    }
    $module.ExitJson()
}
catch {
    $module.FailJson("Installing DBA-MultiTool failed: $($_.Exception.Message)", $_)
}
