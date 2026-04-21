#!powershell
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ansible_collections.lowlydba.sqlserver.plugins.module_utils._SqlServerUtils
#Requires -Modules @{ ModuleName="dbatools"; ModuleVersion="2.0.0" }

$ErrorActionPreference = "Stop"

# Get Csharp utility module
$spec = @{
    supports_check_mode = $true
    options = @{
        database = @{type = 'str'; required = $true }
        local_file = @{type = 'str'; required = $false }
        force = @{type = 'bool'; required = $false; default = $false }
    }
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$database = $module.Params.database
$localFile = $module.Params.local_file
$force = $module.Params.force
$checkMode = $module.CheckMode
$module.Result.changed = $false

$whoIsActiveSplat = @{
    SqlInstance = $SqlInstance
    SqlCredential = $SqlCredential
    Database = $Database
    WhatIf = $checkMode
    Force = $force
    Confirm = $false
    EnableException = $true
}
if ($null -ne $LocalFile) {
    $whoIsActiveSplat.LocalFile = $LocalFile
}

try {
    $output = Install-DbaWhoIsActive @whoIsActiveSplat
    $module.Result.changed = $true

    if ($null -ne $output) {
        $resultData = ConvertTo-SerializableObject -InputObject $output
        $module.Result.data = $resultData
    }
    $module.ExitJson()
}

catch {
    $module.FailJson("Installing sp_WhoIsActive failed.", $_)
}
