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
        category = @{type = 'str'; required = $true }
        category_type = @{type = 'str'; required = $false; choices = @('LocalJob', 'MultiServerJob', 'None') }
        state = @{type = 'str'; required = $false; default = 'present'; choices = @('present', 'absent') }
    }
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$category = $module.Params.category
$categoryType = $module.Params.category_type
$state = $module.Params.state
$checkMode = $module.CheckMode
$module.Result.changed = $false

try {
    $agentJobCategorySplat = @{
        SqlInstance = $sqlInstance
        SqlCredential = $sqlCredential
        Category = $category
        EnableException = $true
    }
    if ($null -ne $categoryType) {
        $agentJobCategorySplat.Add("CategoryType", $categoryType)
    }
    $existingCategory = Get-DbaAgentJobCategory @agentJobCategorySplat

    if ($state -eq "present") {
        # Create new job category
        if ($null -eq $existingCategory) {
            $output = New-DbaAgentJobCategory @agentJobCategorySplat -WhatIf:$checkMode
            $module.Result.changed = $true
        }
    }
    elseif ($state -eq "absent") {
        if ($null -ne $existingCategory) {
            $output = $existingCategory | Remove-DbaAgentJobCategory -WhatIf:$checkMode -EnableException -Confirm:$false
            $module.Result.changed = $true
        }
    }

    if ($null -ne $output) {
        $resultData = ConvertTo-SerializableObject -InputObject $output
        $module.Result.data = $resultData
    }
    $module.ExitJson()
}
catch {
    $module.FailJson("Error configuring SQL Agent job category.", $_)
}
