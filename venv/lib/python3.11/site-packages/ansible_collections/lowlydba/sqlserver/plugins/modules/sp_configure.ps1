#!powershell
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# (c) 2021, Sudhir Koduri (@kodurisudhir)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ansible_collections.lowlydba.sqlserver.plugins.module_utils._SqlServerUtils
#Requires -Modules @{ ModuleName="dbatools"; ModuleVersion="2.0.0" }

$ErrorActionPreference = "Stop"

# Get Csharp utility module
$spec = @{
    supports_check_mode = $true
    options = @{
        name = @{type = 'str'; required = $true }
        value = @{type = 'int'; required = $true }
    }
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$name = $module.Params.name
$value = $module.Params.value
$checkMode = $module.CheckMode
$module.Result.changed = $false

try {
    $existingConfig = Get-DbaSpConfigure -SqlInstance $sqlInstance -SqlCredential $sqlCredential -Name $name -EnableException

    if ($existingConfig.ConfiguredValue -ne $value) {
        $setSpConfigureSplat = @{
            SqlInstance = $sqlInstance
            SqlCredential = $sqlCredential
            Name = $name
            Value = $value
            WhatIf = $checkMode
            EnableException = $true
        }
        $output = Set-DbaSpConfigure @setSpConfigureSplat

        if ($existingConfig.IsDynamic -eq $false) {
            $output | Add-Member -MemberType NoteProperty -Name "RestartRequired" -Value $true
        }
        $module.Result.changed = $true
    }

    if ($null -ne $output) {
        $resultData = ConvertTo-SerializableObject -InputObject $output
        $module.Result.data = $resultData
    }
    $module.ExitJson()
}

catch {
    $module.FailJson("sp_configure change failed.", $_)
}
