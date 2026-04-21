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
        username = @{type = 'str'; required = $false }
        password = @{type = 'str'; required = $false; no_log = $true }
        enabled = @{type = 'bool'; required = $false; default = $true }
        force = @{type = 'bool'; required = $false; default = $false }
    }
    required_together = @(
        , @('username', 'password')
    )
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
if ($null -ne $Module.Params.username) {
    [securestring]$secPassword = ConvertTo-SecureString $Module.Params.password -AsPlainText -Force
    [pscredential]$credential = New-Object System.Management.Automation.PSCredential ($Module.Params.username, $secPassword)
}
$enabled = $module.Params.enabled
$force = $module.Params.force
$checkMode = $module.CheckMode
$module.Result.changed = $false

try {
    $server = Connect-DbaInstance -SqlInstance $sqlInstance -SqlCredential $sqlCredential
    $existingHadr = $server | Get-DbaAgHadr -EnableException
    $output = $existingHadr
    if ($existingHadr.IsHadrEnabled -ne $enabled) {
        $setHadr = @{
            Credential = $credential
            WhatIf = $checkMode
            Force = $force
            Confirm = $false
            EnableException = $true
        }
        if ($enabled -eq $false) {
            $output = $server | Disable-DbaAgHadr @setHadr
        }
        else {
            $output = $server | Enable-DbaAgHadr @setHadr
        }

        if ($force -ne $true) {
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
    $module.FailJson("Error configuring Hadr.", $_)
}
