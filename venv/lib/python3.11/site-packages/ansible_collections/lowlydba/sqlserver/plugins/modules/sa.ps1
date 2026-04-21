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
        new_name = @{type = 'str'; required = $false; }
        password = @{type = 'str'; required = $false; no_log = $true }
        enabled = @{type = 'bool'; required = $false; default = $true }
        password_must_change = @{type = 'bool'; required = $false }
        password_policy_enforced = @{type = 'bool'; required = $false }
        password_expiration_enabled = @{type = 'bool'; required = $false }
    }
}
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$newName = $module.Params.new_name
if ($null -ne $module.Params.password) {
    $secPassword = ConvertTo-SecureString -String $module.Params.password -AsPlainText -Force
}
$enabled = $module.Params.enabled
[nullable[bool]]$passwordMustChange = $module.Params.password_must_change
[nullable[bool]]$passwordExpirationEnabled = $module.Params.password_expiration_enabled
[nullable[bool]]$passwordPolicyEnforced = $module.Params.password_policy_enforced
$checkMode = $module.CheckMode
$module.Result.changed = $false

try {
    $sa = Get-DbaLogin -SqlInstance $SqlInstance -SqlCredential $sqlCredential -EnableException | Where-Object ID -eq 1

    $setLoginSplat = @{ }

    if ($null -ne $newName) {
        $setLoginSplat.Add("NewName", $newName)
        if ($sa.Name -ne $newName) {
            $changed = $true
        }
    }
    if ($null -ne $passwordExpirationEnabled) {
        if ($sa.PasswordExpirationEnabled -ne $passwordExpirationEnabled) {
            $changed = $true
        }
        if ($passwordExpirationEnabled -eq $true) {
            $setLoginSplat.add("PasswordExpirationEnabled", $true)
        }
    }
    if ($null -ne $passwordPolicyEnforced) {
        if ($sa.PasswordPolicyEnforced -ne $passwordPolicyEnforced) {
            $changed = $true
        }
        if ($passwordPolicyEnforced -eq $true) {
            $setLoginSplat.add("PasswordPolicyEnforced", $true)
        }
    }
    if ($true -eq $passwordMustChange) {
        if ($sa.PasswordMustChange -ne $passwordMustChange) {
            $changed = $true
        }
        if ($passwordMustChange -eq $true) {
            $setLoginSplat.add("PasswordMustChange", $true)
        }
    }
    if ($null -ne $secPassword) {
        $setLoginSplat.add("SecurePassword", $secPassword)
    }
    if ($enabled -eq $false) {
        $disabled = $true
        $setLoginSplat.add("Disable", $true)
    }
    else {
        $disabled = $false
        $setLoginSplat.add("Enable", $true)
    }

    # Check for changes
    if (($changed -eq $true) -or ($disabled -ne $sa.IsDisabled) -or ($secPassword)) {
        $output = $sa | Set-DbaLogin @setLoginSplat -WhatIf:$checkMode -EnableException
        $module.Result.changed = $true
    }
    else {
        $output = $sa
    }

    if ($null -ne $output) {
        $resultData = ConvertTo-SerializableObject -InputObject $output
        $module.Result.data = $resultData
    }
    $module.exitJson()
}
catch {
    $module.FailJson("Configuring 'sa' login failed: $($_.Exception.Message)", $_)
}
