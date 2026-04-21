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
        login = @{type = 'str'; required = $true }
        password = @{type = 'str'; required = $false; no_log = $true }
        enabled = @{type = 'bool'; required = $false; default = $true }
        default_database = @{type = 'str'; required = $false }
        language = @{type = 'str'; required = $false }
        password_must_change = @{type = 'bool'; required = $false }
        password_policy_enforced = @{type = 'bool'; required = $false }
        password_expiration_enabled = @{type = 'bool'; required = $false }
        sid = @{type = 'str'; required = $false }
        skip_password_reset = @{type = 'bool'; required = $false; default = $false }
        state = @{type = 'str'; required = $false; default = 'present'; choices = @('present', 'absent') }
    }
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$login = $module.Params.login
if ($null -ne $module.Params.password) {
    $secPassword = ConvertTo-SecureString -String $module.Params.password -AsPlainText -Force
}
$enabled = $module.Params.enabled
$defaultDatabase = $module.Params.default_database
$language = $module.Params.language
[nullable[bool]]$passwordMustChange = $module.Params.password_must_change
[nullable[bool]]$passwordExpirationEnabled = $module.Params.password_expiration_enabled
[nullable[bool]]$passwordPolicyEnforced = $module.Params.password_policy_enforced
[nullable[bool]]$skip_password_reset = $module.Params.skip_password_reset
$sid = $module.Params.sid
$state = $module.Params.state
$checkMode = $module.CheckMode

$module.Result.changed = $false

try {
    $getLoginSplat = @{
        SqlInstance = $sqlInstance
        SqlCredential = $sqlCredential
        Login = $login
        ExcludeSystemLogin = $true
        EnableException = $true
    }
    $existingLogin = Get-DbaLogin @getLoginSplat

    if ($state -eq "absent") {
        if ($null -ne $existingLogin) {
            $output = $existingLogin | Remove-DbaLogin -WhatIf:$checkMode -EnableException -Force -Confirm:$false
            $module.Result.changed = $true
        }
    }
    elseif ($state -eq "present") {
        $setLoginSplat = @{
            SqlInstance = $sqlInstance
            SqlCredential = $sqlCredential
            Login = $login
            WhatIf = $checkMode
            EnableException = $true
            Confirm = $false
        }
        if ($null -ne $defaultDatabase) {
            $setLoginSplat.add("DefaultDatabase", $defaultDatabase)
        }
        if ($null -ne $passwordExpirationEnabled) {
            if ($existingLogin.PasswordExpirationEnabled -ne $passwordExpirationEnabled) {
                $changed = $true
            }
            if ($passwordExpirationEnabled -eq $true) {
                $setLoginSplat.add("PasswordExpirationEnabled", $true)
            }
        }
        if ($null -ne $passwordPolicyEnforced) {
            if ($existingLogin.PasswordPolicyEnforced -ne $passwordPolicyEnforced) {
                $changed = $true
            }
            if ($passwordPolicyEnforced -eq $true) {
                $setLoginSplat.add("PasswordPolicyEnforced", $true)
            }
        }
        if ($true -eq $passwordMustChange) {
            if ($existingLogin.PasswordMustChange -ne $passwordMustChange) {
                $changed = $true
            }
            if ($passwordMustChange -eq $true) {
                $setLoginSplat.add("PasswordMustChange", $true)
            }
        }

        # Login already exists
        if ($null -ne $existingLogin) {
            if (($null -ne $secPassword) -and ($skip_password_reset -eq $false)) {
                $setLoginSplat.add("SecurePassword", $secPassword)
                $changed = $true
            }

            # Splat login status
            if ($enabled -eq $false) {
                $disabled = $true
                $setLoginSplat.add("Disable", $true)
            }
            else {
                $disabled = $false
                $setLoginSplat.add("Enable", $true)
            }
            # Login needs to be modified
            if (($changed -eq $true) -or ($disabled -ne $existingLogin.IsDisabled) -or ($setLoginSplat.ContainsKey("SecurePassword"))) {
                $output = Set-DbaLogin @setLoginSplat
                $module.result.changed = $true
            }
        }
        # New login
        else {
            $setLoginSplat.add("SecurePassword", $secPassword)
            if ($null -ne $language) {
                $setLoginSplat.add("Language", $language)
            }
            if ($enabled -eq $false) {
                $setLoginSplat.add("Disabled", $true)
            }
            if ($null -ne $sid) {
                $setLoginSplat.add("Sid", $sid)
            }
            $output = New-DbaLogin @setLoginSplat
            $module.result.changed = $true
        }
        # If not in check mode, add extra fields we can change to default display set
        if ($null -ne $output) {
            $output.PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames.Add("DefaultDatabase")
            $output.PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames.Add("Language")
        }
    }

    if ($null -ne $output) {
        $resultData = ConvertTo-SerializableObject -InputObject $output
        $module.Result.data = $resultData
    }
    $module.ExitJson()
}
catch {
    $module.FailJson("Configuring login failed: $($_.Exception.Message) ; $setLoginSplat", $_)
}
