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
        server_role = @{type = 'str'; required = $true }
        state = @{type = 'str'; required = $false; default = 'present'; choices = @('present', 'absent') }
    }
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$login = $module.Params.login
$serverRole = $module.Params.server_role
$state = $module.Params.state
$checkMode = $module.CheckMode

$module.Result.changed = $false

$getLoginSplat = @{
    SqlInstance = $sqlInstance
    SqlCredential = $sqlCredential
    Login = $login
    EnableException = $true
}
$getRoleSplat = @{
    SqlInstance = $sqlInstance
    SqlCredential = $sqlCredential
    ServerRole = $serverRole
    EnableException = $true
}
$getRoleMemberSplat = @{
    SqlInstance = $sqlInstance
    SqlCredential = $sqlCredential
    Login = $login
    ServerRole = $serverRole
    EnableException = $true
}

$existingLogin = Get-DbaLogin @getLoginSplat
if ($null -eq $existingLogin) {
    $module.FailJson("Login [$login] does not exist.")
}
$existingRole = Get-DbaServerRole @getRoleSplat
if ($null -eq $existingRole) {
    $module.FailJson("Server role [$serverRole] does not exist.")
}

# Get role member
$existingRoleMember = Get-DbaServerRoleMember @getRoleMemberSplat

if ($state -eq "absent") {
    if ($null -ne $existingRoleMember) {
        try {
            $removeRoleMemberSplat = @{
                SqlInstance = $sqlInstance
                SqlCredential = $sqlCredential
                Login = $login
                ServerRole = $serverRole
                EnableException = $true
                WhatIf = $checkMode
                Confirm = $false
            }
            $output = Remove-DbaServerRoleMember @removeRoleMemberSplat
            $module.Result.changed = $true
        }
        catch {
            $module.FailJson("Removing login [$login] from server role [$serverRole] failed: $($_.Exception.Message)", $_)
        }
    }
}
elseif ($state -eq "present") {
    # Add user to role
    if ($null -eq $existingRoleMember) {
        try {
            $addRoleMemberSplat = @{
                SqlInstance = $sqlInstance
                SqlCredential = $sqlCredential
                Login = $login
                ServerRole = $serverRole
                EnableException = $true
                WhatIf = $checkMode
                Confirm = $false
            }
            $output = Add-DbaServerRoleMember @addRoleMemberSplat
            $module.Result.changed = $true
        }
        catch {
            $module.FailJson("Adding login [$login] to server role [$serverRole] failed: $($_.Exception.Message)", $_)
        }
    }
}
try {
    if ($null -ne $output) {
        $resultData = ConvertTo-SerializableObject -InputObject $output
        $module.Result.data = $resultData
    }
    $module.ExitJson()
}
catch {
    $module.FailJson("Failure: $($_.Exception.Message)", $_)
}
