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
        username = @{type = 'str'; required = $true }
        role = @{type = 'str'; required = $true }
        state = @{type = 'str'; required = $false; default = 'present'; choices = @('present', 'absent') }
    }
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$username = $module.Params.username
$database = $module.Params.database
$role = $module.Params.role
$state = $module.Params.state
$checkMode = $module.CheckMode

$module.Result.changed = $false

$getUserSplat = @{
    SqlInstance = $sqlInstance
    SqlCredential = $sqlCredential
    Database = $database
    User = $username
    EnableException = $true
}
$getRoleSplat = @{
    SqlInstance = $sqlInstance
    SqlCredential = $sqlCredential
    Database = $database
    Role = $role
    EnableException = $true
}
$getRoleMemberSplat = @{
    SqlInstance = $sqlInstance
    SqlCredential = $sqlCredential
    Database = $database
    Role = $role
    IncludeSystemUser = $true
    EnableException = $true
}

# Verify user and role exist, DBATools currently fails silently
$existingUser = Get-DbaDbUser @getUserSplat
if ($null -eq $existingUser) {
    $module.FailJson("User [$username] does not exist in database [$database].")
}
$existingRole = Get-DbaDbRole @getRoleSplat
if ($null -eq $existingRole) {
    $module.FailJson("Role [$role] does not exist in database [$database].")
}

# Get role members
$existingRoleMembers = Get-DbaDbRoleMember @getRoleMemberSplat

if ($state -eq "absent") {
    if ($existingRoleMembers.username -contains $username) {
        try {
            $removeRoleMemberSplat = @{
                SqlInstance = $sqlInstance
                SqlCredential = $sqlCredential
                User = $username
                Database = $database
                Role = $role
                EnableException = $true
                WhatIf = $checkMode
                Confirm = $false
            }
            $output = Remove-DbaDbRoleMember @removeRoleMemberSplat
            $module.Result.changed = $true
        }
        catch {
            $module.FailJson("Removing user [$username] from database role [$role] failed: $($_.Exception.Message)", $_)
        }
    }
}
elseif ($state -eq "present") {
    # Add user to role
    if ($existingRoleMembers.username -notcontains $username) {
        try {
            $addRoleMemberSplat = @{
                SqlInstance = $sqlInstance
                SqlCredential = $sqlCredential
                User = $username
                Database = $database
                Role = $role
                EnableException = $true
                WhatIf = $checkMode
                Confirm = $false
            }
            $output = Add-DbaDbRoleMember @addRoleMemberSplat
            $module.Result.changed = $true
        }
        catch {
            $module.FailJson("Adding user [$username] to database role [$role] failed: $($_.Exception.Message)", $_)
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
