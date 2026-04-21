#!powershell
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# (c) 2021, Sudhir Koduri (@kodurisudhir)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ansible_collections.lowlydba.sqlserver.plugins.module_utils._SqlServerUtils
#Requires -Modules @{ ModuleName="dbatools"; ModuleVersion="2.0.0" }

$ErrorActionPreference = "Stop"

$spec = @{
    supports_check_mode = $true
    options = @{
        computer_username = @{ type = 'str'; required = $false }
        computer_password = @{ type = 'str'; required = $false; no_log = $true; }
        computer = @{ type = 'str'; required = $true }
        service_account = @{ type = 'str'; required = $true; }
        state = @{ type = 'str'; required = $false; default = 'present'; choices = @('present', 'absent') }
    }
    required_together = @(
        , @('computer_username', 'computer_password')
    )
}
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
if ($null -ne $module.Params.computer_username) {
    [securestring]$secPassword = ConvertTo-SecureString $Module.Params.computer_password -AsPlainText -Force
    [pscredential]$computerCredential = New-Object System.Management.Automation.PSCredential ($Module.Params.computer_username, $secPassword)
}
$computer = $module.Params.computer
$serviceAccount = $module.Params.service_account
$serviceClass = "MSSQLSvc"
$spn = "$serviceClass/$computer"
$state = $module.Params.state
$checkMode = $module.CheckMode
$module.Result.changed = $false
$PSDefaultParameterValues = @{ "*:EnableException" = $true; "*:Confirm" = $false; "*:WhatIf" = $checkMode }

try {
    $existingSPN = Get-DbaSpn -ComputerName $computer -Credential $computerCredential -AccountName $serviceAccount | Where-Object spn -eq $spn

    if ($state -eq "present") {
        if ($null -ne $existingSPN) {
            # SPNs can only be added and removed, not modified
            $module.ExitJson()
        }
        elseif ($null -eq $existingSPN) {
            $output = Set-DbaSpn -SPN $spn -ServiceAccount $serviceAccount -Credential $computerCredential
            $module.Result.changed = $true
        }
    }
    elseif ($state -eq "absent") {
        if ($null -ne $existingSPN) {
            $output = Remove-DbaSpn -SPN $spn -ServiceAccount $serviceAccount -Credential $computerCredential
            $module.Result.changed = $true
        }
    }

    if ($output) {
        $resultData = ConvertTo-SerializableObject -InputObject $output
        $module.Result.data = $resultData
    }
    $module.ExitJson()
}
catch {
    $module.FailJson("Configuring SPN failed: $($_.Exception.Message)", $_)
}
