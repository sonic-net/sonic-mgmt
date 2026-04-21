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
        ag_name = @{type = 'str'; required = $true }
        listener_name = @{type = 'str'; required = $true }
        ip_address = @{type = 'list'; elements = 'str'; required = $false }
        subnet_ip = @{type = 'list'; elements = 'str'; required = $false }
        subnet_mask = @{type = 'list'; elements = 'str'; required = $false; default = '255.255.255.0' }
        port = @{type = 'int'; required = $false; default = 1433 }
        dhcp = @{type = 'bool'; required = $false; default = $false }
        state = @{type = "str"; required = $false; default = "present"; choices = @("present", "absent") }
    }
}
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$agName = $module.Params.ag_name
$listenerName = $module.Params.listener_name
$subnetIp = $module.Params.subnet_ip
$subnetMask = $module.Params.subnet_mask
$ipAddress = $module.Params.ip_address
$port = $module.Params.port
$dhcp = $module.Params.dhcp
$state = $module.Params.state
$checkMode = $module.CheckMode
$module.Result.changed = $false
$PSDefaultParameterValues = @{
    "*:SqlInstance" = $sqlInstance
    "*:SqlCredential" = $sqlCredential
    "*:EnableException" = $true
    "*:Confirm" = $false
    "*:WhatIf" = $checkMode
}

try {
    $existingListener = Get-DbaAgListener -AvailabilityGroup $agName -Listener $listenerName
    if ($state -eq "present") {
        if ($null -eq $existingListener) {
            $listenerParams = @{
                AvailabilityGroup = $agName
                Name = $listenerName
                Port = $port
                Dhcp = $dhcp
                SubnetMask = $subnetMask
            }
            if ($null -ne $ipAddress) {
                $listenerParams.Add("IPAddress", $ipAddress)
            }
            if ($null -ne $subnetIp) {
                $listenerParams.Add("SubnetIP", $subnetIp)
            }
            $output = Add-DbaAgListener @listenerParams
            $module.Result.changed = $true
        }
        elseif ($existingListener.PortNumber -ne $port) {
            $output = Set-DbaAgListener -AvailabilityGroup $agName -Listener $listenerName -Port $port
            $module.Result.changed = $true
        }
    }
    elseif ($state -eq "absent") {
        if ($null -ne $existingListener) {
            $output = Remove-DbaAgListener -AvailabilityGroup $agName -Listener $listenerName
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
    $module.FailJson("Configuring availability group listener failed: $($_.Exception.Message)", $_)
}
