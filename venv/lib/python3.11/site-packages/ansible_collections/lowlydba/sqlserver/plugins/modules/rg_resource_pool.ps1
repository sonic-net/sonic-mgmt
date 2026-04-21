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
        resource_pool = @{type = 'str'; required = $true }
        type = @{type = 'str'; required = $false; default = 'Internal'; choices = @('Internal', 'External') }
        max_cpu_perc = @{type = 'int'; required = $false; }
        min_cpu_perc = @{type = 'int'; required = $false; }
        cap_cpu_perc = @{type = 'int'; required = $false; }
        max_mem_perc = @{type = 'int'; required = $false; }
        min_mem_perc = @{type = 'int'; required = $false; }
        min_iops_per_vol = @{type = 'int'; required = $false; }
        max_iops_per_vol = @{type = 'int'; required = $false; }
        state = @{type = 'str'; required = $false; default = 'present'; choices = @('present', 'absent') }
    }
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$state = $module.Params.state
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$options = @{
    SqlInstance = $sqlInstance
    SqlCredential = $sqlCredential
    ResourcePool = $module.Params.resource_pool
    Type = $module.Params.type
    MaximumCpuPercentage = $module.Params.max_cpu_perc
    MinimumCpuPercentage = $module.Params.min_cpu_perc
    CapCpuPercentage = $module.Params.cap_cpu_perc
    MaximumMemoryPercentage = $module.params.max_mem_perc
    MinimumMemoryPercentage = $module.Params.min_mem_perc
    MinimumIOPSPerVolume = $module.params.min_iops_per_vol
    MaximumIOPSPerVolume = $module.params.max_iops_per_vol
}
$checkMode = $module.CheckMode
$module.Result.changed = $false

[System.Collections.ArrayList]$compareProperty = @(
    'MaximumCpuPercentage',
    'MinimumCpuPercentage',
    'CapCpuPercentage',
    'MinimumMemoryPercentage',
    'MaximumMemoryPercentage',
    'MinimumIOPSPerVolume',
    'MaximumIOPSPerVolume'
)

$optionsToRemove = @()
foreach ($item in $options.GetEnumerator() ) {
    if ($null -eq $item.Value) {
        $optionsToRemove += $item.Name
    }
}
foreach ($item in $optionsToRemove) {
    $options.Remove($item)
    $compareProperty.Remove($item)
}

try {
    $getPoolParams = @{
        SqlInstance = $options.SqlInstance
        SqlCredential = $options.SqlCredential
        Type = $options.Type
        EnableException = $true
    }
    $existingResourcePool = Get-DbaRgResourcePool @getPoolParams | Where-Object Name -eq $options.ResourcePool

    if ($state -eq "absent") {
        if ($null -ne $existingResourcePool) {
            $removePoolParams = @{
                SqlInstance = $options.SqlInstance
                SqlCredential = $options.SqlCredential
                Type = $options.Type
                ResourcePool = $options.ResourcePool
                WhatIf = $checkMode
                EnableException = $true
                Confirm = $false
            }
            $output = Remove-DbaRgResourcePool @removePoolParams
            $module.Result.changed = $true
        }
    }
    elseif ($state -eq "present") {
        $options.Add("WhatIf", $checkMode)
        if ($null -ne $existingResourcePool) {
            # Check for value parity
            $diff = Compare-Object -ReferenceObject $options -DifferenceObject $existingResourcePool -Property $compareProperty
            if ($null -ne $diff) {
                # Set to new values
                $output = Set-DbaRgResourcePool @options -EnableException
                $module.Result.changed = $true
            }
        }
        else {
            # Create a resource pool
            $output = New-DbaRgResourcePool @options -EnableException
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
    $module.FailJson("Configuring resource pool failed: $($_.Exception.Message)", $_)
}
