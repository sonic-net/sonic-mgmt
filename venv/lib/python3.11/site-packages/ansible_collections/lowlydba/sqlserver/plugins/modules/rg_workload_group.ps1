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
        workload_group = @{type = 'str'; required = $true; }
        resource_pool = @{type = 'str'; required = $true; }
        resource_pool_type = @{type = 'str'; required = $false; default = 'Internal'; choices = @('Internal', 'External') }
        group_max_requests = @{type = 'int'; required = $false; }
        importance = @{type = 'str'; required = $false; choices = @('Low', 'Medium', 'High') }
        max_dop = @{type = 'int'; required = $false; }
        request_max_cpu_time = @{type = 'int'; required = $false; }
        request_max_mem_grant_perc = @{type = 'int'; required = $false; }
        request_mem_grant_timeout_sec = @{type = 'int'; required = $false; }
        state = @{type = 'str'; required = $false; default = 'present'; choices = @('present', 'absent') }
    }
}

# Get Csharp utility module
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$options = @{
    SqlInstance = $sqlInstance
    SqlCredential = $sqlCredential
    WorkloadGroup = $module.Params.workload_group
    ResourcePool = $module.Params.resource_pool
    ResourcePoolType = $module.Params.resource_pool_type
    GroupMaximumRequests = $module.Params.group_max_requests
    Importance = $module.Params.importance
    MaximumDegreeOfParallelism = $module.Params.max_dop
    RequestMaximumCpuTimeInSeconds = $module.Params.request_max_cpu_time
    RequestMaximumMemoryGrantPercentage = $module.Params.request_max_mem_grant_perc
    RequestMemoryGrantTimeoutInSeconds = $module.Params.request_mem_grant_timeout_sec
}
$state = $module.Params.state
$module.Result.changed = $false
$checkMode = $module.CheckMode
[System.Collections.ArrayList]$compareProperty = @(
    'GroupMaximumRequests',
    'Importance',
    'MaximumDegreeOfParallelism',
    'RequestMaximumCpuTimeInSeconds',
    'RequestMemoryGrantTimeoutInSeconds',
    'RequestMaximumMemoryGrantPercentage'
)

# Remove unsupplied params - the dbatools functions handle default value checks
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
    $getResourcePoolSplat = @{
        SqlInstance = $options.SqlInstance
        SqlCredential = $options.SqlCredential
        Type = $options.ResourcePoolType
    }
    $existingResourcePool = Get-DbaRgResourcePool @getResourcePoolSplat | Where-Object Name -eq $options.ResourcePool
    if ($null -eq $existingResourcePool) {
        $module.FailJson("Failed to lookup parent resource pool '$($options.ResourcePool)'.", $_)
    }
    $existingWorkloadGroup = $existingResourcePool.WorkloadGroups | Where-Object Name -eq $options.WorkloadGroup

    if ($state -eq "absent") {
        if ($null -ne $existingResourcePool) {
            $output = $existingWorkloadGroup | Remove-DbaRgWorkloadGroup -WhatIf:$checkMode -EnableException
            $module.Result.changed = $true
        }
    }
    elseif ($state -eq "present") {
        if ($null -ne $existingWorkloadGroup) {
            # Check for value parity
            $diff = Compare-Object -ReferenceObject $existingWorkloadGroup -DifferenceObject $options -Property $compareProperty
            # Set to new values
            if ($null -ne $diff) {
                $output = Set-DbaRgWorkloadGroup @options -WhatIf:$checkMode -EnableException
                $module.Result.changed = $true
            }
        }
        else {
            # Create a new workload group
            $output = New-DbaRgWorkloadGroup @options -WhatIf:$checkMode -EnableException
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
    $module.FailJson("Failed to configure workload group: $($_.Exception.Message)", $_)
}
