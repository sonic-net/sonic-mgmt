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
        trace_flag = @{type = 'int'; required = $true }
        enabled = @{type = 'bool'; required = $true }
    }
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$traceFlag = $module.Params.trace_flag
$enabled = $module.Params.enabled
$checkMode = $module.CheckMode
$module.Result.changed = $false

try {
    $traceFlagSplat = @{
        SqlInstance = $SqlInstance
        SqlCredential = $sqlCredential
        TraceFlag = $traceFlag
        EnableException = $true
    }
    $existingFlag = Get-DbaTraceFlag @traceFlagSplat

    if ($enabled -eq $true) {
        if (-not $checkMode) {
            $enabled = Enable-DbaTraceFlag @traceFlagSplat
            $output = $enabled | Select-Object -Property InstanceName, SqlInstance, TraceFlag
        }
        if ($existingFlag.TraceFlag -notcontains $traceFlag) {
            $module.Result.changed = $true
        }
    }
    elseif ($enabled -eq $false) {

        if (-not $checkMode) {
            $disabled = Disable-DbaTraceFlag @traceFlagSplat
            $output = $disabled | Select-Object -Property InstanceName, SqlInstance, TraceFlag
        }
        if ($existingFlag.TraceFlag -contains $traceFlag) {
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
    $module.FailJson("Configuring trace flag failed: $($_.Exception.Message)", $_)
}
