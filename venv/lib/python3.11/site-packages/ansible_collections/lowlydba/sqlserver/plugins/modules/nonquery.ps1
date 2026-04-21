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
        database = @{type = 'str'; required = $true }
        nonquery = @{type = 'str'; required = $true }
        query_timeout = @{type = 'int'; required = $false; default = 60 }
    }
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$database = $module.Params.database
$nonquery = $module.Params.nonquery
$queryTimeout = $module.Params.query_timeout
$checkMode = $module.CheckMode

$module.Result.changed = $false

try {
    $invokeQuerySplat = @{
        SqlInstance = $sqlInstance
        SqlCredential = $sqlCredential
        Database = $database
        Query = $nonquery
        QueryTimeout = $queryTimeout
        EnableException = $true
    }
    if ($checkMode) {
        $invokeQuerySplat.Add("NoExec", $true)
    }
    $null = Invoke-DbaQuery @invokeQuerySplat

    $module.Result.changed = $true
    $module.ExitJson()
}
catch {
    $module.FailJson("Executing nonquery failed.", $_)
}
