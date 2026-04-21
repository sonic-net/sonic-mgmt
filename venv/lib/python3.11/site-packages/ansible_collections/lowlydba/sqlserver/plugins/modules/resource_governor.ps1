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
        enabled = @{type = 'bool'; required = $false; default = $true }
        classifier_function = @{type = 'str'; required = $false }
    }
}

# Get Csharp utility module
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))

$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$enabled = $module.Params.enabled
$classifierFunction = $module.Params.classifier_function
$checkMode = $module.CheckMode
$module.Result.changed = $false
$PSDefaultParameterValues = @{ "*:EnableException" = $true; "*:Confirm" = $false; "*:WhatIf" = $checkMode }

try {
    $rg = Get-DbaResourceGovernor -SqlInstance $sqlInstance -SqlCredential $sqlCredential
    $rgClassifierFunction = $rg.ClassifierFunction

    if ($rg.Enabled -ne $enabled) {
        $change = $true
    }
    if ($classifierFunction -ne "NULL" -and $rgClassifierFunction -ne $classifierFunction) {
        $change = $true
    }
    if ($classifierFunction -eq "NULL" -and $null -ne $rgClassifierFunction) {
        $change = $true
    }

    if ($change) {
        $rgSplat = @{
            SqlInstance = $sqlInstance
            SqlCredential = $sqlCredential
            ClassifierFunction = $classifierFunction
        }
        if ($enabled) {
            $rgSplat.Add("Enabled", $true)
        }
        else {
            $rgSplat.Add("Disabled", $true)
        }
        $output = Set-DbaResourceGovernor @rgSplat
        $module.Result.changed = $true
    }

    if ($null -ne $output) {
        $resultData = ConvertTo-SerializableObject -InputObject $output
        $module.Result.data = $resultData
    }
    $module.ExitJson()
}
catch {
    $module.FailJson("Setting resource governor failed.", $_)
}
