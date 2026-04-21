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
        branch = @{type = 'str'; required = $false; choices = @('main', 'dev') }
        local_file = @{type = 'str'; required = $false }
        only_script = @{type = 'str'; required = $false; default = 'Install-All-Scripts.sql'; choices = @('Install-All-Scripts.sql'
                'Install-Core-Blitz-No-Query-Store.sql'
                'Install-Core-Blitz-With-Query-Store.sql'
                'sp_Blitz.sql'
                'sp_BlitzFirst.sql'
                'sp_BlitzIndex.sql'
                'sp_BlitzCache.sql'
                'sp_BlitzWho.sql'
                'sp_BlitzQueryStore.sql'
                'sp_BlitzAnalysis.sql'
                'sp_BlitzBackups.sql'
                'sp_BlitzInMemoryOLTP.sql'
                'sp_BlitzLock.sql'
                'sp_AllNightLog.sql'
                'sp_AllNightLog_Setup.sql'
                'sp_DatabaseRestore.sql'
                'sp_ineachdb.sql'
                'SqlServerVersions.sql'
                'Uninstall.sql')
        }
        database = @{type = 'str'; required = $true }
        force = @{type = 'bool'; required = $false; default = $false }
    }
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$database = $module.Params.database
$branch = $module.Params.branch
$onlyScript = $module.Params.only_script
$localFile = $module.Params.local_file
$force = $module.Params.force
$checkMode = $module.Checkmode
$PSDefaultParameterValues = @{ "*:EnableException" = $true; "*:Confirm" = $false; "*:WhatIf" = $checkMode }

$firstResponderKitSplat = @{
    SqlInstance = $sqlInstance
    SqlCredential = $sqlCredential
    Database = $database
    Force = $force
}
if ($localFile) {
    $firstResponderKitSplat.Add("LocalFile", $localFile)
}
if ($branch) {
    $firstResponderKitSplat.Add("Branch", $branch)
}
if ($onlyScript) {
    $firstResponderKitSplat.Add("OnlyScript", $onlyScript)
}

try {
    $output = Install-DbaFirstResponderKit @firstResponderKitSplat
    $module.Result.changed = $true

    if ($null -ne $output) {
        $resultData = ConvertTo-SerializableObject -InputObject $output
        $module.Result.data = $resultData
    }
    $module.ExitJson()
}
catch {
    $module.FailJson("Installing First Responder Kit failed: $($_.Exception.Message)", $_)
}
