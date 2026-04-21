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
        username = @{type = 'str'; required = $false }
        password = @{type = 'str'; required = $false; no_log = $true }
        port = @{type = 'int'; required = $true }
        ip_address = @{type = 'str'; required = $false }
        force = @{type = 'bool'; required = $false; default = $false }
    }
    required_together = @(
        , @('username', 'password')
    )
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
if ($null -ne $module.Params.username) {
    [securestring]$secPassword = ConvertTo-SecureString $Module.Params.password -AsPlainText -Force
    [pscredential]$credential = New-Object System.Management.Automation.PSCredential ($Module.Params.username, $secPassword)
}
$port = $module.Params.port
$ipAddress = $module.Params.ip_address
$checkMode = $module.CheckMode
$force = $module.Params.force
$module.Result.changed = $false
$PSDefaultParameterValues = @{ "*:EnableException" = $true; "*:Confirm" = $false; "*:WhatIf" = $checkMode }

try {
    $tcpPortSplat = @{
        SqlInstance = $SqlInstance
        Credential = $credential
        Port = $port
        Force = $force
    }
    if ($ipAddress) {
        $tcpPortSplat.Add("IPAddress", $ipAddress)
    }
    $output = Set-DbaTcpPort @tcpPortSplat

    if ($output.Changes.Count -gt 0 -or $checkMode) {
        $module.Result.changed = $true
        if ($force -ne $true) {
            $output | Add-Member -MemberType NoteProperty -Name "RestartRequired" -Value $true
        }
    }

    if ($null -ne $output) {
        $resultData = ConvertTo-SerializableObject -InputObject $output
        $module.Result.data = $resultData
    }
    $module.ExitJson()
}
catch {
    $module.FailJson("Configuring TCP port failed: $($_.Exception.Message)", $_)
}
