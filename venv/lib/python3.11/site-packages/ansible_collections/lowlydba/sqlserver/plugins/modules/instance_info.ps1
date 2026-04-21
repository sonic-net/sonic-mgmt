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
    options = @{}
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$module.Result.changed = $false

# Fetch instance information
try {
    $getSplat = @{
        SqlInstance = $sqlInstance
        SqlCredential = $sqlCredential
        EnableException = $true
    }
    $output = Get-DbaConnection @getSplat | Select-Object -Property "ComputerName", "SqlInstance", "InstanceName" -First 1

    if ($null -ne $output) {
        # Add additional fields
        $extraProperties = @(
            "BuildNumber"
            "Language"
            "VersionMajor"
            "VersionMinor"
            "VersionString"
            "Collation"
            "ProductLevel"
            "IsClustered"
            "LoginMode"
        )
        foreach ($prop in $extraProperties) {
            $value = (Get-DbaInstanceProperty @getSplat -InstanceProperty $prop).Value
            $output | Add-Member -MemberType NoteProperty -Name $prop -Value $value
        }

        $resultData = ConvertTo-SerializableObject -InputObject $output
        $module.Result.data = $resultData
    }
    $module.ExitJson()
}
catch {
    $module.FailJson("Error fetching instance information: $($_.Exception.Message)", $_)
}
