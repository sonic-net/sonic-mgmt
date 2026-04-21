#!powershell

# Copyright: (c) 2018, Ansible Project
# Copyright: (c) 2018, Simon Baerlocher <s.baerlocher@sbaerlocher.ch>
# Copyright: (c) 2018, ITIGO AG <opensource@itigo.ch>
# Copyright: (c) 2020, Chocolatey Software
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

#Requires -Module Ansible.ModuleUtils.ArgvParser
#Requires -Module Ansible.ModuleUtils.CommandUtil

#AnsibleRequires -CSharpUtil Ansible.Basic

#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Common
#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Config
#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Sources
#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Features
#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Packages

[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseConsistentWhitespace',
    '',
    Justification = 'Relax whitespace rule for better readability in module spec',
    Scope = 'function',
    # Apply suppression specifically to module spec
    Target = 'Get-ModuleSpec')]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

# Documentation: https://docs.ansible.com/ansible/2.10/dev_guide/developing_modules_general_windows.html#windows-new-module-development
function Get-ModuleSpec {
    @{
        options             = @{
            filter = @{
                type = "list"
                elements = "str"
                choices = "all", "config", "feature", "outdated", "packages", "sources"
                default = "all"
                aliases = "gather_subset"
            }
        }
        supports_check_mode = $true
    }
}

$spec = Get-ModuleSpec

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
Set-ActiveModule $module

$gather_filter = $module.Params.filter

$chocoCommand = Get-ChocolateyCommand

$module.Result.ansible_facts = @{
    ansible_chocolatey = @{}
}

if ($gather_filter -contains "all" -or $gather_filter -contains "config") {
    $module.Result.ansible_facts.ansible_chocolatey.Add(
        "config", (Get-ChocolateyConfig -ChocoCommand $chocoCommand)
    )
}
if ($gather_filter -contains "all" -or $gather_filter -contains "feature") {
    $module.Result.ansible_facts.ansible_chocolatey.Add(
        "feature", (Get-ChocolateyFeature -ChocoCommand $chocoCommand)
    )
}
if ($gather_filter -contains "all" -or $gather_filter -contains "sources") {
    $module.Result.ansible_facts.ansible_chocolatey.Add(
        "sources", @(Get-ChocolateySource -ChocoCommand $chocoCommand)
    )
}
if ($gather_filter -contains "all" -or $gather_filter -contains "packages") {
    $module.Result.ansible_facts.ansible_chocolatey.Add(
        "packages", @(Get-ChocolateyPackage -ChocoCommand $chocoCommand)
    )
}
if ($gather_filter -contains "all" -or $gather_filter -contains "outdated") {
    $module.Result.ansible_facts.ansible_chocolatey.Add(
        "outdated", @(Get-ChocolateyOutdated -ChocoCommand $chocoCommand)
    )
}

$module.Result.ansible_facts.ansible_chocolatey.Add(
    "filter", @($gather_filter)
)

# Return result
$module.ExitJson()
