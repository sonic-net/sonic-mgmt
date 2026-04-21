#!powershell

# Copyright: (c), 2018 Ansible Project
# Copyright: (c) 2020, Chocolatey Software
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

#Requires -Module Ansible.ModuleUtils.ArgvParser
#Requires -Module Ansible.ModuleUtils.CommandUtil

#AnsibleRequires -CSharpUtil Ansible.Basic

#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Common
#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Features

[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseConsistentWhitespace',
    '',
    Justification = 'Relax whitespace rule for better readability in module spec',
    Scope = 'function',
    # Apply suppression specifically to module spec
    Target = 'Get-ModuleSpec')]
param()

$ErrorActionPreference = "Stop"

# Documentation: https://docs.ansible.com/ansible/2.10/dev_guide/developing_modules_general_windows.html#windows-new-module-development
function Get-ModuleSpec {
    @{
        options             = @{
            name  = @{ type = "str"; required = $true }
            state = @{ type = "str"; default = "enabled"; choices = "disabled", "enabled" }
        }
        supports_check_mode = $true
    }
}

$spec = Get-ModuleSpec

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
Set-ActiveModule $module

$name = $module.Params.name
$state = $module.Params.state

$chocoCommand = Get-ChocolateyCommand
$featureStates = Get-ChocolateyFeature -ChocoCommand $chocoCommand

if ($name -notin $featureStates.Keys) {
    $message = "Invalid feature name '$name' specified, valid features are: $($featureStates.Keys -join ', ')"
    Assert-TaskFailed -Message $message
}

$shouldBeEnabled = $state -eq "enabled"
$isEnabled = $featureStates.$name

if ($isEnabled -ne $shouldBeEnabled) {
    if (-not $module.CheckMode) {
        Set-ChocolateyFeature -ChocoCommand $chocoCommand -Name $name -Enabled:$shouldBeEnabled
    }

    Set-TaskResultChanged
}

$module.ExitJson()
