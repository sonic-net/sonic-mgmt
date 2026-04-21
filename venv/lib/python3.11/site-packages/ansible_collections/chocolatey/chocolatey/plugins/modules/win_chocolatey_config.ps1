#!powershell

# Copyright: (c) 2018, Ansible Project
# Copyright: (c) 2020, Chocolatey Software
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

#Requires -Module Ansible.ModuleUtils.ArgvParser
#Requires -Module Ansible.ModuleUtils.CommandUtil

#AnsibleRequires -CSharpUtil Ansible.Basic

#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Common
#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Config

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
            state = @{ type = "str"; default = "present"; choices = "absent", "present" }
            value = @{ type = "str" }
        }
        required_if         = @(
            # Explicit prefix `,` required, Ansible wants a list of lists for `required_if`
            # Read as:
            # ,@( [if] property, [is] value, [require] other_properties, $true_if_only_one_other_is_required ) -- last option is not mandatory
            , @( 'state', 'present', @( 'value' ) )
        )
        supports_check_mode = $true
    }
}

$spec = Get-ModuleSpec

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
Set-ActiveModule $module

$name = $module.Params.name
$state = $module.Params.state
$value = $module.Params.value

if ($module.DiffMode) {
    $module.Diff.before = $null
    $module.Diff.after = $null
}

if ($state -eq "present") {
    if ([string]::IsNullOrEmpty($value)) {
        $message = "Cannot set Chocolatey config as an empty string when state=present, use state=absent instead"
        Assert-TaskFailed -Message $message
    }

    # make sure bool values are lower case
    if ($value -ceq "True" -or $value -ceq "False") {
        $value = $value.ToLower()
    }
}

$chocoCommand = Get-ChocolateyCommand
$config = Get-ChocolateyConfig -ChocoCommand $chocoCommand

if ($name -notin $config.Keys) {
    $message = "The Chocolatey config '{0}' is not an existing config value, check the spelling. Valid config names: {1}" -f @(
        $name
        $config.Keys -join ', '
    )

    Assert-TaskFailed -Message $message
}

if ($module.DiffMode) {
    $module.Diff.before = $config.$name
}

if ($state -eq "absent" -and -not [string]::IsNullOrEmpty($config.$name)) {
    if (-not $module.CheckMode) {
        Remove-ChocolateyConfig -ChocoCommand $chocoCommand -Name $name
    }

    Set-TaskResultChanged
}
elseif ($state -eq "present" -and $value -ne $config.$name) {
    # choco.exe config set is not case sensitive, it won't make a change if the
    # value is the same but doesn't match, so we skip setting it as well in that
    # case.

    if (-not $module.CheckMode) {
        Set-ChocolateyConfig -ChocoCommand $chocoCommand -Name $name -Value $value
    }

    Set-TaskResultChanged
    if ($module.DiffMode) {
        $module.Diff.after = $value
    }
}

$module.ExitJson()
