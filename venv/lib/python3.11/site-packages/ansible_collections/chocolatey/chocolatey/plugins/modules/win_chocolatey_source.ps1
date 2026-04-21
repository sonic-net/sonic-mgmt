#!powershell

# Copyright: (c) 2018, Ansible Project
# Copyright: (c) 2020, Chocolatey Software
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

#Requires -Module Ansible.ModuleUtils.ArgvParser
#Requires -Module Ansible.ModuleUtils.CommandUtil

#AnsibleRequires -CSharpUtil Ansible.Basic

#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Common
#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Sources

[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseConsistentWhitespace',
    '',
    Justification = 'Relax whitespace rule for better readability in module spec',
    Scope = 'function',
    # Apply suppression specifically to module spec
    Target = 'Get-ModuleSpec')]
param()

# Documentation: https://docs.ansible.com/ansible/2.10/dev_guide/developing_modules_general_windows.html#windows-new-module-development
function Get-ModuleSpec {
    @{
        options             = @{
            name                 = @{ type = "str"; required = $true }
            state                = @{ type = "str"; default = "present"; choices = "absent", "disabled", "present" }

            admin_only           = @{ type = "bool" }
            allow_self_service   = @{ type = "bool" }
            bypass_proxy         = @{ type = "bool" }
            certificate          = @{ type = "str" }
            certificate_password = @{ type = "str"; no_log = $true }
            priority             = @{ type = "int" }
            source               = @{ type = "str" }
            source_username      = @{ type = "str" }
            source_password      = @{ type = "str"; no_log = $true }
            update_password      = @{ type = "str"; default = "always"; choices = "always", "on_create" }
        }
        supports_check_mode = $true
        required_together   = @(
            # Explicit `,` prefix required to prevent the array unrolling, Ansible requires nested arrays here.
            , @( 'source_username', 'source_password' )
        )
        required_by         = @{
            'certificate_password' = 'certificate'
        }
    }
}

$spec = Get-ModuleSpec

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
Set-ActiveModule $module

$name = $module.Params.name
$state = $module.Params.state

$admin_only = $module.Params.admin_only
$allow_self_service = $module.Params.allow_self_service
$bypass_proxy = $module.Params.bypass_proxy
$certificate = $module.Params.certificate
$certificate_password = $module.Params.certificate_password
$priority = $module.Params.priority
$source = $module.Params.source
$source_username = $module.Params.source_username
$source_password = $module.Params.source_password
$update_password = $module.Params.update_password

if ($module.DiffMode) {
    $module.Diff.before = @{}
    $module.Diff.after = @{}
}

$chocoCommand = Get-ChocolateyCommand

$targetSource = Get-ChocolateySource -ChocoCommand $chocoCommand | Where-Object { $_.name -eq $name }

if ($module.DiffMode) {
    if ($null -ne $targetSource) {
        $before = $targetSource.Clone()
    }
    else {
        $before = @{}
    }

    $module.Diff.before = $before
}

if ($state -eq "absent" -and $null -ne $targetSource) {
    Remove-ChocolateySource -ChocoCommand $chocoCommand -Name $name
    Set-TaskResultChanged
}
elseif ($state -in ("disabled", "present")) {
    $change = $false

    if ($null -eq $targetSource) {
        if ($null -eq $source) {
            $message = "The source option must be set when creating a new source"
            Assert-TaskFailed -Message $message
        }

        $change = $true
    }
    else {
        $change = ($null -ne $source -and $source -ne $targetSource.source) -or
            ($null -ne $source_username -and $source_username -ne $targetSource.source_username) -or
            ($null -ne $source_password -and $update_password -eq "always") -or
            ($null -ne $certificate -and $certificate -ne $targetSource.certificate) -or
            ($null -ne $certificate_password -and $update_password -eq "always") -or
            ($null -ne $priority -and $priority -ne $targetSource.priority) -or
            ($null -ne $bypass_proxy -and $bypass_proxy -ne $targetSource.bypass_proxy) -or
            ($null -ne $allow_self_service -and $allow_self_service -ne $targetSource.allow_self_service) -or
            ($null -ne $admin_only -and $admin_only -ne $targetSource.admin_only)

        if ($change) {
            Remove-ChocolateySource -ChocoCommand $chocoCommand -Name $Name
            Set-TaskResultChanged
        }
    }

    if ($change) {
        $sourceParams = @{
            ChocoCommand = $chocoCommand
            Name = $name
            Source = $source
            BypassProxy = $bypass_proxy
            AllowSelfService = $allow_self_service
            AdminOnly = $admin_only
        }

        if ($null -ne $priority) {
            $sourceParams.Priority = $priority
        }

        if ($null -ne $source_username) {
            $sourceParams.Username = $source_username
            $sourceParams.Password = $source_password
        }

        if ($null -ne $certificate) {
            $sourceParams.Certificate = $certificate

            if ($null -ne $certificate_password) {
                $sourceParams.CertificatePassword = $certificate_password
            }
        }

        $targetSource = New-ChocolateySource @sourceParams
        Set-TaskResultChanged
    }

    # enable/disable the source if necessary
    $action = if ($state -ne "disabled" -and $targetSource.disabled) {
        "enable"
    }
    elseif ($state -eq "disabled" -and (-not $targetSource.disabled)) {
        "disable"
    }
    else {
        $null
    }

    if ($null -ne $action) {
        $arguments = @(
            $chocoCommand.Path
            "source", $action
            "--name", $name

            if ($module.CheckMode) {
                "--what-if"
            }
        )

        $command = Argv-ToString -Arguments $arguments
        $result = Run-Command -Command $command

        if ($result.rc -ne 0) {
            $message = "Failed to $action Chocolatey source '$name': $($result.stderr)"
            Assert-TaskFailed -Message $message -CommandResult $result
        }

        $targetSource.disabled = ($action -eq "disable")
        Set-TaskResultChanged
    }

    if ($module.DiffMode) {
        $module.Diff.after = $targetSource
    }
}

# finally remove the diff if there was no change
if ($module.DiffMode -and -not $module.Result.changed) {
    $module.Diff.before = @{}
    $module.Diff.after = @{}
}

$module.ExitJson()
