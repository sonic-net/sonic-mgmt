#Requires -Module Ansible.ModuleUtils.ArgvParser
#Requires -Module Ansible.ModuleUtils.CommandUtil

#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Common

function Get-ChocolateyFeature {
    <#
        .SYNOPSIS
        Retrieves a hashtable containing the feature states of all Chocolatey features.

        .DESCRIPTION
        Outputs a hashtable where the keys correspond to configuration names, and the
        values are set to `$true` if the feature is enabled, and `$false` otherwise.
    #>
    [CmdletBinding()]
    param(
        # A CommandInfo object containing the path to choco.exe.
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.CommandInfo]
        $ChocoCommand
    )

    $arguments = @(
        $ChocoCommand.Path
        "feature", "list"
        "-r"
    )

    $command = Argv-ToString -Arguments $arguments
    $result = Run-Command -Command $command

    if ($result.rc -ne 0) {
        $message = "Failed to list Chocolatey features: $($result.stderr)"
        Assert-TaskFailed -Message $message -CommandResult $result
    }

    # Build a hashtable of features where each feature name has a value of
    # either `$true` (enabled), or `$false` (disabled)
    $features = @{}
    $result |
        ConvertFrom-Stdout |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object {
            $name, $state, $null = $_ -split "\|"
            $features.$name = $state -eq "Enabled"
        }

    $features
}

function Set-ChocolateyFeature {
    <#
        .SYNOPSIS
        Sets the target Chocolatey feature to the desired state.

        .DESCRIPTION
        If the `-Enabled` switch is not provided, disables the target Chocolatey feature.
        Otherwise, enables the target Chocolatey feature.
    #>
    [CmdletBinding()]
    param(
        # A CommandInfo object containing the path to choco.exe.
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.CommandInfo]
        $ChocoCommand,

        # The name of the target Chocolatey feature.
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        # If set, enables the targeted feature.
        [Parameter()]
        [switch]
        $Enabled
    )

    $stateCommand = if ($Enabled) { "enable" } else { "disable" }
    $arguments = @(
        $ChocoCommand.Path
        "feature", $stateCommand
        "--name", $Name
    )

    $command = Argv-ToString -Arguments $arguments
    $result = Run-Command -Command $command

    if ($result.rc -ne 0) {
        $message = "Failed to set Chocolatey feature $Name to $($stateCommand): $($result.stderr)"
        Assert-TaskFailed -Message $message -CommandResult $result
    }
}

Export-ModuleMember -Function Get-ChocolateyFeature, Set-ChocolateyFeature
