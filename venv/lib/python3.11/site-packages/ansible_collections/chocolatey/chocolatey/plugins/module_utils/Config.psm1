#Requires -Module Ansible.ModuleUtils.ArgvParser
#Requires -Module Ansible.ModuleUtils.CommandUtil

#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Common

function Get-ChocolateyConfig {
    <#
        .SYNOPSIS
        Outputs a hashtable containing the Chocolatey configuration information.

        .DESCRIPTION
        Inspects the `chocolatey.config` file from the current Chocolatey installation
        and creates a hashtable containing all the configuration values.
    #>
    [CmdletBinding()]
    param(
        # A CommandInfo object containing the path to choco.exe.
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.CommandInfo]
        $ChocoCommand
    )

    # `choco config list -r` does not display easily parsable config entries.
    # It contains config/sources/feature in the same output, and is in the
    # structure `configKey = configValue | description`.
    # If the key or value contains a `=` or `|`, it will make it quite hard to
    # parse it, compared to reading a well-formed XML file with the same values.
    $chocoInstall = Split-Path -LiteralPath (Split-Path -LiteralPath $ChocoCommand.Path)
    $configPath = "$chocoInstall\config\chocolatey.config"

    if (-not (Test-Path -LiteralPath $configPath)) {
        $message = "Could not find Chocolatey config file at expected path '$configPath'"
        Assert-TaskFailed -Message $message
    }

    try {
        [xml]$configXml = Get-Content -LiteralPath $configPath
    }
    catch {
        $message = "Failed to parse Chocolatey config file at '$configPath': $($_.Exception.Message)"
        Assert-TaskFailed -Message $message -Exception $_
    }

    $config = @{}

    foreach ($node in $configXml.chocolatey.config.GetEnumerator()) {
        # try to parse as a bool, then an int, fallback to string
        $value = try {
            [System.Boolean]::Parse($node.value)
        }
        catch {
            try {
                [System.Int32]::Parse($node.value)
            }
            catch {
                $node.value
            }
        }

        $config[$node.key] = $value
    }

    $config
}

function Remove-ChocolateyConfig {
    <#
        .SYNOPSIS
        Unsets the given Chocolatey configuration entry, reverting it to the default value.
    #>
    [CmdletBinding()]
    param(
        # A CommandInfo object containing the path to choco.exe.
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.CommandInfo]
        $ChocoCommand,

        # The name of the configuration entry to unset.
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )

    $command = Argv-ToString -Arguments @(
        $ChocoCommand.Path
        "config", "unset"
        "--name", $Name
    )
    $result = Run-Command -Command $command

    if ($result.rc -ne 0) {
        $message = "Failed to unset Chocolatey config for '$Name': $($result.stderr)"
        Assert-TaskFailed -Message $message -CommandResult $result
    }
}

function Set-ChocolateyConfig {
    <#
        .SYNOPSIS
        Sets the given Chocolatey configuration entry to the requested value.
    #>
    [CmdletBinding()]
    param(
        # A CommandInfo object containing the path to choco.exe.
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.CommandInfo]
        $ChocoCommand,

        # The name of the configuration entry to set.
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        # The value to set the configuration entry to.
        [Parameter(Mandatory = $true)]
        [string]
        $Value
    )

    $command = Argv-ToString -Arguments @(
        $ChocoCommand.Path
        "config", "set"
        "--name", $Name
        "--value", $Value
    )
    $result = Run-Command -Command $command

    if ($result.rc -ne 0) {
        $message = "Failed to set Chocolatey config for '$Name' to '$Value': $($result.stderr)"
        Assert-TaskFailed -Message $message -CommandResult $result
    }
}

Export-ModuleMember -Function Get-ChocolateyConfig, Set-ChocolateyConfig, Remove-ChocolateyConfig
