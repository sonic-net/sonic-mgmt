#Requires -Module Ansible.ModuleUtils.ArgvParser
#Requires -Module Ansible.ModuleUtils.CommandUtil

#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Common

function Get-ChocolateySource {
    <#
        .SYNOPSIS
        Gets a list of all Chocolatey sources.

        .DESCRIPTION
        Outputs a list of hashtables, each containing the properties of a configured
        Chocolatey source.
    #>
    [CmdletBinding()]
    param(
        # A CommandInfo object containing the path to choco.exe.
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.CommandInfo]
        $ChocoCommand
    )

    $configFolder = Split-Path -LiteralPath (Split-Path -LiteralPath $ChocoCommand.Path)
    $configPath = "$configFolder\config\chocolatey.config"

    if (-not (Test-Path -LiteralPath $configPath)) {
        $message = "Expecting Chocolatey config file to exist at '$configPath'"
        Assert-TaskFailed -Message $message
    }

    # would prefer to enumerate the existing sources with an actual API but the
    # only stable interface is choco.exe source list and that does not output
    # the sources in an easily parsable list. Using -r will split each entry by
    # | like a psv but does not quote values that have a | already in it making
    # it inadequete for our tasks. Instead we will parse the chocolatey.config
    # file and get the values from there
    try {
        [xml]$configXml = Get-Content -LiteralPath $configPath
    }
    catch {
        $message = "Failed to parse Chocolatey config file at '$configPath': $($_.Exception.Message)"
        Assert-TaskFailed -Message $message -Exception $_
    }

    foreach ($sourceNode in $configXml.chocolatey.sources.GetEnumerator()) {
        $sourceInfo = @{
            name = $sourceNode.id
            source = $sourceNode.value
            disabled = [System.Convert]::ToBoolean($sourceNode.disabled)
        }

        $attributeList = @(
            @{ attribute = 'user'; type = [string]; name = 'source_username' }
            @{ attribute = 'priority'; type = [int] }
            @{ attribute = 'certificate'; type = [string] }
            @{ attribute = 'bypassProxy'; type = [bool]; name = 'bypass_proxy' }
            @{ attribute = 'selfService'; type = [bool]; name = 'allow_self_service' }
            @{ attribute = 'adminOnly'; type = [bool]; name = 'admin_only' }
        )

        foreach ($item in $attributeList) {
            $attr = $sourceNode.Attributes.GetNamedItem($item.attribute)
            $property = if ($item.ContainsKey('name')) { $item.name } else { $item.attribute }

            $sourceInfo.$property = if ($null -ne $attr) {
                if ($item.type -eq [bool]) {
                    [bool]::Parse($attr.Value)
                }
                elseif ($item.type -eq [int]) {
                    [int]::Parse($attr.Value)
                }
                else {
                    $attr.Value
                }
            }
            else {
                $null
            }
        }

        $sourceInfo
    }
}

function New-ChocolateySource {
    <#
        .SYNOPSIS
        Adds a new Chocolatey source configuration.

        .DESCRIPTION
        Inserts a new Chocolatey source configuration with the requested
        parameters set for the source.
    #>
    [CmdletBinding()]
    param(
        # A CommandInfo object containing the path to choco.exe.
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.CommandInfo]
        $ChocoCommand,

        # The "friendly" name of the source.
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        # The URL to the source repository.
        [Parameter(Mandatory = $true)]
        [string]
        $Source,

        # The username required to authenticate to the source, if any.
        [Parameter()]
        [string]
        $Username,

        # The password required to authenticate to the source, if any.
        [Parameter()]
        [string]
        $Password,

        # The certificate required to authenticate to the source, if any.
        [Parameter()]
        [string]
        $Certificate,

        # The password for the certificate required to authenticate to the source, if applicable.
        [Parameter()]
        [string]
        $CertificatePassword,

        # The priority level of the source.
        [Parameter()]
        [int]
        $Priority,

        # Set to bypass the proxy configuration when retrieving packages from this source.
        [Parameter()]
        [switch]
        $BypassProxy,

        # Set to allow non-admin users to use the source when self-service is enabled.
        [Parameter()]
        [switch]
        $AllowSelfService,

        # Set to restrict usage of the source to administrator users only.
        [Parameter()]
        [switch]
        $AdminOnly,

        # The Ansible module object to check for verbosity levels and check mode.
        # Defaults to the currently active module.
        [Parameter()]
        [Ansible.Basic.AnsibleModule]
        $Module = (Get-AnsibleModule)
    )

    $arguments = @(
        # Add the base arguments
        $ChocoCommand.Path
        "source", "add"
        "--name", $Name
        "--source", $Source

        # Add optional arguments from user input
        if ($PSBoundParameters.ContainsKey('Username')) {
            "--user", $Username
            "--password", $Password
        }

        if ($PSBoundParameters.ContainsKey('Certificate')) {
            "--cert", $Certificate

            if ($PSBoundParameters.ContainsKey('CertificatePassword')) {
                "--certpassword", $CertificatePassword
            }
        }

        if ($PSBoundParameters.ContainsKey('Priority')) {
            "--priority", $Priority
        }
        else {
            $Priority = 0
        }

        if ($BypassProxy) {
            "--bypass-proxy"
        }

        if ($AllowSelfService) {
            "--allow-self-service"
        }

        if ($AdminOnly) {
            "--admin-only"
        }

        if ($Module.CheckMode) {
            "--what-if"
        }
    )


    $command = Argv-ToString -Arguments $arguments
    $result = Run-Command -Command $command

    if ($result.rc -ne 0) {
        $message = "Failed to add Chocolatey source '$Name': $($result.stderr)"
        Assert-TaskFailed -Message $message -CommandResult $result
    }

    @{
        name = $Name
        source = $Source
        disabled = $false
        source_username = $Username
        priority = $Priority
        certificate = $Certificate
        bypass_proxy = $BypassProxy.IsPresent
        allow_self_service = $AllowSelfService.IsPresent
        admin_only = $AdminOnly.IsPresent
    }
}

function Remove-ChocolateySource {
    <#
        .SYNOPSIS
        Removes the target Chocolatey source configuration.
    #>
    [CmdletBinding()]
    param(
        # A CommandInfo object containing the path to choco.exe.
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.CommandInfo]
        $ChocoCommand,

        # The "friendly" name of the source to remove.
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        # The Ansible module object to check for verbosity levels and check mode.
        # Defaults to the currently active module.
        [Parameter()]
        [Ansible.Basic.AnsibleModule]
        $Module = (Get-AnsibleModule)
    )

    $arguments = @(
        $ChocoCommand.Path
        "source", "remove"
        "--name", $Name

        if ($Module.CheckMode) {
            "--what-if"
        }
    )
    $command = Argv-ToString -Arguments $arguments
    $result = Run-Command -Command $command

    if ($result.rc -ne 0) {
        $message = "Failed to remove Chocolatey source '$Name': $($result.stderr)"
        Assert-TaskFailed -Message $message -CommandResult $result
    }
}

Export-ModuleMember -Function @(
    'Get-ChocolateySource'
    'New-ChocolateySource'
    'Remove-ChocolateySource'
)
