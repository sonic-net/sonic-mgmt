#Requires -Module Ansible.ModuleUtils.ArgvParser
#Requires -Module Ansible.ModuleUtils.CommandUtil

#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Common

# As of chocolatey 0.9.10, non-zero success exit codes can be returned
# See https://github.com/chocolatey/choco/issues/512#issuecomment-214284461
$script:SuccessExitCodes = (0, 1605, 1614, 1641, 3010)

$script:ChocolateyVersion = $null

function Get-ChocolateyOutdated {
    <#
        .SYNOPSIS
        Retrieves the list of Chocolatey packages, already present on the local system, for which an update is available.
    #>
    [CmdletBinding()]
    param(
        # A CommandInfo object containing the path to choco.exe.
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.CommandInfo]
        $ChocoCommand
    )

    $command = Argv-ToString -Arguments @(
        $ChocoCommand.Path
        "outdated"
        "--limit-output"
    )
    $result = Run-Command -Command $command

    # Chocolatey v0.10.12 introduced enhanced exit codes, 2 means no results, e.g. no package
    if ($result.rc -notin @(0, 2)) {
        $message = 'Error checking outdated status for installed chocolatey packages'
        Assert-TaskFailed -Message $message -Command $command -CommandResult $result
    }

    $result |
        ConvertFrom-Stdout |
        ForEach-Object {
            # Sanity check in case additional output is added in the future.
            if ($_.Contains('|')) {
                $package, $current_version, $available_version, $pinned, $null = $_.Split('|')

                @{
                    package = $package
                    current_version = $current_version
                    available_version = $available_version
                    pinned = [System.Boolean]::Parse($pinned)
                }
            }
        }
}

function Get-ChocolateyPackage {
    <#
        .SYNOPSIS
        Retrieves the list of Chocolatey packages already present on the local system.
    #>
    [CmdletBinding()]
    param(
        # A CommandInfo object containing the path to choco.exe.
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.CommandInfo]
        $ChocoCommand,

        # The version of packages to retrieve. Defaults to all package versions.
        [Parameter()]
        [string]
        $Version
    )

    $command = Argv-ToString -Arguments @(
        $ChocoCommand.Path
        "list"
        if ((Get-ChocolateyVersion -ChocoCommand $ChocoCommand) -lt [version]'2.0.0') {
            "--local-only"
        }
        "--limit-output"

        if ($Version) {
            '--version', $Version
        }
        else {
            '--all-versions'
        }
    )
    $result = Run-Command -Command $command

    # Chocolatey v0.10.12 introduced enhanced exit codes, 2 means no results, e.g. no package
    if ($result.rc -notin @(0, 2)) {
        $message = 'Error checking installation status for chocolatey packages'
        Assert-TaskFailed -Message $message -Command $command -CommandResult $result
    }

    $result |
        ConvertFrom-Stdout |
        ForEach-Object {
            # Sanity check in case additional output is added in the future.
            if ($_.Contains('|')) {
                $package, $version, $null = $_.Split('|')

                @{
                    package = $package
                    version = $version
                }
            }
        }
}

function Get-ChocolateyPackageVersion {
    <#
        .SYNOPSIS
        Gets entries of a specific Chocolatey package installed on the local system, if any.
    #>
    [CmdletBinding()]
    param(
        # A CommandInfo object containing the path to choco.exe.
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.CommandInfo]
        $ChocoCommand,

        # The name of the package to look for.
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]
        $Name,

        # The version of the package to look for.
        [Parameter()]
        [string]
        $Version
    )
    begin {
        $versionSplat = if ([string]::IsNullOrEmpty($Version)) { @{} } else { @{ Version = $Version } }

        # Due to https://github.com/chocolatey/choco/issues/1843, we get a list of all the installed packages and
        # filter it ourselves. This has the added benefit of being quicker when dealing with multiple packages as we
        # only call choco.exe once.
        $installedPackages = Get-ChocolateyPackage @versionSplat -ChocoCommand $ChocoCommand

        # Create a hashtable that will store our package version info.
        $results = @{}
    }
    process {
        if ($Name -eq 'all') {
            # All is a special package name that means all installed packages, we set a dummy version so absent, latest
            # and downgrade will run with all.
            $results.'all' = @('0.0.0')
        }
        else {
            $packageInfo = $installedPackages | Where-Object { $_.package -eq $Name }
            if ($null -eq $packageInfo) {
                $results.$Name = $null
            }
            else {
                $results.$Name = @($packageInfo.version)
            }
        }
    }
    end {
        $results
    }
}

function Get-ChocolateyVersion {
    <#
        .SYNOPSIS
        Gets the version of Chocolatey that is currently installed and being used to execute instructions.
    #>
    [CmdletBinding()]
    param(
        # A CommandInfo object containing the path to choco.exe.
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.CommandInfo]
        $ChocoCommand
    )

    # If we've already found the choco version, just return the known version.
    if ($script:ChocolateyVersion) {
        $script:ChocolateyVersion
        return
    }

    # Query choco.exe for the version and cache it in the module-scope variable.
    $command = Argv-ToString -Arguments @(
        $ChocoCommand.Path
        "--version"
    )
    $result = Run-Command -Command $command

    # Prerelease versions are not relevant for our purposes.
    # Stripping off any prerelease tag here gets us enough for what we need.
    # Also, if a license is installed, but the licensed extension is missing,
    # choco.exe output will contain an error which we need to ignore for the
    # purposes of determining the version of Chocolatey CLI.
    # We're using the suggested regex for matching SemVer strings:
    # https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string
    $SemVerRegex = '(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?'
    if ($result.stdout -match $SemVerRegex) {
        ($script:ChocolateyVersion = [version]($matches[0] -replace '-.+$'))
    }
    else {
        $message = "Error getting version of Chocolatey CLI"
        Assert-TaskFailed -Message $message -Command $command -CommandResult $result
    }
}

function Get-CommonChocolateyArgument {
    <#
        .SYNOPSIS
        Retrieves a set of common Chocolatey arguments.

        .DESCRIPTION
        Retrieves the default set of Chocolatey arguments, constructed to function
        best in headless environments (disable progress, auto-confirm) as well as
        setting the verbosity levels of output to match the provided Ansible module.
    #>
    [CmdletBinding()]
    param(
        # The Ansible module object to check for verbosity levels and check mode.
        # Defaults to the currently active module.
        [Parameter()]
        [Ansible.Basic.AnsibleModule]
        $Module = (Get-AnsibleModule)
    )

    # uses global vars like check_mode and verbosity to control the common args
    # run with Chocolatey
    "--yes"
    "--no-progress"

    # global vars that control the arguments
    if ($Module.CheckMode) {
        "--what-if"
    }

    if ($Module.Verbosity -ge 4) {
        if ($Module.Verbosity -ge 5) {
            "--debug"
        }

        "--verbose"
    }
    elseif ($Module.Verbosity -le 2) {
        "--limit-output"
    }
}

function ConvertTo-ChocolateyArgument {
    <#
        .SYNOPSIS
        Translates parameters into commonly used Chocolatey command line arguments.

        .DESCRIPTION
        Takes the provided parameters and outputs an array of raw command line
        parameters to pass to Chocolatey, including a set of
    #>
    [CmdletBinding()]
    param(
        # Whether to permit downgrading packages with `choco upgrade`.
        [Parameter()]
        [switch]
        $AllowDowngrade,

        # Whether to ignore missing checksums in packages' downloaded files.
        [Parameter()]
        [switch]
        $AllowEmptyChecksums,

        # Whether to permit multiple side by side installations of the same package.
        [Parameter()]
        [switch]
        $AllowMultiple,

        # Whether to consider pre-release packages as valid selections to install.
        [Parameter()]
        [switch]
        $AllowPrerelease,

        # Set to `x86` to force Chocolatey to install x86 binaries.
        [Parameter()]
        [string]
        $Architecture,

        # Specify to override package checksum.
        [Parameter()]
        [string]
        $Checksum,

        # Specify to override package checksum for x64 installers.
        [Parameter()]
        [string]
        $Checksum64,

        # Specify to override package checksum type.
        [Parameter()]
        [ValidateSet('md5', 'sha1', 'sha256', 'sha512')]
        [string]
        $ChecksumType,

        # Specify to override package checksum type for x64 installers.
        [Parameter()]
        [ValidateSet('md5', 'sha1', 'sha256', 'sha512')]
        [string]
        $ChecksumType64,

        # Any additional arguments to be passed directly to `choco.exe`
        [Parameter()]
        [string[]]
        $ChocoArgs,

        # Set to force choco to reinstall the package if the package (version)
        # is already installed.
        [Parameter()]
        [switch]
        $Force,

        # Set to ignore mismatched checksums for files downloaded by packages.
        [Parameter()]
        [switch]
        $IgnoreChecksums,

        # Set to ignore any defined package dependencies.
        [Parameter()]
        [switch]
        $IgnoreDependencies,

        # Installation args to be provided to installers in a given package.
        [Parameter()]
        [string]
        $InstallArgs,

        # Set to have `-InstallArgs` completely overwrite rather than append to
        # normal arguments provided by the package installation script.
        [Parameter()]
        [switch]
        $OverrideArgs,

        # Add specific package parameters to the package installation.
        [Parameter()]
        [string]
        $PackageParams,

        # Set a proxy URL to use when downloading packages.
        [Parameter()]
        [string]
        $ProxyUrl,

        # Set a username for the proxy used when downloading packages.
        [Parameter()]
        [string]
        $ProxyUsername,

        # Set the password for the proxy used for downloading packages.
        [Parameter()]
        [string]
        $ProxyPassword,

        # Skip any .ps1 scripts for the package and just manage the package files
        # in the lib folder directly.
        [Parameter()]
        [bool]
        $SkipScripts,

        # Define a specific source or sources to search for the package.
        [Parameter()]
        [string]
        $Source,

        # Set a username to access authenticated sources.
        [Parameter()]
        [string]
        $SourceUsername,

        # Set the password to access authenticated sources.
        [Parameter()]
        [string]
        $SourcePassword,

        # Set a specific timout in seconds to apply to the operation.
        [Parameter()]
        [int]
        $Timeout,

        # The version for the package to install or uninstall.
        [Parameter()]
        [string]
        $Version
    )

    "--fail-on-unfound"

    # Include common arguments for installing/updating a Chocolatey package
    Get-CommonChocolateyArgument

    if ($AllowDowngrade) { "--allow-downgrade" }
    if ($AllowEmptyChecksums) { "--allow-empty-checksums" }
    if ($AllowMultiple) { "--allow-multiple" }
    if ($AllowPrerelease) { "--prerelease" }
    if ($Architecture -eq "x86") { "--x86" }
    if ($Checksum) { '--checksum', $Checksum }
    if ($Checksum64) { '--checksum64', $Checksum64 }
    if ($ChecksumType) { '--checksumtype', $ChecksumType }
    if ($ChecksumType64) { '--checksumtype64', $ChecksumType64 }
    if ($Force) { "--force" }
    if ($IgnoreChecksums) { "--ignore-checksums" }
    if ($IgnoreDependencies) { "--ignore-dependencies" }
    if ($InstallArgs) { "--install-arguments", $InstallArgs }
    if ($OverrideArgs) { "--override-arguments" }
    if ($PackageParams) { "--package-parameters", $PackageParams }
    if ($ProxyUrl) { "--proxy", $ProxyUrl }
    if ($ProxyUsername) { "--proxy-user", $ProxyUsername }
    if ($ProxyPassword) { "--proxy-password", $ProxyPassword }
    if ($SkipScripts) { "--skip-scripts" }
    if ($Source) { "--source", $Source }

    if ($SourceUsername) {
        "--user", $SourceUsername
        "--password", $SourcePassword
    }

    if ($PSBoundParameters.ContainsKey('Timeout')) { "--timeout", $Timeout }
    if ($Version) { "--version", $Version }
    if ($ChocoArgs) { $ChocoArgs }
}

function Get-ChocolateyPin {
    <#
        .SYNOPSIS
        Gets a hashtable containing all configured pins for installed packages.

        .DESCRIPTION
        Outputs a hashtable with keys corresponding to installed package names,
        and the values as a collection of version numbers.
    #>
    [CmdletBinding()]
    param(
        # A CommandInfo object containing the path to choco.exe.
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.CommandInfo]
        $ChocoCommand
    )

    $command = Argv-ToString -Arguments @(
        $ChocoCommand.Path
        "pin", "list"
        "--limit-output"
    )
    $result = Run-Command -Command $command

    if ($result.rc -ne 0) {
        $message = "Error getting list of pinned packages"
        Assert-TaskFailed -Message $message -Command $command -CommandResult $result
    }

    $pins = @{}

    $result |
        ConvertFrom-Stdout |
        ForEach-Object {
            $package, $version, $null = $_.Split('|')

            if ($pins.ContainsKey($package)) {
                $pins.$package.Add($version)
            }
            else {
                $pins.$package = [System.Collections.Generic.List[string]]@( $version )
            }
        }

    $pins
}

function Set-ChocolateyPin {
    <#
        .SYNOPSIS
        Sets the pin configuration for the target package.
    #>
    [CmdletBinding()]
    param(
        # A CommandInfo object containing the path to choco.exe.
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.CommandInfo]
        $ChocoCommand,

        # The name of the package to pin.
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        # Set to pin the package, otherwise it will be unpinned.
        [Parameter()]
        [switch]
        $Pin,

        # The specific version to pin.
        [Parameter()]
        [string]
        $Version
    )

    if ($Pin) {
        $action = "add"
        $errorMessage = "Error pinning package '$name'"
    }
    else {
        $action = "remove"
        $errorMessage = "Error unpinning package '$name'"
    }

    $arguments = @(
        $ChocoCommand.Path,
        "pin", $action
        "--name", $name

        if ($Version) {
            $errorMessage = "$errorMessage at '$Version'"
            "--version", $Version
        }

        Get-CommonChocolateyArgument
    )

    $command = Argv-ToString -Arguments $arguments
    $result = Run-Command -Command $command
    if ($result.rc -ne 0) {
        Assert-TaskFailed -Message $errorMessage -Command $command -CommandResult $result
    }

    Set-TaskResultChanged
}

function Update-ChocolateyPackage {
    <#
        .SYNOPSIS
        Updates one or more Chocolatey packages.
    #>
    [CmdletBinding()]
    param(
        # A CommandInfo object containing the path to choco.exe.
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.CommandInfo]
        $ChocoCommand,

        # The package or packages to upgrade.
        [Parameter(Mandatory = $true)]
        [string[]]
        $Package,

        # The current module, will be used to set the response codes and
        # any other information needing to be returned.
        # Defaults to the currently active module.
        [Parameter()]
        [Ansible.Basic.AnsibleModule]
        $Module = (Get-AnsibleModule),

        # Whether to permit downgrading packages with `choco upgrade`.
        [Parameter()]
        [switch]
        $AllowDowngrade,

        # Whether to ignore missing checksums in packages' downloaded files.
        [Parameter()]
        [switch]
        $AllowEmptyChecksums,

        # Whether to permit multiple side by side installations of the same package.
        [Parameter()]
        [switch]
        $AllowMultiple,

        # Whether to consider pre-release packages as valid selections to install.
        [Parameter()]
        [switch]
        $AllowPrerelease,

        # Set to `x86` to force Chocolatey to install x86 binaries.
        [Parameter()]
        [string]
        $Architecture,

        # Specify to override package checksum.
        [Parameter()]
        [string]
        $Checksum,

        # Specify to override package checksum for x64 installers.
        [Parameter()]
        [string]
        $Checksum64,

        # Specify to override package checksum type.
        [Parameter()]
        [ValidateSet('md5', 'sha1', 'sha256', 'sha512')]
        [string]
        $ChecksumType,

        # Specify to override package checksum type for x64 installers.
        [Parameter()]
        [ValidateSet('md5', 'sha1', 'sha256', 'sha512')]
        [string]
        $ChecksumType64,

        # Any additional arguments to be passed directly to `choco.exe`
        [Parameter()]
        [string[]]
        $ChocoArgs,

        # Set to force choco to reinstall the package if the package (version)
        # is already installed.
        [Parameter()]
        [switch]
        $Force,

        # Set to ignore mismatched checksums for files downloaded by packages.
        [Parameter()]
        [switch]
        $IgnoreChecksums,

        # Set to ignore any defined package dependencies.
        [Parameter()]
        [switch]
        $IgnoreDependencies,

        # Installation args to be provided to installers in a given package.
        [Parameter()]
        [string]
        $InstallArgs,

        # Set to have `-InstallArgs` completely overwrite rather than append to
        # normal arguments provided by the package installation script.
        [Parameter()]
        [switch]
        $OverrideArgs,

        # Add specific package parameters to the package installation.
        [Parameter()]
        [string]
        $PackageParams,

        # Set a proxy URL to use when downloading packages.
        [Parameter()]
        [string]
        $ProxyUrl,

        # Set a username for the proxy used when downloading packages.
        [Parameter()]
        [string]
        $ProxyUsername,

        # Set the password for the proxy used for downloading packages.
        [Parameter()]
        [string]
        $ProxyPassword,

        # Skip any .ps1 scripts for the package and just manage the package files
        # in the lib folder directly.
        [Parameter()]
        [bool]
        $SkipScripts,

        # Define a specific source or sources to search for the package.
        [Parameter()]
        [string]
        $Source,

        # Set a username to access authenticated sources.
        [Parameter()]
        [string]
        $SourceUsername,

        # Set the password to access authenticated sources.
        [Parameter()]
        [string]
        $SourcePassword,

        # Set a specific timout in seconds to apply to the operation.
        [Parameter()]
        [int]
        $Timeout,

        # The version for the package to upgrade.
        [Parameter()]
        [string]
        $Version
    )

    $commonParams = $PSBoundParameters -as [hashtable]
    $commonParams.Remove('Package')
    $commonParams.Remove('ChocoCommand')
    if ($PSBoundParameters.ContainsKey('Module')) {
        $commonParams.Remove('Module')
    }

    $arguments = @(
        $ChocoCommand.Path
        "upgrade"
        $Package
        ConvertTo-ChocolateyArgument @commonParams
    )

    $command = Argv-ToString -Arguments $arguments
    $result = Run-Command -Command $command
    $Module.Result.rc = $result.rc

    if ($result.rc -notin $script:SuccessExitCodes) {
        $message = "Error updating package(s) '$($Package -join ", ")'"
        Assert-TaskFailed -Message $message -Command $command -CommandResult $result
    }

    if ($Module.Verbosity -gt 1) {
        $Module.Result.stdout = $result.stdout
    }

    if ($result.stdout -match ' upgraded (\d+)/\d+ package') {
        if ($matches[1] -gt 0) {
            Set-TaskResultChanged
        }
    }

    # Need to set to false in case the rc is not 0 and a failure didn't actually occur
    $Module.Result.failed = $false
}

function Install-ChocolateyPackage {
    <#
        .SYNOPSIS
        Installs one or more Chocolatey packages.
    #>
    [CmdletBinding()]
    param(
        # A CommandInfo object containing the path to choco.exe.
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.CommandInfo]
        $ChocoCommand,

        # The package or packages to install.
        [Parameter(Mandatory = $true)]
        [string[]]
        $Package,

        # The current module, will be used to set the response codes and
        # any other information needing to be returned.
        # Defaults to the currently active module.
        [Parameter()]
        [Ansible.Basic.AnsibleModule]
        $Module = (Get-AnsibleModule),

        # Whether to permit downgrading packages with `choco upgrade`.
        [Parameter()]
        [switch]
        $AllowDowngrade,

        # Whether to ignore missing checksums in packages' downloaded files.
        [Parameter()]
        [switch]
        $AllowEmptyChecksums,

        # Whether to permit multiple side by side installations of the same package.
        [Parameter()]
        [switch]
        $AllowMultiple,

        # Whether to consider pre-release packages as valid selections to install.
        [Parameter()]
        [switch]
        $AllowPrerelease,

        # Set to `x86` to force Chocolatey to install x86 binaries.
        [Parameter()]
        [string]
        $Architecture,

        # Specify to override package checksum.
        [Parameter()]
        [string]
        $Checksum,

        # Specify to override package checksum for x64 installers.
        [Parameter()]
        [string]
        $Checksum64,

        # Specify to override package checksum type.
        [Parameter()]
        [ValidateSet('md5', 'sha1', 'sha256', 'sha512')]
        [string]
        $ChecksumType,

        # Specify to override package checksum type for x64 installers.
        [Parameter()]
        [ValidateSet('md5', 'sha1', 'sha256', 'sha512')]
        [string]
        $ChecksumType64,

        # Any additional arguments to be passed directly to `choco.exe`
        [Parameter()]
        [string[]]
        $ChocoArgs,

        # Set to force choco to reinstall the package if the package (version)
        # is already installed.
        [Parameter()]
        [switch]
        $Force,

        # Set to ignore mismatched checksums for files downloaded by packages.
        [Parameter()]
        [switch]
        $IgnoreChecksums,

        # Set to ignore any defined package dependencies.
        [Parameter()]
        [switch]
        $IgnoreDependencies,

        # Installation args to be provided to installers in a given package.
        [Parameter()]
        [string]
        $InstallArgs,

        # Set to have `-InstallArgs` completely overwrite rather than append to
        # normal arguments provided by the package installation script.
        [Parameter()]
        [switch]
        $OverrideArgs,

        # Add specific package parameters to the package installation.
        [Parameter()]
        [string]
        $PackageParams,

        # Set a proxy URL to use when downloading packages.
        [Parameter()]
        [string]
        $ProxyUrl,

        # Set a username for the proxy used when downloading packages.
        [Parameter()]
        [string]
        $ProxyUsername,

        # Set the password for the proxy used for downloading packages.
        [Parameter()]
        [string]
        $ProxyPassword,

        # Skip any .ps1 scripts for the package and just manage the package files
        # in the lib folder directly.
        [Parameter()]
        [bool]
        $SkipScripts,

        # Define a specific source or sources to search for the package.
        [Parameter()]
        [string]
        $Source,

        # Set a username to access authenticated sources.
        [Parameter()]
        [string]
        $SourceUsername,

        # Set the password to access authenticated sources.
        [Parameter()]
        [string]
        $SourcePassword,

        # Set a specific timout in seconds to apply to the operation.
        [Parameter()]
        [int]
        $Timeout,

        # The version for the package to install.
        [Parameter()]
        [string]
        $Version
    )

    $commonParams = $PSBoundParameters -as [hashtable]
    $commonParams.Remove('Package')
    $commonParams.Remove('ChocoCommand')
    if ($PSBoundParameters.ContainsKey('Module')) {
        $commonParams.Remove('Module')
    }

    $arguments = @(
        $ChocoCommand.Path
        "install"
        $Package
        ConvertTo-ChocolateyArgument @commonParams
    )

    $command = Argv-ToString -Arguments $arguments
    $result = Run-Command -Command $command
    $Module.Result.rc = $result.rc

    if ($result.rc -notin $script:SuccessExitCodes) {
        $message = "Error installing package(s) '$($Package -join ", ")'"
        Assert-TaskFailed -Message $message -Command $command -CommandResult $result
    }

    if ($Module.Verbosity -gt 1) {
        $Module.Result.stdout = $result.stdout
    }

    Set-TaskResultChanged

    # need to set to false in case the rc is not 0 and a failure didn't actually occur
    $Module.Result.failed = $false
}

function Uninstall-ChocolateyPackage {
    <#
        .SYNOPSIS
        Uninstalls one or more Chocolatey packages.
    #>
    [CmdletBinding()]
    param(
        # A CommandInfo object containing the path to choco.exe.
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.CommandInfo]
        $ChocoCommand,

        # The package or packages to uninstall.
        [Parameter(Mandatory = $true)]
        [string[]]
        $Package,

        # The current module, will be used to set the response codes and
        # any other information needing to be returned.
        # Defaults to the currently active module.
        [Parameter()]
        [Ansible.Basic.AnsibleModule]
        $Module = (Get-AnsibleModule),

        # Set to force choco to reinstall the package if the package (version)
        # is already installed.
        [Parameter()]
        [switch]
        $Force,

        # Add specific package parameters to the package installation.
        [Parameter()]
        [string]
        $PackageParams,

        # Skip any .ps1 scripts for the package and just manage the package files
        # in the lib folder directly.
        [Parameter()]
        [switch]
        $SkipScripts,

        # Uninstall all dependencies for this package as well.
        [Parameter()]
        [switch]
        $RemoveDependencies,

        # Whether to permit multiple side by side installations of the same package.
        [Parameter()]
        [switch]
        $AllowMultiple,

        # Set a specific timout in seconds to apply to the operation.
        [Parameter()]
        [int]
        $Timeout,

        # The version for the package to uninstall.
        [Parameter()]
        [string]
        $Version
    )

    $arguments = @(
        $ChocoCommand.Path
        "uninstall"
        $Package
        Get-CommonChocolateyArgument

        if ($Version) {
            "--version", $Version

            if ($AllowMultiple) {
                "--allow-multiple"
            }
        }
        else {
            "--all-versions"
        }

        if ($RemoveDependencies) { "--remove-dependencies" }
        if ($Force) { "--force" }
        if ($PSBoundParameters.ContainsKey('Timeout')) { "--timeout", $timeout }
        if ($SkipScripts) { "--skip-scripts" }
        if ($PackageParams) { "--package-parameters", $package_params }
    )

    $command = Argv-ToString -Arguments $arguments
    $result = Run-Command -Command $command
    $Module.Result.rc = $result.rc

    if ($result.rc -notin $script:SuccessExitCodes) {
        $message = "Error uninstalling package(s) '$($Package -join ", ")'"
        Assert-TaskFailed -Message $message -Command $command -CommandResult $result
    }

    if ($Module.Verbosity -gt 1) {
        $Module.Result.stdout = $result.stdout
    }

    Set-TaskResultChanged

    # need to set to false in case the rc is not 0 and a failure didn't actually occur
    $Module.Result.failed = $false
}

function Install-Chocolatey {
    [CmdletBinding()]
    param(
        # The current module, will be used to set the response codes and
        # any other information needing to be returned.
        # Defaults to the currently active module.
        [Parameter()]
        [Ansible.Basic.AnsibleModule]
        $Module = (Get-AnsibleModule),

        # Set a proxy URL to use when downloading Chocolatey.
        [Parameter()]
        [string]
        $ProxyUrl,

        # Set a proxy username to use when downloading Chocolatey.
        [Parameter()]
        [string]
        $ProxyUsername,

        # Set a proxy password to use when downloading Chocolatey.
        [Parameter()]
        [string]
        $ProxyPassword,

        # Set the source URL to find the chocolatey install script in.
        [Parameter()]
        [string]
        $Source,

        # The username to authenticate to the source repository.
        [Parameter()]
        [string]
        $SourceUsername,

        # The password to authenticate to the source repository.
        [Parameter()]
        [string]
        $SourcePassword,

        # The version of Chocolatey to install.
        [Parameter()]
        [string]
        $Version,

        # Set to skip writing the warning message when Chocolatey is not yet present.
        [Parameter()]
        [switch]
        $SkipWarning,

        [Parameter()]
        [string]
        $BootstrapScript,

        [Parameter()]
        [string[]]
        $BootstrapTlsVersion
    )

    $chocoCommand = Get-ChocolateyCommand -IgnoreMissing
    if ($null -eq $chocoCommand) {
        # We need to install chocolatey

        # Chocolatey CLI v2.0.0 and above requires .NET Framework 4.8 to be installed.
        # If the user has specified a 1.x version of Chocolatey to install, or the .NET requirement is met, we'll install Chocolatey.
        $dotNetRegistryPath = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
        $installedDotNetVersion = [version]((Get-ItemProperty -Path $dotNetRegistryPath -Name Version).Version)

        $chocolateyLegacyVersion = if ($Version) {
            [version]$Version -lt [version]"2.0.0"
        } else {
            $false
        }

        if ((-not $chocolateyLegacyVersion) -and ($installedDotNetVersion -lt [version]"4.8")) {
            $message = @(
                "Chocolatey 2.0.0 requires .NET Framework 4.8 or higher to be installed."
                "Please install .NET Framework 4.8 or higher and try again,"
                "or specify a 1.x version of Chocolatey to install."
            ) -join ' '
            Assert-TaskFailed -Message $message
        }

        # Enable necessary TLS versions if they're available but disabled.
        # Default for win_chocolatey is to allow TLS 1.1, 1.2, and 1.3 (if available)
        $protocols = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::SystemDefault

        foreach ($tlsVersion in $BootstrapTlsVersion) {
            # If the TLS version isn't available on the system, this will evaluate to $null and be skipped
            $value = $tlsVersion -as [System.Net.SecurityProtocolType]
            if ($value) {
                $protocols = $protocols -bor $value
            }
        }

        [System.Net.ServicePointManager]::SecurityProtocol = $protocols

        # These env values are used in the install.ps1 script when getting
        # external dependencies
        $environment = [Environment]::GetEnvironmentVariables()
        $client = New-Object -TypeName System.Net.WebClient

        if ($ProxyUrl) {
            $environment.chocolateyProxyLocation = $ProxyUrl

            $proxy = New-Object -TypeName System.Net.WebProxy -ArgumentList $ProxyUrl, $true
            $client.Proxy = $proxy

            if ($ProxyUsername -and $ProxyPassword) {
                $environment.chocolateyProxyUser = $ProxyUsername
                $environment.chocolateyProxyPassword = $ProxyPassword
                $securePassword = ConvertTo-SecureString -String $ProxyPassword -AsPlainText -Force
                $proxy.Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @(
                    $ProxyUsername
                    $securePassword
                )
            }
        }

        if ($Version) {
            # Set the chocolateyVersion environment variable when bootstrapping Chocolatey to install that specific
            # version.
            $environment.chocolateyVersion = $Version
        }

        $scriptUrl = if ($BootstrapScript) {
            $BootstrapScript
        }
        elseif ($Source) {
            $uriInfo = [System.Uri]$Source

            # check if the URL already contains the path to PS script
            if ($Source -like "*.ps1") {
                $Source
            }
            elseif ($uriInfo.AbsolutePath -like '/repository/*') {
                # Best-effort guess at finding an install.ps1 for Chocolatey in the given repository
                "$($uriInfo.Scheme)://$($uriInfo.Authority)/$($uriInfo.AbsolutePath)/install.ps1" -replace '(?<!:)//', '/'
            }
            else {
                # chocolatey server automatically serves a script at http://host/install.ps1, we rely on this
                # behaviour when a user specifies the choco source URL and it doesn't look like a repository
                # style url.
                # If a custom URL or file path is desired, they should use win_get_url/win_shell manually.
                # We need to strip the path off the URL and append `install.ps1`
                "$($uriInfo.Scheme)://$($uriInfo.Authority)/install.ps1"
            }

            if ($SourceUsername) {
                # While the choco-server does not require creds on install.ps1, Net.WebClient will only send the
                # credentials if the initial request fails; we add the creds here in case the source URL is not
                # choco-server and requires authentication.
                $securePassword = ConvertTo-SecureString -String $SourcePassword -AsPlainText -Force
                $client.Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @(
                    $SourceUsername
                    $securePassword
                )
            }
        }
        else {
            "https://community.chocolatey.org/install.ps1"
        }

        try {
            $installScript = $client.DownloadString($scriptUrl)
        }
        catch {
            $message = "Failed to download Chocolatey script from '$scriptUrl'; $($_.Exception.Message)"
            Assert-TaskFailed -Message $message -Exception $_.Exception
        }

        if (-not $Module.CheckMode) {
            $scriptFile = New-Item -Path (Join-Path $Module.TmpDir -ChildPath 'chocolateyInstall.ps1') -ItemType File
            $installScript | Set-Content -Path $scriptFile

            # These commands will be sent over stdin for the PowerShell process, and will be read line by line,
            # so we must join them on \r\n line-feeds to have them read as separate commands.
            $commands = @(
                '$ProgressPreference = "SilentlyContinue"'
                '& "{0}"' -f $scriptFile
            ) -join "`r`n"

            $result = Run-Command -Command "powershell.exe -" -Stdin $commands -Environment $environment
            if ($result.rc -ne 0) {
                $message = "Chocolatey bootstrap installation failed."
                Assert-TaskFailed -Message $message -CommandResult $result
            }

            if (-not $SkipWarning) {
                $Module.Warn("Chocolatey was missing from this system, so it was installed during this task run.")
            }
        }

        Set-TaskResultChanged

        # locate the newly installed choco.exe
        $chocoCommand = Get-ChocolateyCommand -IgnoreMissing
    }

    if ($null -eq $chocoCommand -or -not (Test-Path -LiteralPath $chocoCommand.Path)) {
        if ($Module.CheckMode) {
            $Module.Result.skipped = $true
            $Module.Result.msg = "Skipped check mode run on win_chocolatey as choco.exe cannot be found on the system"
            $Module.ExitJson()
        }
        else {
            $message = "Failed to find choco.exe, make sure it is added to the PATH or the env var 'ChocolateyInstall' is set"
            Assert-TaskFailed -Message $message
        }
    }

    $chocolateyPackageVersion = (Get-ChocolateyPackageVersion -ChocoCommand $chocoCommand -Name 'chocolatey').chocolatey |
        Select-Object -First 1

    if ($chocolateyPackageVersion) {
        try {
            # The Chocolatey version may not be in the strict form of major.minor.build and will fail to cast to
            # System.Version. We want to warn if this is the case saying module behaviour may be incorrect.
            $actualVersion = [Version]$chocolateyPackageVersion
        }
        catch {
            $warning = @(
                "Failed to parse Chocolatey version '$actualVersion' for checking module requirements."
                "Module may not work correctly: $($_.Exception.Message)"
            ) -join ' '
            $Module.Warn($warning)
            $actualVersion = $null
        }
    }
    else {
        # Couldn't find the Chocolatey package information
        $warning = @(
            "Did not find version information for package ID 'chocolatey'."
            "Unable to determine the client's installed Chocolatey version."
            "Module may not work correctly."
            "You may be able to rectify this by upgrading / reinstalling 'chocolatey'."
        ) -join ' '
        $Module.Warn($warning)
        $actualVersion = $null
    }

    if ($null -ne $actualVersion -and $actualVersion -lt [Version]"0.10.5") {
        if ($Module.CheckMode) {
            $Module.Result.skipped = $true
            $Module.Result.msg = @(
                "Skipped check mode run on win_chocolatey as choco.exe is too old, a real run would have upgraded the executable."
                "Actual: '$actualVersion', Minimum Version: '0.10.5'"
            ) -join ' '
            $Module.ExitJson()
        }

        $Module.Warn("Chocolatey was older than v0.10.5 so it will be upgraded during this task run.")
        $params = @{
            ChocoCommand = $chocoCommand
            Packages = @("chocolatey")
            ProxyUrl = $ProxyUrl
            ProxyUsername = $ProxyUsername
            ProxyPassword = $ProxyPassword
            Source = $Source
            SourceUsername = $SourceUsername
            SourcePassword = $SourcePassword
        }
        Update-ChocolateyPackage @params
    }

    $chocoCommand
}

Export-ModuleMember -Function @(
    'ConvertTo-ChocolateyArgument'
    'Get-ChocolateyOutdated'
    'Get-ChocolateyPackage'
    'Get-ChocolateyPackageVersion'
    'Get-ChocolateyPin'
    'Get-ChocolateyVersion'
    'Get-CommonChocolateyArgument'
    'Set-ChocolateyPin'
    'Install-Chocolatey'
    'Install-ChocolateyPackage'
    'Uninstall-ChocolateyPackage'
    'Update-ChocolateyPackage'
)
