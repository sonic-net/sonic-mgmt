#!powershell

# Copyright: (c) 2014, Trond Hindenes <trond@hindenes.com>
# Copyright: (c) 2017, Dag Wieers <dag@wieers.com>
# Copyright: (c) 2018, Ansible Project
# Copyright: (c) 2020, Chocolatey Software
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

#Requires -Module Ansible.ModuleUtils.ArgvParser
#Requires -Module Ansible.ModuleUtils.CommandUtil

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Common
#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Packages

[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseConsistentWhitespace',
    '',
    Justification = 'Relax whitespace rule for better readability in module spec',
    Scope = 'function',
    # Apply suppression specifically to module spec
    Target = 'Get-ModuleSpec')]
param()

# As of chocolatey 0.9.10, non-zero success exit codes can be returned
# See https://github.com/chocolatey/choco/issues/512#issuecomment-214284461
$script:successExitCodes = (0, 1605, 1614, 1641, 3010)

function Get-ModuleSpec {
    @{
        options             = @{
            allow_empty_checksums = @{ type = "bool"; default = $false }
            allow_multiple        = @{ type = "bool"; default = $false; removed_in_version = '2.0.0'; removed_from_collection = 'chocolatey.chocolatey' }
            allow_prerelease      = @{ type = "bool"; default = $false }
            architecture          = @{ type = "str"; default = "default"; choices = "default", "x86" }
            bootstrap_script      = @{ type = "str"; aliases = "install_ps1", "bootstrap_ps1" }
            bootstrap_tls_version = @{
                type = "list"
                elements = "str"
                choices = "tls11", "tls12", "tls13"
                default = "tls12", "tls13"
                aliases = "tls_version", "tls_versions", "bootstrap_tls_versions"
            }
            checksum              = @{ type = "str" }
            checksum64            = @{ type = "str" }
            checksum_type         = @{ type = "str"; choices = "md5", "sha1", "sha256", "sha512" }
            checksum_type64       = @{ type = "str"; choices = "md5", "sha1", "sha256", "sha512" }
            choco_args            = @{ type = "list"; elements = "str"; aliases = "licensed_args" }
            force                 = @{ type = "bool"; default = $false }
            ignore_checksums      = @{ type = "bool"; default = $false }
            ignore_dependencies   = @{ type = "bool"; default = $false }
            install_args          = @{ type = "str" }
            name                  = @{ type = "list"; elements = "str"; required = $true }
            override_args         = @{ type = "bool"; default = $false }
            package_params        = @{ type = "str"; aliases = @("params") }
            pinned                = @{ type = "bool" }
            proxy_url             = @{ type = "str" }
            proxy_username        = @{ type = "str" }
            proxy_password        = @{ type = "str"; no_log = $true }
            remove_dependencies   = @{ type = "bool"; default = $false }
            skip_scripts          = @{ type = "bool"; default = $false }
            source                = @{ type = "str" }
            source_username       = @{ type = "str" }
            source_password       = @{ type = "str"; no_log = $true }
            state                 = @{ type = "str"; default = "present"; choices = "absent", "downgrade", "upgrade", "latest", "present", "reinstalled" }
            timeout               = @{ type = "int"; default = 2700; aliases = @("execution_timeout") }
            validate_certs        = @{ type = "bool"; default = $true }
            version               = @{ type = "str" }
        }
        supports_check_mode = $true
    }
}

$spec = Get-ModuleSpec

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
Set-ActiveModule $module

$allow_empty_checksums = $module.Params.allow_empty_checksums
$allow_multiple = $module.Params.allow_multiple
$allow_prerelease = $module.Params.allow_prerelease
$architecture = $module.Params.architecture
$bootstrap_script = $module.Params.bootstrap_script
$checksum = $module.Params.checksum
$checksum64 = $module.Params.checksum64
$checksum_type = $module.Params.checksum_type
$checksum_type64 = $module.Params.checksum_type64
$choco_args = $module.Params.choco_args
$force = $module.Params.force
$ignore_checksums = $module.Params.ignore_checksums
$ignore_dependencies = $module.Params.ignore_dependencies
$install_args = $module.Params.install_args
$name = $module.Params.name
$override_args = $module.Params.override_args
$package_params = $module.Params.package_params
$pinned = $module.Params.pinned
$proxy_url = $module.Params.proxy_url
$proxy_username = $module.Params.proxy_username
$proxy_password = $module.Params.proxy_password
$remove_dependencies = $module.Params.remove_dependencies
$skip_scripts = $module.Params.skip_scripts
$source = $module.Params.source
$source_username = $module.Params.source_username
$source_password = $module.Params.source_password
$state = $module.Params.state
$timeout = $module.Params.timeout
$bootstrap_tls_version = $module.Params.bootstrap_tls_version
$validate_certs = $module.Params.validate_certs
$version = $module.Params.version

$module.Result.rc = 0

if (-not $validate_certs) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
}

# get the full path to choco.exe, otherwise install/upgrade to at least 0.10.5
$installParams = @{
    BootstrapTlsVersion = $bootstrap_tls_version
    ProxyUrl = $proxy_url
    ProxyUsername = $proxy_username
    ProxyPassword = $proxy_password
    Source = $source
    SourceUsername = $source_username
    SourcePassword = $source_password
}

if ($version -and "chocolatey" -in $name) {
    # If a version is set and chocolatey is in the package list, pass the chocolatey version to the bootstrapping
    # process.
    $installParams.Version = $version
    $installParams.SkipWarning = $true
}

if ($bootstrap_script) {
    $installParams.BootstrapScript = $bootstrap_script
}

$chocoCommand = Install-Chocolatey @installParams

if ('all' -in $name -and $state -in @('present', 'reinstalled')) {
    $message = "Cannot specify the package name as 'all' when state=$state"
    Assert-TaskFailed -Message $message
}

# Get the installed versions of all specified packages
$packageInfo = $name | Get-ChocolateyPackageVersion -ChocoCommand $chocoCommand
$chocolateyVersion = Get-ChocolateyVersion -ChocoCommand $chocoCommand

# Ensure module output contains the choco CLI version in case folks need it for
# debugging purposes.
$module.Result.choco_cli_version = "$chocolateyVersion"

if ($chocolateyVersion -ge [version]'2.0.0' -and $allow_multiple) {
    Assert-TaskFailed -Message "Option 'allow_multiple' is not supported on the installed version of Chocolatey CLI"
}

if ($state -in "absent", "reinstalled") {
    $installedPackages = $packageInfo.Keys | Where-Object { $null -ne $packageInfo.$_ }

    if ($null -ne $installedPackages) {
        foreach ($package in $installedPackages) {
            # If a version has been supplied, check that that version of the package is actually installed.
            # If that version of the package is not present, don't uninstall other versions by accident.
            if ($version) {
                $packageVersionedInfo = $package | Get-ChocolateyPackageVersion -ChocoCommand $chocoCommand -Version $version
                $currentlyInstalledVersions = $packageVersionedInfo.Keys | Where-Object { $null -ne $packageVersionedInfo.$_ }
                if (@($currentlyInstalledVersions).Count -eq 0) {
                    continue
                }
            }

            # --allow-multiple is buggy for `choco uninstall`.
            # To get the correct behaviour, we have to use it only when multiple side by side package versions
            # are actually installed, or we'll either just get errors, or end up uninstalling all installed versions
            # even if a specific version is targeted.
            $useAllowMultiple = $packageInfo.$package.Count -gt 1
            $uninstallParams = @{
                ChocoCommand = $chocoCommand
                Package = $package
                Force = $force
                PackageParams = $package_params
                SkipScripts = $skip_scripts
                RemoveDependencies = $remove_dependencies
                Timeout = $timeout
                Version = $version
                AllowMultiple = $useAllowMultiple
            }
            Uninstall-ChocolateyPackage @uninstallParams
        }
    }

    # Ensure the package info for the uninstalled versions has been removed,
    # so state=reinstall will install them in the next step
    foreach ($package in $installedPackages) {
        $packageInfo.$package = $null
    }
}

if ($state -in @("downgrade", "latest", "upgrade", "present", "reinstalled")) {
    # When state=present and force=true, we just run the install step with the packages specified,
    # otherwise only install the packages that are not installed
    $missingPackages = [System.Collections.Generic.List[string]]@()

    if ($state -eq "present" -and $force) {
        $missingPackages.Add($name)
    }
    else {
        foreach ($package in $packageInfo.GetEnumerator()) {
            if ($null -eq $package.Value) {
                $missingPackages.Add($package.Key)
            }
        }
    }

    # If version is specified and installed version does not match or not
    # allow_multiple, throw error. Ignore this if force is set.
    if ($state -eq "present" -and $null -ne $version -and -not $force) {
        foreach ($package in $name) {
            $packageVersions = @($packageInfo.$package | Where-Object { $_ })

            if ($packageVersions.Count -gt 0) {
                if (-not $packageVersions.Contains($version) -and -not $allow_multiple) {
                    $message = @(
                        "Chocolatey package '$package' is already installed with version(s) '$($packageVersions -join "', '")'"
                        "but was expecting '$version'. Either change the expected version, set state=latest or state=upgrade,"
                        "set allow_multiple=yes, or set force=yes to continue"
                    ) -join ' '
                    Assert-TaskFailed -Message $message
                }
                elseif ($version -notin $packageVersions -and $allow_multiple) {
                    # add the package back into the list of missing packages if installing multiple
                    $missingPackages.Add($package)
                }
            }
        }
    }

    $commonParams = @{
        ChocoCommand = $chocoCommand
        AllowDowngrade = ($state -eq "downgrade")
        AllowEmptyChecksums = $allow_empty_checksums
        AllowMultiple = $allow_multiple
        AllowPrerelease = $allow_prerelease
        Architecture = $architecture
        Checksum = $checksum
        Checksum64 = $checksum64
        ChocoArgs = $choco_args
        Force = $force
        IgnoreChecksums = $ignore_checksums
        IgnoreDependencies = $ignore_dependencies
        InstallArgs = $install_args
        OverrideArgs = $override_args
        PackageParams = $package_params
        ProxyUrl = $proxy_url
        ProxyUsername = $proxy_username
        ProxyPassword = $proxy_password
        SkipScripts = $skip_scripts
        Source = $source
        SourceUsername = $source_username
        SourcePassword = $source_password
        Timeout = $timeout
        Version = $version
    }

    if ($checksum_type -and $checksum_type -ne '') {
        $commonParams.Add('ChecksumType', $checksum_type)
    }

    if ($checksum_type64 -and $checksum_type64 -ne '') {
        $commonParams.Add('ChecksumType64', $checksum_type64)
    }

    if ($missingPackages.Count -gt 0) {
        Install-ChocolateyPackage -Package $missingPackages @commonParams
    }

    if ($state -in @("latest", "upgrade") -or ($state -eq "downgrade" -and $null -ne $version)) {
        # when in a downgrade/latest situation, we want to run choco upgrade on
        # the remaining packages that were already installed, don't run this if
        # state=downgrade and a version isn't specified (this will actually
        # upgrade a package)
        $installedPackages = ($packageInfo.GetEnumerator() | Where-Object { $null -ne $_.Value }).Key

        if ($null -ne $installedPackages) {
            Update-ChocolateyPackage -Package $installedPackages @commonParams
        }
    }

    # Now we want to pin/unpin any packages now that it has been installed/upgraded
    if ($null -ne $pinned) {
        $pins = Get-ChocolateyPin -ChocoCommand $chocoCommand

        foreach ($package in $name) {
            if ($pins.ContainsKey($package)) {
                if (-not $pinned -and $null -eq $version) {
                    # No version is set and pinned=no, we want to remove all pins on the package. There is a bug in
                    # 'choco pin remove' with multiple versions where an older version might be pinned but
                    # 'choco pin remove' will still fail without an explicit version. Instead we take the literal
                    # interpretation that pinned=no and no version means the package has no pins at all
                    foreach ($v in $pins.$package) {
                        Set-ChocolateyPin -ChocoCommand $chocoCommand -Name $package -Version $v
                    }
                }
                elseif ($null -ne $version -and $pins.$package.Contains($version) -ne $pinned) {
                    Set-ChocolateyPin -ChocoCommand $chocoCommand -Name $package -Pin:$pinned -Version $version
                }
            }
            elseif ($pinned) {
                # Package had no pins but pinned=yes is set.
                Set-ChocolateyPin -ChocoCommand $chocoCommand -Name $package -Pin -Version $version
            }
        }
    }
}

$module.ExitJson()
