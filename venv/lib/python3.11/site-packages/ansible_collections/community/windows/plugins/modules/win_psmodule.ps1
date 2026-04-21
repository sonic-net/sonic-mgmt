#!powershell

# Copyright: (c) 2018, Wojciech Sciesinski <wojciech[at]sciesinski[dot]net>
# Copyright: (c) 2017, Daniele Lazzari <lazzari@mailup.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -PowerShell ..module_utils._Tls
#Requires -Module Ansible.ModuleUtils.Legacy

# win_psmodule (Windows PowerShell modules Additions/Removals/Updates)

$params = Parse-Args -arguments $args -supports_check_mode $true
$check_mode = Get-AnsibleParam -obj $params -name "_ansible_check_mode" -type "bool" -default $false

$name = Get-AnsibleParam -obj $params -name "name" -type "str" -failifempty $true
$required_version = Get-AnsibleParam -obj $params -name "required_version" -type "str"
$minimum_version = Get-AnsibleParam -obj $params -name "minimum_version" -type "str"
$maximum_version = Get-AnsibleParam -obj $params -name "maximum_version" -type "str"
$repo = Get-AnsibleParam -obj $params -name "repository" -type "str"
$repo_user = Get-AnsibleParam -obj $params -name "username" -type "str"
$repo_pass = Get-AnsibleParam -obj $params -name "password" -type "str"
$state = Get-AnsibleParam -obj $params -name "state" -type "str" -default "present" -validateset "present", "absent", "latest"
$allow_clobber = Get-AnsibleParam -obj $params -name "allow_clobber" -type "bool" -default $false
$skip_publisher_check = Get-AnsibleParam -obj $params -name "skip_publisher_check" -type "bool" -default $false
$allow_prerelease = Get-AnsibleParam -obj $params -name "allow_prerelease" -type "bool" -default $false
$accept_license = Get-AnsibleParam -obj $params -name "accept_license" -type "bool" -default $false
$force = Get-AnsibleParam -obj $params -name "force" -type "bool" -default $false

$result = @{changed = $false
    output = ""
    nuget_changed = $false
    repository_changed = $false
}

Enable-TlsProtocol

Function Install-NugetProvider {
    Param(
        [Bool]$CheckMode
    )
    $PackageProvider = Get-PackageProvider -ListAvailable | Where-Object { ($_.name -eq 'Nuget') -and ($_.version -ge "2.8.5.201") }
    if (-not($PackageProvider)) {
        try {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -WhatIf:$CheckMode | Out-Null
            $result.changed = $true
            $result.nuget_changed = $true
        }
        catch [ System.Exception ] {
            $ErrorMessage = "Problems adding package provider: $($_.Exception.Message)"
            Fail-Json $result $ErrorMessage
        }
    }
}

Function Install-PrereqModule {
    Param(
        [Switch]$TestInstallationOnly,
        [bool]$AllowClobber,
        [Bool]$CheckMode,
        [bool]$AcceptLicense,
        [string]$Repository
    )

    # Those are minimum required versions of modules.
    $PrereqModules = @{
        PackageManagement = '1.1.7'
        PowerShellGet = '1.6.0'
    }

    $ExistingPrereqModule = Get-Module -Name @($PrereqModules.Keys) -ListAvailable |
        Where-Object { $_.Version -ge $PreReqModules[$_.Name] } |
        Select-Object -ExpandProperty Name -Unique
    $toInstall = $PrereqModules.Keys |
        Where-Object { $_ -notin $ExistingPrereqModule } |
        Select-Object @{N = 'Name'; E = { $_ } }, @{N = 'Version'; E = { $PrereqModules[$_] } }

    if ($TestInstallationOnly) {
        -not [bool]$toInstall
    }
    elseif ($toInstall) {
        $result.changed = $true
        if ($CheckMode) {
            $result.output = "Skipped check mode run on win_psmodule as the pre-reqs need upgrading"
            Exit-Json $result
        }

        # Need to run this in another process as importing PackageManagement at
        # the older version is irreversible (you cannot load the same dll at
        # different versions). Start-Job runs in a new process so it can safely
        # use the older version to install our pre-reqs.
        # https://github.com/ansible-collections/community.windows/issues/487
        $job = Start-Job -ScriptBlock {
            $ErrorActionPreference = 'Stop'

            if (-not (Get-PackageProvider -ListAvailable | Where-Object { ($_.name -eq 'Nuget') -and ($_.version -ge "2.8.5.201") }) ) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
            }

            $Repository = $using:Repository

            foreach ($info in $using:ToInstall) {
                $install_params = @{
                    Name = $info.Name
                    MinimumVersion = $info.Version
                    Force = $true
                }
                $installCmd = Get-Command -Name Install-Module
                if ($installCmd.Parameters.ContainsKey('SkipPublisherCheck')) {
                    $install_params.SkipPublisherCheck = $true
                }
                if ($installCmd.Parameters.ContainsKey('AllowClobber')) {
                    $install_params.AllowClobber = $using:AllowClobber
                }
                if ($installCmd.Parameters.ContainsKey('AcceptLicense')) {
                    $install_params.AcceptLicense = $using:AcceptLicense
                }
                if ($Repository) {
                    $install_params.Repository = $Repository
                }

                Install-Module @install_params > $null
            }
        }

        try {
            $null = $job | Receive-Job -AutoRemoveJob -Wait -ErrorAction Stop
        }
        catch {
            $ErrorMessage = "Problems adding a prerequisite module PackageManagement or PowerShellGet: $($_.Exception.Message)"
            $result.exception = ($_ | Out-String) + "`r`n" + $_.ScriptStackTrace
            Fail-Json $result $ErrorMessage
        }
    }
}

Function Get-PsModule {
    Param(
        [Parameter(Mandatory = $true)]
        [String]$Name,
        [String]$RequiredVersion,
        [String]$MinimumVersion,
        [String]$MaximumVersion
    )

    $ExistingModule = @{
        Exists = $false
        Version = ""
    }

    $ExistingModules = Get-Module -ListAvailable | Where-Object { ($_.name -eq $Name) }
    $ExistingModulesCount = $($ExistingModules | Measure-Object).Count

    if ( $ExistingModulesCount -gt 0 ) {

        $ExistingModules | Add-Member -MemberType ScriptProperty -Name FullVersion -Value {
            if ( $null -ne ( $this.PrivateData ) ) {
                [String]"$($this.Version)-$(($this | Select-Object -ExpandProperty PrivateData).PSData.Prerelease)".TrimEnd('-')
            }
            else {
                [String]"$($this.Version)"
            }
        }

        if ( -not ($RequiredVersion -or
                $MinimumVersion -or
                $MaximumVersion) ) {

            $ReturnedModule = $ExistingModules | Select-Object -First 1
        }
        elseif ( $RequiredVersion ) {
            $ReturnedModule = $ExistingModules | Where-Object -FilterScript { $_.FullVersion -eq $RequiredVersion }
        }
        elseif ( $MinimumVersion -and $MaximumVersion ) {
            $ReturnedModule = $ExistingModules |
                Where-Object -FilterScript { $MinimumVersion -le $_.Version -and $MaximumVersion -ge $_.Version } |
                Select-Object -First 1
        }
        elseif ( $MinimumVersion ) {
            $ReturnedModule = $ExistingModules | Where-Object -FilterScript { $MinimumVersion -le $_.Version } | Select-Object -First 1
        }
        elseif ( $MaximumVersion ) {
            $ReturnedModule = $ExistingModules | Where-Object -FilterScript { $MaximumVersion -ge $_.Version } | Select-Object -First 1
        }
    }

    $ReturnedModuleCount = ($ReturnedModule | Measure-Object).Count

    if ( $ReturnedModuleCount -eq 1 ) {
        $ExistingModule.Exists = $true
        $ExistingModule.Version = $ReturnedModule.FullVersion
    }

    $ExistingModule
}

Function Add-DefinedParameter {
    Param (
        [Parameter(Mandatory = $true)]
        [Hashtable]$Hashtable,
        [Parameter(Mandatory = $true)]
        [String[]]$ParametersNames
    )

    ForEach ($ParameterName in $ParametersNames) {
        $ParameterVariable = Get-Variable -Name $ParameterName -ErrorAction SilentlyContinue
        if ( $ParameterVariable.Value -and $Hashtable.Keys -notcontains $ParameterName ) {
            $Hashtable.Add($ParameterName, $ParameterVariable.Value)
        }
    }

    $Hashtable
}

Function Install-PsModule {
    Param(
        [Parameter(Mandatory = $true)]
        [String]$Name,
        [String]$RequiredVersion,
        [String]$MinimumVersion,
        [String]$MaximumVersion,
        [String]$Repository,
        [System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty,
        [Bool]$AllowClobber,
        [Bool]$SkipPublisherCheck,
        [Bool]$AllowPrerelease,
        [Bool]$CheckMode,
        [Bool]$AcceptLicense,
        [Bool]$Force
    )

    $getParams = @{
        Name = $Name
        RequiredVersion = $RequiredVersion
        MinimumVersion = $MinimumVersion
        MaximumVersion = $MaximumVersion
    }
    $ExistingModuleBefore = Get-PsModule @getParams

    if ( -not $ExistingModuleBefore.Exists ) {
        try {
            # Install NuGet provider if needed.
            Install-NugetProvider -CheckMode $CheckMode

            $ht = @{
                Name = $Name
            }

            [String[]]$ParametersNames = @("RequiredVersion", "MinimumVersion", "MaximumVersion", "AllowPrerelease",
                "Repository", "Credential")
            $ht = Add-DefinedParameter -Hashtable $ht -ParametersNames $ParametersNames

            # When module require License Acceptance, or repository is Untrusted.
            # `-Force` is mandatory to skip interactive prompt
            $psgetModuleInfo = Find-Module @ht
            if (($psgetModuleInfo.AdditionalMetadata.requireLicenseAcceptance -eq "True") -or
                ((Get-PSRepository -Name $psgetModuleInfo.Repository).InstallationPolicy -eq "Untrusted")) {
                $ht["Force"] = $true
            }
            else {
                $ht["Force"] = $Force
            }

            $ht = $ht + @{
                WhatIf = $CheckMode
                AcceptLicense = $AcceptLicense
            }

            [String[]]$ParametersNames = @("AllowClobber", "SkipPublisherCheck")
            $ht = Add-DefinedParameter -Hashtable $ht -ParametersNames $ParametersNames

            Install-Module @ht -ErrorVariable ErrorDetails | Out-Null

            $result.changed = $true
            $result.output = "Module $($Name) installed"
        }
        catch [ System.Exception ] {
            $ErrorMessage = "Problems installing $($Name) module: $($_.Exception.Message)"
            Fail-Json $result $ErrorMessage
        }
    }
    else {
        $result.output = "Module $($Name) already present"
    }
}

Function Remove-PsModule {
    Param(
        [Parameter(Mandatory = $true)]
        [String]$Name,
        [String]$RequiredVersion,
        [String]$MinimumVersion,
        [String]$MaximumVersion,
        [Bool]$CheckMode
    )
    # If module is present, uninstalls it.
    if (Get-Module -ListAvailable | Where-Object { $_.name -eq $Name }) {
        try {
            $ht = @{
                Name = $Name
                Confirm = $false
                Force = $true
            }

            $ExistingModuleBefore = Get-PsModule -Name $Name -RequiredVersion $RequiredVersion -MinimumVersion $MinimumVersion -MaximumVersion $MaximumVersion

            [String[]]$ParametersNames = @("RequiredVersion", "MinimumVersion", "MaximumVersion")

            $ht = Add-DefinedParameter -Hashtable $ht -ParametersNames $ParametersNames

            if ( -not ( $RequiredVersion -or $MinimumVersion -or $MaximumVersion ) ) {
                $ht.Add("AllVersions", $true)
            }

            if ( $ExistingModuleBefore.Exists) {
                # The Force parameter overwrite the WhatIf parameter
                if ( -not $CheckMode ) {
                    Uninstall-Module @ht -ErrorVariable ErrorDetails | Out-Null
                }
                $result.changed = $true
                $result.output = "Module $($Name) removed"
            }
        }
        catch [ System.Exception ] {
            $ErrorMessage = "Problems uninstalling $($Name) module: $($_.Exception.Message)"
            Fail-Json $result $ErrorMessage
        }
    }
    else {
        $result.output = "Module $($Name) removed"
    }
}

Function Find-LatestPsModule {
    Param(
        [Parameter(Mandatory = $true)]
        [String]$Name,
        [String]$Repository,
        [System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty,
        [Bool]$AllowPrerelease,
        [Bool]$CheckMode
    )

    try {
        $ht = @{
            Name = $Name
        }

        [String[]]$ParametersNames = @("AllowPrerelease", "Repository", "Credential")

        $ht = Add-DefinedParameter -Hashtable $ht -ParametersNames $ParametersNames

        $LatestModule = Find-Module @ht | Select-Object Version
    }
    catch [ System.Exception ] {
        $ErrorMessage = "Cant find the module $($Name): $($_.Exception.Message)"
        Fail-Json $result $ErrorMessage
    }

    if ( $LatestModule.Version.GetType().FullName -eq 'System.Object[]' ) {
        $ErrorMessage = "The module $Name exists in multiple repositories. Define a repository."
        Fail-Json $result $ErrorMessage
    }

    $LatestModule
}

# Check PowerShell version, fail if < 5.0 and required modules are not installed
$PsVersion = $PSVersionTable.PSVersion
if ($PsVersion.Major -lt 5 ) {
    $PrereqModulesInstalled = Install-PrereqModule -TestInstallationOnly
    if ( -not $PrereqModulesInstalled ) {
        $ErrorMessage = -join @(
            "Modules PowerShellGet and PackageManagement in versions 1.6.0 and 1.1.7 respectively "
            "have to be installed before using the win_psmodule."
        )
        Fail-Json $result $ErrorMessage
    }
}

if ( $required_version -and ( $minimum_version -or $maximum_version ) ) {
    $ErrorMessage = "Parameters required_version and minimum/maximum_version are mutually exclusive."
    Fail-Json $result $ErrorMessage
}

if ( $allow_prerelease -and ( $minimum_version -or $maximum_version ) ) {
    $ErrorMessage = "Parameters minimum_version, maximum_version can't be used with the parameter allow_prerelease."
    Fail-Json $result $ErrorMessage
}

if ( $allow_prerelease -and $state -eq "absent" ) {
    $ErrorMessage = "The parameter allow_prerelease can't be used with state set to 'absent'."
    Fail-Json $result $ErrorMessage
}

if ( ($state -eq "latest") -and
    ( $required_version -or $minimum_version -or $maximum_version ) ) {
    $ErrorMessage = "When the parameter state is equal to 'latest' you can't use any of required_version, minimum_version, maximum_version."
    Fail-Json $result $ErrorMessage
}

if ( $repo ) {
    $RepositoryExists = Get-PSRepository -Name $repo -ErrorAction SilentlyContinue
    if ( $null -eq $RepositoryExists) {
        $ErrorMessage = "The repository $repo doesn't exist."
        Fail-Json $result $ErrorMessage
    }

}

if ($repo_user -and $repo_pass ) {
    $repo_credential = New-Object -TypeName PSCredential ($repo_user, ($repo_pass | ConvertTo-SecureString -AsPlainText -Force))
}

if ( ($allow_clobber -or $allow_prerelease -or $skip_publisher_check -or
        $required_version -or $minimum_version -or $maximum_version -or $accept_license) ) {
    # Update the PowerShellGet and PackageManagement modules.
    # It's required to support AllowClobber, AllowPrerelease parameters.
    # This must occur before PackageManagement or PowerShellGet is imported in
    # the current process.
    Install-PrereqModule -AllowClobber $allow_clobber -CheckMode $check_mode -AcceptLicense $accept_license -Repository $repo
}

Import-Module -Name PackageManagement, PowerShellGet -Force

if ($state -eq "present") {
    if ($name) {
        $ht = @{
            Name = $name
            RequiredVersion = $required_version
            MinimumVersion = $minimum_version
            MaximumVersion = $maximum_version
            Repository = $repo
            AllowClobber = $allow_clobber
            SkipPublisherCheck = $skip_publisher_check
            AllowPrerelease = $allow_prerelease
            CheckMode = $check_mode
            Credential = $repo_credential
            AcceptLicense = $accept_license
            Force = $force
        }
        Install-PsModule @ht
    }
}
elseif ($state -eq "absent") {
    if ($name) {
        $ht = @{
            Name = $Name
            CheckMode = $check_mode
            RequiredVersion = $required_version
            MinimumVersion = $minimum_version
            MaximumVersion = $maximum_version
        }
        Remove-PsModule @ht
    }
}
elseif ( $state -eq "latest") {

    $ht = @{
        Name = $Name
        AllowPrerelease = $allow_prerelease
        Repository = $repo
        CheckMode = $check_mode
        Credential = $repo_credential
    }

    $LatestModule = Find-LatestPsModule @ht

    $ExistingModule = Get-PsModule $Name

    if ( ($LatestModule.Version -ne $ExistingModule.Version) -or $force ) {

        $ht = @{
            Name = $Name
            RequiredVersion = $LatestModule.Version
            Repository = $repo
            AllowClobber = $allow_clobber
            SkipPublisherCheck = $skip_publisher_check
            AllowPrerelease = $allow_prerelease
            CheckMode = $check_mode
            Credential = $repo_credential
            AcceptLicense = $accept_license
            Force = $force
        }
        Install-PsModule @ht
    }
}

Exit-Json $result
