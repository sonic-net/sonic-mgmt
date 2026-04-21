#!powershell

# Copyright (c) 2022 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic

$spec = @{
    options = @{
        create_dns_delegation = @{
            type = 'bool'
        }
        database_path = @{
            type = 'path'
        }
        dns_domain_name = @{
            required = $true
            type = 'str'
        }
        domain_mode = @{
            type = 'str'
        }
        domain_netbios_name = @{
            type = 'str'
        }
        forest_mode = @{
            type = 'str'
        }
        install_dns = @{
            default = $true
            type = 'bool'
        }
        log_path = @{
            type = 'path'
        }
        reboot = @{
            default = $false
            type = 'bool'
        }
        reboot_timeout = @{
            default = 600
            type = 'int'
        }
        safe_mode_password = @{
            no_log = $true
            required = $true
            type = 'str'
        }
        sysvol_path = @{
            type = 'path'
        }
    }
    supports_check_mode = $true
}
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$module.Result.reboot_required = $false
$module.Result._do_action_reboot = $false  # Used by action plugin

$create_dns_delegation = $module.Params.create_dns_delegation
$database_path = $module.Params.database_path
$dns_domain_name = $module.Params.dns_domain_name
$domain_mode = $module.Params.domain_mode
$domain_netbios_name = $module.Params.domain_netbios_name
$forest_mode = $module.Params.forest_mode
$install_dns = $module.Params.install_dns
$log_path = $module.Params.log_path
$safe_mode_password = $module.Params.safe_mode_password
$sysvol_path = $module.Params.sysvol_path

if ([System.Environment]::OSVersion.Version -lt [Version]"6.2") {
    $module.FailJson("microsoft.ad.domain requires Windows Server 2012 or higher")
}

if ($domain_netbios_name -and $domain_netbios_name.Length -gt 15) {
    $module.FailJson("The parameter 'domain_netbios_name' should not exceed 15 characters in length")
}

$requiredFeatures = @("AD-Domain-Services", "RSAT-ADDS")
$features = Get-WindowsFeature -Name $requiredFeatures
$unavailableFeatures = Compare-Object -ReferenceObject $requiredFeatures -DifferenceObject $features.Name -PassThru

if ($unavailableFeatures) {
    $module.FailJson("The following features required for a domain controller are unavailable: $($unavailableFeatures -join ',')")
}

$missingFeatures = $features | Where-Object InstallState -NE Installed
if ($missingFeatures) {
    $res = Install-WindowsFeature -Name $missingFeatures -WhatIf:$module.CheckMode
    $module.Result.changed = $true
    $module.Result.reboot_required = [bool]$res.RestartNeeded

    # When in check mode and the prereq was "installed" we need to exit early as
    # the AD cmdlets weren't really installed
    if ($module.CheckMode) {
        $module.ExitJson()
    }
}

# Check that we got a valid domain_mode
$validDomainModes = [Enum]::GetNames((Get-Command -Name Install-ADDSForest).Parameters.DomainMode.ParameterType)
if (($null -ne $domain_mode) -and -not ($domain_mode -in $validDomainModes)) {
    $validModes = $validDomainModes -join ", "
    $module.FailJson("The parameter 'domain_mode' does not accept '$domain_mode', please use one of: $validModes")
}

# Check that we got a valid forest_mode
$validForestModes = [Enum]::GetNames((Get-Command -Name Install-ADDSForest).Parameters.ForestMode.ParameterType)
if (($null -ne $forest_mode) -and -not ($forest_mode -in $validForestModes)) {
    $validModes = $validForestModes -join ", "
    $module.FailJson("The parameter 'forest_mode' does not accept '$forest_mode', please use one of: $validModes")
}

try {
    $forestContext = New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext -ArgumentList @(
        'Forest', $dns_domain_name
    )
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($forestContext)
}
catch [System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException] {
    $forest = $null
}
catch [System.DirectoryServices.ActiveDirectory.ActiveDirectoryOperationException] {
    $forest = $null
}

if (-not $forest) {
    $installParams = @{
        DomainName = $dns_domain_name
        SafeModeAdministratorPassword = (ConvertTo-SecureString $safe_mode_password -AsPlainText -Force)
        Confirm = $false
        SkipPreChecks = $true
        InstallDns = $install_dns
        NoRebootOnCompletion = $true
        WhatIf = $module.CheckMode
    }

    if ($database_path) {
        $installParams.DatabasePath = $database_path
    }

    if ($sysvol_path) {
        $installParams.SysvolPath = $sysvol_path
    }

    if ($log_path) {
        $installParams.LogPath = $log_path
    }

    if ($domain_netbios_name) {
        $installParams.DomainNetBiosName = $domain_netbios_name
    }

    if ($null -ne $create_dns_delegation) {
        $installParams.CreateDnsDelegation = $create_dns_delegation
    }

    if ($domain_mode) {
        $installParams.DomainMode = $domain_mode
    }

    if ($forest_mode) {
        $installParams.ForestMode = $forest_mode
    }

    $res = $null
    try {
        $res = Install-ADDSForest @installParams
    }
    catch [Microsoft.DirectoryServices.Deployment.DCPromoExecutionException] {
        # ExitCode 15 == 'Role change is in progress or this computer needs to be restarted.'
        # DCPromo exit codes details can be found at
        # https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/troubleshooting-domain-controller-deployment
        if ($_.Exception.ExitCode -in @(15, 19)) {
            $module.Result.reboot_required = $true
            $module.Result._do_action_reboot = $true
        }

        $module.FailJson("Failed to install ADDSForest, DCPromo exited with $($_.Exception.ExitCode): $($_.Exception.Message)", $_)
    }
    finally {
        # The Netlogon service is set to auto start but is not started. This is
        # required for Ansible to connect back to the host and reboot in a
        # later task. Even if this fails Ansible can still connect but only
        # with ansible_winrm_transport=basic so we just display a warning if
        # this fails.
        if (-not $module.CheckMode) {
            try {
                Start-Service -Name Netlogon
            }
            catch {
                $msg = -join @(
                    "Failed to start the Netlogon service after promoting the host, "
                    "Ansible may be unable to connect until the host is manually rebooting: $($_.Exception.Message)"
                )
                $module.Warn($msg)
            }
        }
    }

    $module.Result.changed = $true

    if ($module.CheckMode) {
        # the return value after -WhatIf does not have RebootRequired populated
        # manually set to True as the domain would have been installed
        $module.Result.reboot_required = $true
    }
    elseif ($res.RebootRequired) {
        $module.Result.reboot_required = $true
    }
}

$module.ExitJson()
