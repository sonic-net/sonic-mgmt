#!powershell

# Copyright (c) 2022 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic

$spec = @{
    options = @{
        database_path = @{
            type = 'path'
        }
        dns_domain_name = @{
            type = 'str'
        }
        domain_admin_password = @{
            no_log = $true
            required = $true
            type = 'str'
        }
        domain_admin_user = @{
            required = $true
            type = 'str'
        }
        domain_log_path = @{
            # FUTURE: Add alias for log_path once some time has passed
            type = 'path'
        }
        install_dns = @{
            type = 'bool'
        }
        install_media_path = @{
            type = 'path'
        }
        local_admin_password = @{
            no_log = $true
            type = 'str'
        }
        read_only = @{
            default = $false
            type = 'bool'
        }
        reboot = @{
            default = $false
            type = 'bool'
        }
        reboot_timeout = @{
            default = 600
            type = 'int'
        }
        replication_source_dc = @{
            type = 'str'
        }
        safe_mode_password = @{
            no_log = $true
            type = 'str'
        }
        site_name = @{
            type = 'str'
        }
        state = @{
            choices = 'domain_controller', 'member_server'
            required = $true
            type = 'str'
        }
        sysvol_path = @{
            type = 'path'
        }
    }
    required_if = @(
        , @('state', 'domain_controller', @('dns_domain_name', 'safe_mode_password'))
        , @('state', 'member_server', @(, 'local_admin_password'))
    )
    supports_check_mode = $true
}
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$module.Result.reboot_required = $false
$module.Result._do_action_reboot = $false  # Used by action plugin

$databasePath = $module.Params.database_path
$dnsDomainName = $module.Params.dns_domain_name
$installDns = $module.Params.install_dns
$installMediaPath = $module.Params.install_media_path
$logPath = $module.Params.domain_log_path
$readOnly = $module.Params.read_only
$replicationSourceDC = $module.Params.replication_source_dc
$siteName = $module.Params.site_name
$state = $module.Params.state
$sysvolPath = $module.Params.sysvol_path

$domainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @(
    $module.Params.domain_admin_user,
    (ConvertTo-SecureString -AsPlainText -Force -String $module.Params.domain_admin_password)
)

if ([System.Environment]::OSVersion.Version -lt [Version]"6.2") {
    $module.FailJson("microsoft.ad.domain_controller requires Windows Server 2012 or higher")
}

# short-circuit "member server" check, since we don't need feature checks for this...
# role 4/5 - backup/primary DC
$win32CS = Get-CimInstance -ClassName Win32_ComputerSystem -Property Domain, DomainRole
$isKdc = $win32CS.DomainRole -in @(4, 5)
If ($state -eq "member_server" -and -not $isKdc) {
    $module.ExitJson()
}

# all other operations will require the AD-DS and RSAT-ADDS features...
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

$lastBootTime = (Get-CimInstance -ClassName Win32_OperatingSystem -Property LastBootUpTime).LastBootUpTime.ToFileTime()

if ($state -eq 'domain_controller') {
    # ensure that domain admin user is in UPN or down-level domain format (prevent hang from https://support.microsoft.com/en-us/kb/2737935)
    If (-not $domainCredential.UserName.Contains("\") -and -not $domainCredential.UserName.Contains("@")) {
        $module.FailJson("domain_admin_user must be in domain\user or user@domain.com format")
    }

    If ($isKdc) {
        # FUTURE: implement managed Remove/Add to change domains?
        If ($dnsDomainName -ne $win32CS.Domain) {
            $msg = -join @(
                "The host $env:COMPUTERNAME is a domain controller for the domain $($win32CS.Domain); "
                "changing DC domains is not implemented"
            )
            $module.FailJson($msg)
        }
    }
    else {
        $safeModePassword = $module.Params.safe_mode_password | ConvertTo-SecureString -AsPlainText -Force

        $installParams = @{
            Confirm = $false
            Credential = $domainCredential
            DomainName = $dnsDomainName
            Force = $true
            NoRebootOnCompletion = $true
            SafeModeAdministratorPassword = $safeModePassword
            SkipPreChecks = $true
            WhatIf = $module.CheckMode
        }
        if ($databasePath) {
            $installParams.DatabasePath = $databasePath
        }
        if ($logPath) {
            $installParams.LogPath = $logPath
        }
        if ($sysvolPath) {
            $installParams.SysvolPath = $sysvolPath
        }
        if ($installMediaPath) {
            $installParams.InstallationMediaPath = $installMediaPath
        }
        if ($readOnly) {
            # while this is a switch value, if we set on $false site_name is required
            # https://github.com/ansible/ansible/issues/35858
            $installParams.ReadOnlyReplica = $true
        }
        if ($replicationSourceDC) {
            $installParams.ReplicationSourceDC = $replicationSourceDC
        }
        if ($siteName) {
            $installParams.SiteName = $siteName
        }
        if ($null -ne $installDns) {
            $installParams.InstallDns = $installDns
        }

        try {
            $null = Install-ADDSDomainController @installParams
        }
        catch [Microsoft.DirectoryServices.Deployment.DCPromoExecutionException] {
            # ExitCode 15 == 'Role change is in progress or this computer needs to be restarted.'
            # DCPromo exit codes details can be found at
            # https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/troubleshooting-domain-controller-deployment
            if ($_.Exception.ExitCode -in @(15, 19)) {
                $module.Result.reboot_required = $true
                $module.Result._do_action_reboot = $true
            }

            $module.FailJson("Failed to install ADDSDomainController, DCPromo exited with $($_.Exception.ExitCode): $($_.Exception.Message)", $_)
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
        $module.Result.reboot_required = $true
    }
}
else {
    # at this point we already know we're a DC and shouldn't be (due to short circuit check)...
    $assignedRoles = @((Get-ADDomainController -Server localhost).OperationMasterRoles)
    $localAdminPassword = $module.Params.local_admin_password | ConvertTo-SecureString -AsPlainText -Force

    # FUTURE: figure out a sane way to hand off roles automatically (designated recipient server, randomly look one up?)
    If ($assignedRoles.Count -gt 0) {
        $msg = -join @(
            "This domain controller has operation master role(s) ({0}) assigned; they must be moved to other "
            "DCs before demotion (see Move-ADDirectoryServerOperationMasterRole)" -f ($assignedRoles -join ", ")
        )
        $module.FailJson($msg)
    }

    # While the cmdlet has -WhatIf, it doesn't seem to work properly. Only run
    # when not in check mode.
    if (-not $module.CheckMode) {
        $uninstallParams = @{
            Confirm = $false
            Credential = $domainCredential
            Force = $true
            LocalAdministratorPassword = $localAdminPassword
            NoRebootOnCompletion = $true
        }
        $null = Uninstall-ADDSDomainController @uninstallParams
    }

    $module.Result.changed = $true
    $module.Result.reboot_required = $true
}

if ($module.Result.reboot_required -and $module.Params.reboot -and -not $module.CheckMode) {
    # Promoting or depromoting puts the server in a very funky state and it may
    # not be possible for Ansible to connect back without a reboot is done. If
    # the user requested the action plugin to perform the reboot then start it
    # here and get the action plugin to continue where this left off.

    $module.Result._previous_boot_time = $lastBootTime

    $shutdownRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoLogonChecked'
    Remove-Item -LiteralPath $shutdownRegPath -Force -ErrorAction SilentlyContinue

    $comment = 'Reboot initiated by Ansible'
    $stdout = $null
    $stderr = . { shutdown.exe /r /t 10 /c $comment | Set-Variable stdout } 2>&1 | ForEach-Object ToString
    if ($LASTEXITCODE -eq 1190) {
        # A reboot was already scheduled, abort it and try again
        shutdown.exe /a
        $stdout = $null
        $stderr = . { shutdown.exe /r /t 10 /c $comment | Set-Variable stdout } 2>&1 | ForEach-Object ToString
    }

    if ($LASTEXITCODE) {
        $module.Result.rc = $LASTEXITCODE
        $module.Result.stdout = $stdout
        $module.Result.stderr = $stderr
        $module.FailJson("Failed to initiate reboot, see rc, stdout, stderr for more information")
    }
}

$module.ExitJson()
