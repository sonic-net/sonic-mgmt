#!powershell

# Copyright (c) 2024 Ansible Project
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
            type = 'str'
        }
        domain_admin_password = @{
            type = 'str'
            required = $true
            no_log = $true
        }
        domain_admin_user = @{
            type = 'str'
            required = $true
        }
        domain_mode = @{
            type = 'str'
        }
        domain_type = @{
            choices = 'child', 'tree'
            default = 'child'
            type = 'str'
        }
        install_dns = @{
            type = 'bool'
        }
        log_path = @{
            type = 'path'
        }
        parent_domain_name = @{
            type = 'str'
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
            type = 'str'
            required = $true
            no_log = $true
        }
        site_name = @{
            type = 'str'
        }
        sysvol_path = @{
            type = 'path'
        }
    }
    required_if = @(
        , @('domain_type', 'tree', @('parent_domain_name'))
    )
    required_together = @(
        , @("domain_admin_user", "domain_admin_password")
    )
    supports_check_mode = $true
}
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$module.Result.reboot_required = $false
$module.Result._do_action_reboot = $false  # Used by action plugin

$createDnsDelegation = $module.Params.create_dns_delegation
$databasePath = $module.Params.database_path
$dnsDomainName = $module.Params.dns_domain_name
$domainMode = $module.Params.domain_mode
$domainType = $module.Params.domain_type
$installDns = $module.Params.install_dns
$logPath = $module.Params.log_path
$parentDomainName = $module.Params.parent_domain_name
$replicationSourceDC = $module.Params.replication_source_dc
$safeModePassword = $module.Params.safe_mode_password
$siteName = $module.Params.site_name
$sysvolPath = $module.Params.sysvol_path

$domainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @(
    $module.Params.domain_admin_user,
    (ConvertTo-SecureString -AsPlainText -Force -String $module.Params.domain_admin_password)
)

if ($domainType -eq 'child' -and $parentDomainName) {
    $module.FailJson("parent_domain_name must not be set when domain_type=child")
}

$requiredFeatures = @("AD-Domain-Services", "RSAT-ADDS")
$features = Get-WindowsFeature -Name $requiredFeatures
$unavailableFeatures = Compare-Object -ReferenceObject $requiredFeatures -DifferenceObject $features.Name -PassThru

if ($unavailableFeatures) {
    $module.FailJson("The following features required for a domain child are unavailable: $($unavailableFeatures -join ',')")
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
$validDomainModes = [Enum]::GetNames((Get-Command -Name Install-ADDSDomain).Parameters.DomainMode.ParameterType)
if (($null -ne $domainMode) -and -not ($domainMode -in $validDomainModes)) {
    $validModes = $validDomainModes -join ", "
    $module.FailJson("The parameter 'domain_mode' does not accept '$domainMode', please use one of: $validModes")
}

$systemRole = Get-CimInstance -ClassName Win32_ComputerSystem -Property Domain, DomainRole
if ($systemRole.DomainRole -in @(4, 5)) {
    if ($systemRole.Domain -ne $dnsDomainName) {
        $module.FailJson("Host is already a domain controller in another domain $($systemRole.Domain)")
    }
    $module.ExitJson()
}

$installParams = @{
    Confirm = $false
    Credential = $domainCredential
    Force = $true
    NoRebootOnCompletion = $true
    SafeModeAdministratorPassword = (ConvertTo-SecureString $safeModePassword -AsPlainText -Force)
    SkipPreChecks = $true
    WhatIf = $module.CheckMode
}

if ($domainType -eq 'child') {
    $newDomainName, $parentDomainName = $dnsDomainName.Split([char[]]".", 2)
    $installParams.DomainType = 'ChildDomain'
    $installParams.NewDomainName = $newDomainName
    $installParams.ParentDomainName = $parentDomainName
}
else {
    $installParams.DomainType = 'TreeDomain'
    $installParams.NewDomainName = $dnsDomainName
    $installParams.ParentDomainName = $parentDomainName
}

if ($null -ne $createDnsDelegation) {
    $installParams.CreateDnsDelegation = $createDnsDelegation
}
if ($databasePath) {
    $installParams.DatabasePath = $databasePath
}
if ($domainMode) {
    $installParams.DomainMode = $domainMode
}
if ($null -ne $installDns) {
    $installParams.InstallDns = $installDns
}
if ($logPath) {
    $installParams.LogPath = $logPath
}
if ($replicationSourceDC) {
    $installParams.ReplicationSourceDC = $replicationSourceDC
}
if ($siteName) {
    $installParams.SiteName = $siteName
}
if ($sysvolPath) {
    $installParams.SysvolPath = $sysvolPath
}

try {
    $null = Install-ADDSDomain @installParams
}
catch [Microsoft.DirectoryServices.Deployment.DCPromoExecutionException] {
    # ExitCode 15 == 'Role change is in progress or this computer needs to be restarted.'
    # DCPromo exit codes details can be found at
    # https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/troubleshooting-domain-controller-deployment
    if ($_.Exception.ExitCode -in @(15, 19)) {
        $module.Result.reboot_required = $true
        $module.Result._do_action_reboot = $true
    }

    $module.FailJson("Failed to install ADDSDomain, DCPromo exited with $($_.Exception.ExitCode)", $_)
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
                "Ansible may be unable to connect until the host is manually rebooted: $($_.Exception.Message)"
            )
            $module.Warn($msg)
        }
    }
}

$module.Result.changed = $true
$module.Result.reboot_required = $true

if ($module.Result.reboot_required -and $module.Params.reboot -and -not $module.CheckMode) {
    # Promoting or depromoting puts the server in a very funky state and it may
    # not be possible for Ansible to connect back without a reboot is done. If
    # the user requested the action plugin to perform the reboot then start it
    # here and get the action plugin to continue where this left off.

    $lastBootTime = (Get-CimInstance -ClassName Win32_OperatingSystem -Property LastBootUpTime).LastBootUpTime.ToFileTime()
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
