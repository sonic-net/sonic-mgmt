#!powershell

# Copyright: (c) 2025, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic

# Define Bindings Options
$binding_options = @{
    type = 'list'
    elements = 'dict'
    options = @{
        ip = @{ type = 'str' }
        port = @{ type = 'int' }
        hostname = @{ type = 'str' }
        protocol = @{ type = 'str' ; default = 'http' ; choices = @('http', 'https') }
        use_sni = @{ type = 'bool' }
        use_ccs = @{ type = 'bool' }
        certificate_hash = @{ type = 'str' }
        certificate_store_name = @{ type = 'str'; default = "my" }
    }
}

$spec = @{
    options = @{
        name = @{
            required = $true
            type = "str"
        }
        state = @{
            type = "str"
            default = "started"
            choices = @("absent", "restarted", "started", "stopped")
        }
        site_id = @{
            type = "str"
        }
        application_pool = @{
            type = "str"
        }
        physical_path = @{
            type = "str"
        }
        bindings = @{
            default = @{}
            type = 'dict'
            options = @{
                add = $binding_options
                set = $binding_options
                remove = @{
                    type = 'list'
                    elements = 'dict'
                    options = @{
                        ip = @{ type = 'str' }
                        port = @{ type = 'int' }
                        hostname = @{ type = 'str' }
                    }
                }
            }
            mutually_exclusive = @(
                , @('set', 'add')
                , @('set', 'remove')
            )
        }
    }
    supports_check_mode = $true
}
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$name = $module.Params.name
$state = $module.Params.state
$site_id = $module.Params.site_id
$application_pool = $module.Params.application_pool
$physical_path = $module.Params.physical_path
$bindings = $module.Params.bindings

$check_mode = $module.CheckMode
$module.Result.changed = $false

function Get-SSLFlagFromBinding {
    param (
        [Parameter(Mandatory = $true)]
        $BindingInfo
    )
    $ssl_flags = 0
    # Check for use_sni
    if ($BindingInfo.use_sni) {
        If ($BindingInfo.protocol -ne 'https') {
            $module.FailJson("use_sni can only be set for https protocol")
        }
        If (-Not $BindingInfo.hostname) {
            $module.FailJson("must specify hostname value when use_sni is set.")
        }
        $ssl_flags += 1
    }
    # Check for use_ccs
    if ($BindingInfo.use_ccs) {
        If ($BindingInfo.protocol -ne 'https') {
            $module.FailJson("use_ccs can only be set for https protocol")
        }
        If (-Not $BindingInfo.hostname) {
            $module.FailJson("must specify hostname value when use_ccs is set.")
        }
        If ($BindingInfo.certificate_hash) {
            $module.FailJson("You set use_ccs to $($BindingInfo.use_ccs).
            This indicates you wish to use the Central Certificate Store feature.
            This cannot be used in combination with certficiate_hash and certificate_store_name. When using the Central Certificate Store feature,
            the certificate is automatically retrieved from the store rather than manually assigned to the binding.")
        }
        $ssl_flags += 2
    }
    # Validate protocol is https and either use_ccs or certificate_hash is set
    If ($BindingInfo.protocol -eq 'https') {
        if (-Not $BindingInfo.use_ccs -and -Not $BindingInfo.certificate_hash) {
            $module.FailJson("must either specify a certificate_hash or use_ccs.")
        }
    }
    # Validate certificate_hash
    If ($BindingInfo.certificate_hash) {
        If ($BindingInfo.protocol -ne 'https') {
            $module.FailJson("You can only provide a certificate thumbprint when protocol is set to https")
        }
        # Validate cert path
        $cert_path = "cert:\LocalMachine\$($BindingInfo.certificate_store_name)\$($BindingInfo.certificate_hash)"
        If (-Not (Test-Path -LiteralPath $cert_path)) {
            $module.FailJson("Unable to locate certificate at $cert_path")
        }
    }
    return $ssl_flags
}

# Ensure WebAdministration module is loaded
if ($null -eq (Get-Module "WebAdministration" -ErrorAction SilentlyContinue)) {
    Import-Module WebAdministration
}

# Site info
$site = Get-Website | Where-Object { $_.Name -eq $name }

Try {
    # Add site
    If (($state -ne 'absent') -and (-not $site)) {
        If (-not $physical_path) {
            $module.FailJson("missing required arguments: physical_path")
        }
        ElseIf (-not (Test-Path -LiteralPath $physical_path)) {
            $module.FailJson("specified folder must already exist: physical_path")
        }
        $site_parameters = @{
            Name = $name
            PhysicalPath = $physical_path
        }
        If ($application_pool) {
            $site_parameters.ApplicationPool = $application_pool
        }
        If ($site_id) {
            $site_parameters.ID = $site_id
        }
        # Fix for error "New-Item : Index was outside the bounds of the array."
        # This is a bug in the New-WebSite commandlet. Apparently there must be at least one site configured in IIS otherwise New-WebSite crashes.
        # For more details, see http://stackoverflow.com/questions/3573889/ps-c-new-website-blah-throws-index-was-outside-the-bounds-of-the-array
        $sites_list = Get-ChildItem -LiteralPath IIS:\sites
        if ($null -eq $sites_list) {
            if ($site_id) {
                $site_parameters.ID = $site_id
            }
            else {
                $site_parameters.ID = 1
            }
        }
        if ( -not $check_mode) {
            $site = New-Website @site_parameters -Force
        }
        # Verify that initial site has no binding
        Get-WebBinding -Name $site.Name | Remove-WebBinding -WhatIf:$check_mode
        $module.Result.changed = $true
    }
    # Remove site
    If ($state -eq 'absent' -and $site) {
        $site = Remove-Website -Name $name -WhatIf:$check_mode
        $module.Result.changed = $true
    }
    $site = Get-Website | Where-Object { $_.Name -eq $name }
    If ($site) {
        # Change Physical Path if needed
        if ($physical_path) {
            If (-not (Test-Path -LiteralPath $physical_path)) {
                $module.FailJson("specified folder must already exist: physical_path")
            }
            $folder = Get-Item -LiteralPath $physical_path
            If ($folder.FullName -ne $site.PhysicalPath) {
                Set-ItemProperty -LiteralPath "IIS:\Sites\$($site.Name)" -name physicalPath -value $folder.FullName -WhatIf:$check_mode
                $module.Result.changed = $true
            }
        }
        # Change Application Pool if needed
        if ($application_pool) {
            If ($application_pool -ne $site.applicationPool) {
                Set-ItemProperty -LiteralPath "IIS:\Sites\$($site.Name)" -name applicationPool -value $application_pool -WhatIf:$check_mode
                $module.Result.changed = $true
            }
        }
        # Add Remove or Set bindings if needed
        if ( $null -ne $bindings.set -or $bindings.add.Count -gt 0 -or $bindings.remove.Count -gt 0 ) {
            $site_bindings = (Get-ItemProperty -LiteralPath "IIS:\Sites\$($site.Name)").Bindings.Collection
            $toAdd = @()
            $toEdit = @()
            $toRemove = @()
            if ($null -ne $bindings.set) {
                $toAdd = $bindings.set | Where-Object { -not ($site_bindings.bindingInformation -contains "$($_.ip):$($_.port):$($_.hostname)") }
                $toEdit = $bindings.set | Where-Object { ($site_bindings.bindingInformation -contains "$($_.ip):$($_.port):$($_.hostname)") }
                $user_bindings = $bindings.set | ForEach-Object { "$($_.ip):$($_.port):$($_.hostname)" }
                if ($null -ne $site_bindings.bindingInformation) {
                    $toRemove = $site_bindings.bindingInformation | Where-Object { $_ -notin $user_bindings }
                }
            }
            else {
                if ($bindings.add) {
                    $toAdd = $bindings.add | Where-Object { -not ($site_bindings.bindingInformation -contains "$($_.ip):$($_.port):$($_.hostname)") }
                    $toEdit = $bindings.add | Where-Object { ($site_bindings.bindingInformation -contains "$($_.ip):$($_.port):$($_.hostname)") }
                }
                if ($bindings.remove) {
                    $user_bindings = $bindings.remove | ForEach-Object { "$($_.ip):$($_.port):$($_.hostname)" }
                    $toRemove = $site_bindings.bindingInformation | Where-Object { $_ -in $user_bindings }
                }
            }
            $toAdd | ForEach-Object {
                $ssl_flags = Get-SSLFlagFromBinding -BindingInfo $_
                if (-not $check_mode) {
                    New-WebBinding -Name $site.Name -IPAddress $_.ip -Port $_.port -HostHeader $_.hostname -Protocol $_.protocol -SslFlags $ssl_flags
                    If ($_.certificate_hash) {
                        $new_binding = Get-WebBinding -Name $site.Name -IPAddress $_.ip -Port $_.port -HostHeader $_.hostname
                        $new_binding.AddSslCertificate($_.certificate_hash, $_.certificate_store_name)
                    }
                }
                $module.Result.changed = $true
            }
            $toEdit | ForEach-Object {
                $user_edit = $_
                $site_edit = $site_bindings | Where-Object { $_.bindingInformation -eq "$($user_edit.ip):$($user_edit.port):$($user_edit.hostname)" }
                $binding_index = $site_bindings.IndexOf($site_edit)
                # Get existing use_sni value from site if null
                if ($null -eq $user_edit.use_sni) {
                    $user_edit.use_sni = $site_edit.sslFlags % 2
                }
                # Get existing use_ccs value from site if null
                if ($null -eq $user_edit.use_ccs) {
                    $user_edit.use_ccs = [math]::Floor($site_edit.sslFlags / 2)
                }
                $ssl_flags = Get-SSLFlagFromBinding -BindingInfo $user_edit
                if ($site_edit.protocol -ne $user_edit.protocol) {
                    Set-ItemProperty -LiteralPath "IIS:\Sites\$($site.Name)" -Name "Bindings.Collection[$binding_index].protocol"`
                        -value $user_edit.protocol -WhatIf:$check_mode
                    $module.Result.changed = $true
                }
                if ($site_edit.sslFlags -ne $ssl_flags) {
                    Set-ItemProperty -LiteralPath "IIS:\Sites\$($site.Name)" -Name "Bindings.Collection[$binding_index].sslFlags"`
                        -value $ssl_flags -WhatIf:$check_mode
                    $module.Result.changed = $true
                }
                If ($user_edit.certificate_hash) {
                    $edit_binding = Get-WebBinding -Name $site.Name -IPAddress $user_edit.ip -Port $user_edit.port -HostHeader $user_edit.hostname
                    $edit_binding.AddSslCertificate($user_edit.certificate_hash, $user_edit.certificate_store_name)
                }
            }
            $toRemove | ForEach-Object {
                $remove_binding = $_ -split ':'
                Get-WebBinding -Name $site.Name -IPAddress $remove_binding[0] -Port $remove_binding[1]`
                    -HostHeader $remove_binding[2] | Remove-WebBinding -WhatIf:$check_mode
                $module.Result.changed = $true
            }
        }
        # Set run state
        if ((($state -eq 'stopped') -or ($state -eq 'restarted')) -and ($site.State -eq 'Started')) {
            if (-not $check_mode) {
                Stop-Website -Name $name -ErrorAction Stop
            }
            $module.Result.changed = $true
        }
        if ((($state -eq 'started') -and ($site.State -eq 'Stopped')) -or ($state -eq 'restarted')) {
            if (-not $check_mode) {
                Start-Website -Name $name -ErrorAction Stop
            }
            $module.Result.changed = $true
        }
    }
}
Catch {
    $module.FailJson("$($module.Result) - $($_.Exception.Message)", $_)
}

$module.ExitJson()
