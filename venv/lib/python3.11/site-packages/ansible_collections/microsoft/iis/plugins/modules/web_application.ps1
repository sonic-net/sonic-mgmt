#!powershell

# Copyright: (c) 2015, Henrik Wallström <henrik@wallstroms.nu>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic

$spec = @{
    options = @{
        name = @{ type = "str"; required = $true }
        site = @{ type = "str"; required = $true }
        state = @{ type = "str"; default = "present"; choices = "absent", "present" }
        physical_path = @{ type = "str"; aliases = @("path") }
        application_pool = @{ type = "str" }
        connect_as = @{ type = "str"; choices = "specific_user", "pass_through" }
        username = @{ type = "str" }
        password = @{ type = "str"; no_log = $true }
    }
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
$name = $module.Params.name
$site = $module.Params.site
$state = $module.Params.state
$physical_path = $module.Params.physical_path
$application_pool = $module.Params.application_pool
$connect_as = $module.Params.connect_as
$username = $module.Params.username
$password = $module.Params.password
$check_mode = $module.CheckMode

if ($connect_as -eq 'specific_user') {
    if (-not $username) {
        $module.FailJson("missing required arguments: username")
    }
    if (-not $password) {
        $module.FailJson("missing required arguments: password")
    }
}

# Ensure WebAdministration module is loaded
if ($null -eq (Get-Module "WebAdministration" -ErrorAction SilentlyContinue)) {
    Import-Module WebAdministration
}

# Application info
$application = Get-WebApplication -Site $site -Name $name
$website = Get-Website -Name $site

# Set ApplicationPool to current if not specified
if (!$application_pool) {
    $application_pool = $website.applicationPool
}

try {
    # Add application
    if (($state -eq 'present') -and (-not $application)) {
        if (-not $physical_path) {
            $module.FailJson("missing required arguments: physical_path")
        }
        if (-not (Test-Path -LiteralPath $physical_path)) {
            $module.FailJson("specified folder must already exist: '$physical_path'")
        }

        $application_parameters = @{
            Name = $name
            PhysicalPath = $physical_path
            Site = $site
            ApplicationPool = $application_pool
        }

        if (-not $check_mode) {
            $application = New-WebApplication @application_parameters -Force
        }
        $module.Result.changed = $true
    }

    # Remove application
    if ($state -eq 'absent' -and $application) {
        $application = Remove-WebApplication -Site $site -Name $name -WhatIf:$check_mode
        $module.Result.changed = $true
    }

    $application = Get-WebApplication -Site $site -Name $name
    if ($application) {

        # Change Physical Path if needed
        if ($physical_path) {
            if (-not (Test-Path -LiteralPath $physical_path)) {
                $module.FailJson("specified folder must already exist: '$physical_path'")
            }

            $folder = Get-Item -LiteralPath $physical_path
            if ($folder.FullName -ne $application.PhysicalPath) {
                Set-ItemProperty -LiteralPath "IIS:\Sites\$($site)\$($name)" -name physicalPath -value $physical_path -WhatIf:$check_mode
                $module.Result.changed = $true
            }
        }

        # Change Application Pool if needed
        if ($application_pool) {
            if ($application_pool -ne $application.applicationPool) {
                Set-ItemProperty -LiteralPath "IIS:\Sites\$($site)\$($name)" -name applicationPool -value $application_pool -WhatIf:$check_mode
                $module.Result.changed = $true
            }
        }

        # Change username and password if needed
        $app_user = Get-ItemProperty -LiteralPath "IIS:\Sites\$($site)\$($name)" -Name 'userName'
        $app_pass = Get-ItemProperty -LiteralPath "IIS:\Sites\$($site)\$($name)" -Name 'password'
        if ($connect_as -eq 'pass_through') {
            if ($app_user -ne '') {
                Clear-ItemProperty -LiteralPath "IIS:\Sites\$($site)\$($name)" -Name 'userName' -WhatIf:$check_mode
                $module.Result.changed = $true
            }
            if ($app_pass -ne '') {
                Clear-ItemProperty -LiteralPath "IIS:\Sites\$($site)\$($name)" -Name 'password' -WhatIf:$check_mode
                $module.Result.changed = $true
            }
        }
        elseif ($connect_as -eq 'specific_user') {
            if ($app_user -ne $username) {
                Set-ItemProperty -LiteralPath "IIS:\Sites\$($site)\$($name)" -Name 'userName' -Value $username -WhatIf:$check_mode
                $module.Result.changed = $true
            }
            if ($app_pass -ne $password) {
                Set-ItemProperty -LiteralPath "IIS:\Sites\$($site)\$($name)" -Name 'password' -Value $password -WhatIf:$check_mode
                $module.Result.changed = $true
            }
        }
    }
}
catch {
    $module.FailJson($_.Exception.Message, $_)
}

$module.ExitJson()
