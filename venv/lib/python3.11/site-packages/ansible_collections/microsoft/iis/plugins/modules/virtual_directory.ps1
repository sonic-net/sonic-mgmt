#!powershell

# Copyright: (c) 2024, Hen Yaish <hyaish@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic

# Define the argument specification
$spec = @{
    options = @{
        name = @{ required = $true; type = "str" }
        site = @{ required = $true; type = "str" }
        application = @{ required = $false; type = "str" }
        physical_path = @{ required = $false; type = "str" }
        state = @{ required = $false; type = "str"; default = "present"; choices = @("present", "absent") }
        connect_as = @{ required = $false; type = "str"; choices = @("specific_user", "pass_through") }
        username = @{ type = "str" }
        password = @{ type = "str"; no_log = $true }
    }
    supports_check_mode = $true
}

# Create the module
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
$module.Result.changed = $false

# Retrieve parameters
$check_mode = $module.CheckMode
$name = $module.Params.name
$site = $module.Params.site
$application = $module.Params.application
$physical_path = $module.Params.physical_path
$state = $module.Params.state
$connect_as = $module.Params.connect_as
$username = $module.Params.username
$password = $module.Params.password

# Validate credentials if connect_as is specific_user
if ($connect_as -eq "specific_user") {
    if (-not $username -or -not $password) {
        if (-not $username -and -not $password) {
            $module.FailJson("Both username and password are required.")
        }
        elseif (-not $username) {
            $module.FailJson("Username is required.")
        }
        else {
            $module.FailJson("Password is required.")
        }
    }
}

# Ensure WebAdministration module is loaded
if ($null -eq (Get-Module "WebAdministration" -ErrorAction SilentlyContinue)) {
    Import-Module WebAdministration
}

# Construct the directory path
$directory_path = if ($application) {
    "IIS:\Sites\$($site)\$($application)\$($name)"
}
else {
    "IIS:\Sites\$($site)\$($name)"
}

try {
    # Add or Update directory
    if ($state -eq "present") {
        if (-not $physical_path) {
            $module.FailJson("missing required arguments: physical_path")
        }
        if (-not (Test-Path -LiteralPath $physical_path)) {
            $module.FailJson("specified folder must already exist: '$physical_path'")
        }

        $existing_directory = if ($application) {
            Get-WebVirtualDirectory -Site $site -Name $name -Application $application -ErrorAction SilentlyContinue
        }
        else {
            Get-WebVirtualDirectory -Site $site -Name $name -ErrorAction SilentlyContinue
        }

        if (-not $existing_directory) {
            $directory_parameters = @{
                Site = $site
                Name = $name
                PhysicalPath = $physical_path
            }
            if ($application) {
                $directory_parameters.Application = $application
            }
            if (-not $check_mode) {
                New-WebVirtualDirectory @directory_parameters -Force | Out-Null
            }
            $module.Result.changed = $true
        }
        else {
            # Handle updates
            $existing_physical_path = $existing_directory.PhysicalPath
            if ($existing_physical_path -ne $physical_path) {
                Set-ItemProperty -LiteralPath $directory_path -Name "PhysicalPath" -Value $physical_path -WhatIf:$check_mode
                $module.Result.changed = $true
            }

            if ($connect_as -eq "specific_user") {
                if ($existing_directory.username -ne $username) {
                    Set-ItemProperty -LiteralPath $directory_path -Name "userName" -Value $username -WhatIf:$check_mode
                    $module.Result.changed = $true
                }
                if ($existing_directory.password -ne $password) {
                    Set-ItemProperty -LiteralPath $directory_path -Name "password" -Value $password -WhatIf:$check_mode
                    $module.Result.changed = $true
                }
            }
            elseif ($connect_as -eq "pass_through") {
                if ($existing_directory.username) {
                    Clear-ItemProperty -LiteralPath $directory_path -Name "userName" -ErrorAction SilentlyContinue -WhatIf:$check_mode
                    $module.Result.changed = $true
                }
                if ($existing_directory.password) {
                    Clear-ItemProperty -LiteralPath $directory_path -Name "password" -ErrorAction SilentlyContinue -WhatIf:$check_mode
                    $module.Result.changed = $true
                }
            }
        }
    }
    elseif ($state -eq "absent") {
        if (Test-Path -LiteralPath $directory_path) {
            Remove-Item -LiteralPath $directory_path -Recurse -Force -WhatIf:$check_mode
            $module.Result.changed = $true
        }
    }
}
catch {
    $module.FailJson($_.Exception.Message, $_)
}

$module.ExitJson()