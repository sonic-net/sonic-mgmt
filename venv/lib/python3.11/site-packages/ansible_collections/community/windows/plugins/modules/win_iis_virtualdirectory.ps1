#!powershell

# Copyright: (c) 2015, Henrik Wallström <henrik@wallstroms.nu>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#Requires -Module Ansible.ModuleUtils.Legacy

$ErrorActionPreference = "Stop"

$params = Parse-Args $args
$name = Get-AnsibleParam -obj $params -name "name" -type "str" -failifempty $true
$site = Get-AnsibleParam -obj $params -name "site" -type "str" -failifempty $true
$application = Get-AnsibleParam -obj $params -name "application" -type "str"
$physical_path = Get-AnsibleParam -obj $params -name "physical_path" -type "str"
$state = Get-AnsibleParam -obj $params -name "state" -type "str" -default "present" -validateset "absent", "present"
$connect_as = Get-AnsibleParam -obj $params -name 'connect_as' -type 'str' -validateset 'specific_user', 'pass_through'
$username = Get-AnsibleParam -obj $params -name "username" -type "str" -failifempty ($connect_as -eq 'specific_user')
$password = Get-AnsibleParam -obj $params -name "password" -type "str" -failifempty ($connect_as -eq 'specific_user')

# Ensure WebAdministration module is loaded
if ($null -eq (Get-Module "WebAdministration" -ErrorAction SilentlyContinue)) {
    Import-Module WebAdministration
}

# Result
$result = @{
    directory = @{}
    changed = $false
}

# Construct path
$directory_path = if ($application) {
    "IIS:\Sites\$($site)\$($application)\$($name)"
}
else {
    "IIS:\Sites\$($site)\$($name)"
}

# Directory info
$directory = if ($application) {
    Get-WebVirtualDirectory -Site $site -Name $name -Application $application
}
else {
    Get-WebVirtualDirectory -Site $site -Name $name
}

try {
    # Add directory
    If (($state -eq 'present') -and (-not $directory)) {
        If (-not $physical_path) {
            Fail-Json -obj $result -message "missing required arguments: physical_path"
        }
        If (-not (Test-Path -LiteralPath $physical_path)) {
            Fail-Json -obj $result -message "specified folder must already exist: physical_path"
        }

        $directory_parameters = @{
            Site = $site
            Name = $name
            PhysicalPath = $physical_path
        }

        If ($application) {
            $directory_parameters.Application = $application
        }

        $directory = New-WebVirtualDirectory @directory_parameters -Force
        $result.changed = $true
    }

    # Remove directory
    If ($state -eq 'absent' -and $directory) {
        Remove-Item -LiteralPath $directory_path -Recurse -Force
        $result.changed = $true
    }

    $directory = if ($application) {
        Get-WebVirtualDirectory -Site $site -Name $name -Application $application
    }
    else {
        Get-WebVirtualDirectory -Site $site -Name $name
    }

    If ($directory) {

        # Change Physical Path if needed
        if ($physical_path) {
            If (-not (Test-Path -LiteralPath $physical_path)) {
                Fail-Json -obj $result -message "specified folder must already exist: physical_path"
            }

            $vdir_folder = Get-Item -LiteralPath $directory.PhysicalPath
            $folder = Get-Item -LiteralPath $physical_path
            If ($folder.FullName -ne $vdir_folder.FullName) {
                Set-ItemProperty -LiteralPath $directory_path -name physicalPath -value $physical_path
                $result.changed = $true
            }
        }

        # Change username or password if needed
        if ($connect_as -eq 'pass_through') {
            if ($directory.username -ne '') {
                Clear-ItemProperty -LiteralPath $directory_path -Name 'userName'
                $result.changed = $true
            }
            if ($directory.password -ne '') {
                Clear-ItemProperty -LiteralPath $directory_path -Name 'password'
                $result.changed = $true
            }
        }
        elseif ($connect_as -eq 'specific_user') {
            if ($directory.username -ne $username) {
                Set-ItemProperty -LiteralPath $directory_path -Name 'userName' -Value $username
                $result.changed = $true
            }
            if ($directory.password -ne $password) {
                Set-ItemProperty -LiteralPath $directory_path -Name 'password' -Value $password
                $result.changed = $true
            }
        }
    }
}
catch {
    Fail-Json $result $_.Exception.Message
}

# Result
$directory = if ($application) {
    Get-WebVirtualDirectory -Site $site -Name $name -Application $application
}
else {
    Get-WebVirtualDirectory -Site $site -Name $name
}

$result.directory = @{
    PhysicalPath = $directory.PhysicalPath
}

Exit-Json -obj $result