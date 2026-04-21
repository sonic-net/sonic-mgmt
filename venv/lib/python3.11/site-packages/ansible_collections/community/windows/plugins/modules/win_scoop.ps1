#!powershell

# Copyright: (c) 2020, Jamie Magee <jamie.magee@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#Requires -Module Ansible.ModuleUtils.ArgvParser
#Requires -Module Ansible.ModuleUtils.CommandUtil
#AnsibleRequires -CSharpUtil Ansible.Basic

$spec = @{
    options = @{
        architecture = @{ type = "str"; choices = "32bit", "64bit"; aliases = @(, "arch") }
        independent = @{ type = "bool"; default = $false }
        global = @{ type = "bool"; default = $false }
        name = @{ type = "list"; elements = "str"; required = $true }
        no_cache = @{ type = "bool"; default = $false }
        purge = @{ type = "bool"; default = $false }
        skip_checksum = @{ type = "bool"; default = $false }
        state = @{ type = "str"; default = "present"; choices = "present", "absent" }
    }
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$architecture = $module.Params.architecture
$independent = $module.Params.independent
$global = $module.Params.global
$name = $module.Params.name
$no_cache = $module.Params.no_cache
$purge = $module.Params.purge
$skip_checksum = $module.Params.skip_checksum
$state = $module.Params.state

$module.Result.rc = 0

function Install-Scoop {
    [CmdletBinding()]
    param ()

    # Scoop doesn't have refreshenv like Chocolatey
    # Let's try to update PATH first
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

    $scoop_app = Get-Command -Name scoop.ps1 -Type ExternalScript -ErrorAction SilentlyContinue
    if ($module.CheckMode -and $null -eq $scoop_app) {
        $module.Result.skipped = $true
        $module.Result.msg = "Skipped check mode run on win_scoop as scoop.ps1 cannot be found on the system"
        $module.ExitJson()
    }
    elseif ($null -eq $scoop_app) {
        # We need to install scoop
        # We run this in a separate process to make it easier to get the result in a failure and capture any output that
        # might be sent to the host. We also need to enable TLS 1.2 in that process and not here so it can download the
        # install script and other components.
        $install_script = {
            # Enable TLS1.2 if it's available but disabled (eg. .NET 4.5)
            $security_protocols = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::SystemDefault
            if ([Net.SecurityProtocolType].GetMember("Tls12").Count -gt 0) {
                $security_protocols = $security_protcols -bor [Net.SecurityProtocolType]::Tls12
            }
            [Net.ServicePointManager]::SecurityProtocol = $security_protocols

            $script = (New-Object System.Net.WebClient).DownloadString('https://get.scoop.sh')
            $installer = [ScriptBlock]::Create($script)
            $params = @{}

            $current_user = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            if ($current_user.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                $params.RunAsAdmin = $true
            }
            . $installer -RunAsAdmin
        }

        $enc_command = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($install_script.ToString()))
        $cmd = "powershell.exe -NoProfile -NoLogo -EncodedCommand $enc_command"

        # Scoops installer does weird things and the exit code will most likely be 0. Use the presence of the scoop
        # command as the indicator as to whether it was installed or not.
        $res = Run-Command -Command $cmd -environment $environment

        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

        # locate the newly installed scoop.ps1
        $scoop_app = Get-Command -Name scoop.ps1 -Type ExternalScript -ErrorAction SilentlyContinue

        if ($null -eq $scoop_app -or -not (Test-Path -LiteralPath $scoop_app.Path)) {
            $module.Result.rc = $res.rc
            $module.Result.stdout = $res.stdout
            $module.Result.stderr = $res.stderr
            $module.FailJson("Failed to bootstrap scoop.ps1")
        }

        $module.Warn("Scoop was missing from this system, so it was installed during this task run.")
        $module.Result.changed = $true
    }

    return $scoop_app.Path
}

function Get-ScoopPackage {
    param(
        [Parameter(Mandatory = $true)] [string]$scoop_path
    )

    $command = Argv-ToString -arguments @("powershell.exe", "-File", $scoop_path, "export")
    $res = Run-Command -Command $command
    if ($res.rc -ne 0) {
        $module.Result.command = $command
        $module.Result.rc = $res.rc
        $module.Result.stdout = $res.stdout
        $module.Result.stderr = $res.stderr
        $module.FailJson("Error checking installed packages")
    }

    # Scoop since 0.2.3 output as JSON, older versions use a custom format
    # https://github.com/ScoopInstaller/Scoop/commit/c4d1b9c22f943a810bed7f9f74d7d4d5c42d9a74
    try {
        $exportObj = ConvertFrom-Json -InputObject $res.stdout -ErrorAction Stop
    }
    catch {
        $res.stdout -split "`n" |
            Select-String '(.*?) \(v:(.*?)\)( \*global\*)? \[(.*?)\](\{32bit\})?' |
            ForEach-Object {
                [PSCustomObject]@{
                    Package = $_.Matches[0].Groups[1].Value
                    Version = $_.Matches[0].Groups[2].Value
                    Global = -not ([string]::IsNullOrWhiteSpace($_.Matches[0].Groups[3].Value))
                    Bucket = $_.Matches[0].Groups[4].Value
                    x86 = -not ([string]::IsNullOrWhiteSpace($_.Matches[0].Groups[5].Value))
                }
            }
        return
    }

    $exportObj.apps | ForEach-Object {
        $options = @($_.Info -split ',' | ForEach-Object Trim | Where-Object { $_ })
        if ('Install failed' -in $options) {
            return
        }

        [PSCustomObject]@{
            Package = $_.Name
            Version = $_.Version
            Global = 'Global install' -in $options
            Bucket = $_.Source
            x86 = '32bit' -in $options
        }
    }
}

function Get-InstallScoopPackageArgument {
    $arguments = [System.Collections.Generic.List[String]]@()

    if ($architecture) {
        $arguments.Add("--arch")
        $arguments.Add($architecture)
    }
    if ($global) {
        $arguments.Add("--global")
    }
    if ($independent) {
        $arguments.Add("--independent")
    }
    if ($no_cache) {
        $arguments.Add("--no-cache")
    }
    if ($skip_checksum) {
        $arguments.Add("--skip")
    }

    return , $arguments
}

function Install-ScoopPackage {
    param(
        [Parameter(Mandatory = $true)] [string]$scoop_path,
        [Parameter(Mandatory = $true)] [String[]]$packages
    )
    $arguments = [System.Collections.Generic.List[String]]@("powershell.exe", "-File", $scoop_path, "install")
    $arguments.AddRange($packages)

    $common_args = Get-InstallScoopPackageArgument
    $arguments.AddRange($common_args)

    $command = Argv-ToString -arguments $arguments

    if (-not $module.CheckMode) {
        $res = Run-Command -Command $command
        if ($res.rc -ne 0) {
            $module.Result.command = $command
            $module.Result.rc = $res.rc
            $module.Result.stdout = $res.stdout
            $module.Result.stderr = $res.stderr
            $module.FailJson("Error installing $packages")
        }

        if ($module.Verbosity -gt 1) {
            $module.Result.stdout = $res.stdout
        }
    }
    $module.Result.changed = $true
}

function Get-UninstallScoopPackageArgument {
    $arguments = [System.Collections.Generic.List[String]]@()

    if ($global) {
        $arguments.Add("--global")
    }
    if ($purge) {
        $arguments.Add("--purge")
    }

    return , $arguments
}

function Uninstall-ScoopPackage {
    param(
        [Parameter(Mandatory = $true)] [string]$scoop_path,
        [Parameter(Mandatory = $true)] [String[]]$packages
    )

    $arguments = [System.Collections.Generic.List[String]]@("powershell.exe", "-File", $scoop_path, "uninstall")
    $arguments.AddRange($packages)

    $common_args = Get-UninstallScoopPackageArgument
    $arguments.AddRange($common_args)

    $command = Argv-ToString -arguments $arguments

    if (-not $module.CheckMode) {
        $res = Run-Command -Command $command
        if ($res.rc -ne 0) {
            $module.Result.command = $command
            $module.Result.rc = $res.rc
            $module.Result.stdout = $res.stdout
            $module.Result.stderr = $res.stderr
            $module.FailJson("Error uninstalling $packages")
        }

        if ($module.Verbosity -gt 1) {
            $module.Result.stdout = $res.stdout
        }
        if (-not ($res.stdout -match "ERROR '(.*?)' isn't installed.")) {
            $module.Result.changed = $true
        }
    }
    else {
        $module.Result.changed = $true
    }
}

$scoop_path = Install-Scoop

$installed_packages = @(Get-ScoopPackage -scoop_path $scoop_path)

if ($state -in @("absent")) {
    # Always attempt uninstall
    # Packages can be in a broken state where they don't in appear scoop export
    Uninstall-ScoopPackage -scoop_path $scoop_path -packages $name
}

if ($state -in @("present")) {
    $missing_packages = foreach ($package in $name) {
        if (
            ($installed_packages.Package -notcontains $package) -or
            (($installed_packages.Package -contains $package) -and (
                ((($installed_packages | Where-Object { $_.Package -eq $package }).Global -contains $true) -and -not $global) -or
                ((($installed_packages | Where-Object { $_.Package -eq $package }).Global -notcontains $true) -and $global)
            )
      )
        ) {
            $package
        }
    }
}

if ($missing_packages) {
    Install-ScoopPackage -scoop_path $scoop_path -packages $missing_packages
}

$module.ExitJson()
