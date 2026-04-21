#!powershell

# Copyright: (c) 2015, George Frank <george@georgefrank.net>
# Copyright: (c) 2015, Adam Keech <akeech@chathamfinancial.com>
# Copyright: (c) 2015, Hans-Joachim Kliemeck <git@kliemeck.de>
# Copyright: (c) 2019, Kevin Subileau (@ksubileau)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#Requires -Module Ansible.ModuleUtils.Legacy
#Requires -Module Ansible.ModuleUtils.ArgvParser
#Requires -Module Ansible.ModuleUtils.CommandUtil

$ErrorActionPreference = "Stop"

$start_modes_map = @{
    "auto" = "SERVICE_AUTO_START"
    "delayed" = "SERVICE_DELAYED_AUTO_START"
    "manual" = "SERVICE_DEMAND_START"
    "disabled" = "SERVICE_DISABLED"
}

$params = Parse-Args -arguments $args -supports_check_mode $true
$check_mode = Get-AnsibleParam -obj $params -name "_ansible_check_mode" -type "bool" -default $false
$diff_mode = Get-AnsibleParam -obj $params -name "_ansible_diff" -type "bool" -default $false

$name = Get-AnsibleParam -obj $params -name "name" -type "str" -failifempty $true
$state_options = "present", "absent", "started", "stopped", "restarted"
$state = Get-AnsibleParam -obj $params -name "state" -type "str" -default "present" -validateset $state_options -resultobj $result
$display_name = Get-AnsibleParam -obj $params -name 'display_name' -type 'str'
$description = Get-AnsibleParam -obj $params -name 'description' -type 'str'

$application = Get-AnsibleParam -obj $params -name "application" -type "path"
$appDirectory = Get-AnsibleParam -obj $params -name "working_directory" -aliases "app_directory", "chdir" -type "path"
$appArguments = Get-AnsibleParam -obj $params -name "arguments" -aliases "app_parameters_free_form"

$stdoutFile = Get-AnsibleParam -obj $params -name "stdout_file" -type "path"
$stderrFile = Get-AnsibleParam -obj $params -name "stderr_file" -type "path"

$executable = Get-AnsibleParam -obj $params -name "executable" -type "path" -default "nssm.exe"

$app_env = Get-AnsibleParam -obj $params -name "app_environment" -type "dict"

$app_rotate_bytes = Get-AnsibleParam -obj $params -name "app_rotate_bytes" -type "int" -default 104858
$app_rotate_online = Get-AnsibleParam -obj $params -name "app_rotate_online" -type "int" -default 0 -validateset 0, 1
$app_stop_method_console = Get-AnsibleParam -obj $params -name "app_stop_method_console" -type "int"
$app_stop_method_skip = Get-AnsibleParam -obj $params -name "app_stop_method_skip" -type "int" -validateset 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15

$startMode = Get-AnsibleParam -obj $params -name "start_mode" -type "str" -default "auto" -validateset $start_modes_map.Keys -resultobj $result
$dependencies = Get-AnsibleParam -obj $params -name "dependencies" -type "list"
$user = Get-AnsibleParam -obj $params -name "username" -type "str" -aliases "user"
$password = Get-AnsibleParam -obj $params -name "password" -type "str"

$result = @{
    changed = $false
}
$diff_text = $null

function Invoke-NssmCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)]
        [string[]]$arguments
    )

    $command = Argv-ToString -arguments (@($executable) + $arguments)
    $result = Run-Command -command $command

    $result.arguments = $command

    return $result
}

function Get-NssmServiceStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$service
    )

    return Invoke-NssmCommand -arguments @("status", $service)
}

function Get-NssmServiceParameter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$service,
        [Parameter(Mandatory = $true)]
        [Alias("param")]
        [string]$parameter,
        [Parameter(Mandatory = $false)]
        [string]$subparameter
    )

    $arguments = @("get", $service, $parameter)
    if ($subparameter -ne "") {
        $arguments += $subparameter
    }
    return Invoke-NssmCommand -arguments $arguments
}

function Set-NssmServiceParameter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$service,
        [Parameter(Mandatory = $true)]
        [string]$parameter,
        [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)]
        [Alias("value")]
        [string[]]$arguments
    )

    return Invoke-NssmCommand -arguments (@("set", $service, $parameter) + $arguments)
}

function Reset-NssmServiceParameter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$service,
        [Parameter(Mandatory = $true)]
        [Alias("param")]
        [string]$parameter
    )

    return Invoke-NssmCommand -arguments @("reset", $service, $parameter)
}

function Update-NssmServiceParameter {
    <#
    .SYNOPSIS
    A generic cmdlet to idempotently set a nssm service parameter.
    .PARAMETER service
    [String] The service name
    .PARAMETER parameter
    [String] The name of the nssm parameter to set.
    .PARAMETER arguments
    [String[]] Target value (or list of value) or array of arguments to pass to the 'nssm set' command.
    .PARAMETER compare
    [scriptblock] An optionnal idempotency check scriptblock that must return true when
    the current value is equal to the desired value. Usefull when 'nssm get' doesn't return
    the same value as 'nssm set' takes in argument, like for the ObjectName parameter.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$service,

        [Parameter(Mandatory = $true)]
        [string]$parameter,

        [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [Alias("value")]
        [string[]]$arguments,

        [Parameter()]
        [scriptblock]$compare = { param($actual, $expected) @(Compare-Object -ReferenceObject $actual -DifferenceObject $expected).Length -eq 0 }
    )

    if ($null -eq $arguments) { return }
    $arguments = @($arguments | Where-Object { $_ -ne '' })

    $nssm_result = Get-NssmServiceParameter -service $service -parameter $parameter

    if ($nssm_result.rc -ne 0) {
        $result.nssm_error_cmd = $nssm_result.arguments
        $result.nssm_error_log = $nssm_result.stderr
        Fail-Json -obj $result -message "Error retrieving $parameter for service ""$service"""
    }

    $current_values = @($nssm_result.stdout.split("`n`r") | Where-Object { $_ -ne '' })

    if (-not $compare.Invoke($current_values, $arguments)) {
        if ($PSCmdlet.ShouldProcess($service, "Update '$parameter' parameter")) {
            if ($arguments.Count -gt 0) {
                $nssm_result = Set-NssmServiceParameter -service $service -parameter $parameter -arguments $arguments
            }
            else {
                $nssm_result = Reset-NssmServiceParameter -service $service -parameter $parameter
            }

            if ($nssm_result.rc -ne 0) {
                $result.nssm_error_cmd = $nssm_result.arguments
                $result.nssm_error_log = $nssm_result.stderr
                Fail-Json -obj $result -message "Error setting $parameter for service ""$service"""
            }
        }

        $script:diff_text += "-$parameter = $($current_values -join ', ')`n+$parameter = $($arguments -join ', ')`n"
        $result.changed_by = $parameter
        $result.changed = $true
    }
}

function Test-NssmServiceExist {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$service
    )

    return [bool](Get-Service -Name $service -ErrorAction SilentlyContinue)
}

function Invoke-NssmStart {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$service
    )

    $nssm_result = Invoke-NssmCommand -arguments @("start", $service)

    if ($nssm_result.rc -ne 0) {
        $result.nssm_error_cmd = $nssm_result.arguments
        $result.nssm_error_log = $nssm_result.stderr
        Fail-Json -obj $result -message "Error starting service ""$service"""
    }
}

function Invoke-NssmStop {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$service
    )

    $nssm_result = Invoke-NssmCommand -arguments @("stop", $service)

    if ($nssm_result.rc -ne 0) {
        $result.nssm_error_cmd = $nssm_result.arguments
        $result.nssm_error_log = $nssm_result.stderr
        Fail-Json -obj $result -message "Error stopping service ""$service"""
    }
}

function Start-NssmService {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$service
    )

    $currentStatus = Get-NssmServiceStatus -service $service

    if ($currentStatus.rc -ne 0) {
        $result.nssm_error_cmd = $currentStatus.arguments
        $result.nssm_error_log = $currentStatus.stderr
        Fail-Json -obj $result -message "Error starting service ""$service"""
    }

    if ($currentStatus.stdout -notlike "*SERVICE_RUNNING*") {
        if ($PSCmdlet.ShouldProcess($service, "Start service")) {
            switch -wildcard ($currentStatus.stdout) {
                "*SERVICE_STOPPED*" { Invoke-NssmStart -service $service }

                "*SERVICE_CONTINUE_PENDING*" { Invoke-NssmStop -service $service; Invoke-NssmStart -service $service }
                "*SERVICE_PAUSE_PENDING*" { Invoke-NssmStop -service $service; Invoke-NssmStart -service $service }
                "*SERVICE_PAUSED*" { Invoke-NssmStop -service $service; Invoke-NssmStart -service $service }
                "*SERVICE_START_PENDING*" { Invoke-NssmStop -service $service; Invoke-NssmStart -service $service }
                "*SERVICE_STOP_PENDING*" { Invoke-NssmStop -service $service; Invoke-NssmStart -service $service }
            }
        }

        $result.changed_by = "start_service"
        $result.changed = $true
    }
}

function Stop-NssmService {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$service
    )

    $currentStatus = Get-NssmServiceStatus -service $service

    if ($currentStatus.rc -ne 0) {
        $result.nssm_error_cmd = $currentStatus.arguments
        $result.nssm_error_log = $currentStatus.stderr
        Fail-Json -obj $result -message "Error stopping service ""$service"""
    }

    if ($currentStatus.stdout -notlike "*SERVICE_STOPPED*") {
        if ($PSCmdlet.ShouldProcess($service, "Stop service")) {
            Invoke-NssmStop -service $service
        }

        $result.changed_by = "stop_service"
        $result.changed = $true
    }
}

Function ConvertTo-NormalizedUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$InputObject
    )

    $systemSid = [System.Security.Principal.SecurityIdentifier]'S-1-5-18'

    # Try to get the SID from the raw value or with LocalSystem (what services consider to be SYSTEM).
    try {
        $sid = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $InputObject
    }
    catch [ArgumentException] {
        if ($InputObject -eq "LocalSystem") {
            $sid = $systemSid
        }
    }

    if (-not $sid) {
        $candidates = @(if ($InputObject.Contains('\')) {
                $nameSplit = $InputObject.Split('\', 2)

                if ($nameSplit[0] -eq '.') {
                    # If the domain portion is . try using the hostname then falling back to just the username.
                    # Usually the hostname just works except when running on a DC where it's a domain account
                    # where looking up just the username should work.
                    , @($env:COMPUTERNAME, $nameSplit[1])
                    $nameSplit[1]
                }
                else {
                    , $nameSplit
                }
            }
            else {
                $InputObject
            })

        $sid = for ($i = 0; $i -lt $candidates.Length; $i++) {
            $candidate = $candidates[$i]
            $ntAccount = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList $candidate
            try {
                $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
                break
            }
            catch [System.Security.Principal.IdentityNotMappedException] {
                if ($i -eq ($candidates.Length - 1)) {
                    throw
                }
                continue
            }
        }
    }

    if ($sid -eq $systemSid) {
        "LocalSystem"
    }
    else {
        $sid.Translate([System.Security.Principal.NTAccount]).Value
    }
}

if ($state -ne 'absent') {
    if ($null -eq $application) {
        Fail-Json -obj $result -message "The application parameter must be defined when the state is not absent."
    }

    if (-not (Test-Path -LiteralPath $application -PathType Leaf)) {
        Fail-Json -obj $result -message "The application specified ""$application"" does not exist on the host."
    }

    if ($null -eq $appDirectory) {
        $appDirectory = (Get-Item -LiteralPath $application).DirectoryName
    }

    if ($user) {
        $user = ConvertTo-NormalizedUser -InputObject $user
        if (
            $user -in @(
                (ConvertTo-NormalizedUser -InputObject 'S-1-5-18'), # SYSTEM
                (ConvertTo-NormalizedUser -InputObject 'S-1-5-19'), # LOCAL SERVICE
                (ConvertTo-NormalizedUser -InputObject 'S-1-5-20') # NETWORK SERVICE
            )
        ) {
            # These accounts have no password (NSSM expects nothing)
            $password = ""
        }
        elseif ($user.EndsWith('$')) {
            # While a gMSA doesn't have a password NSSM will fail with no password so we set a dummy value. The service
            # still starts up properly with this so SCManager handles this nicely.
            $password = "gsma_password"
        }
        elseif (-not $password) {
            # Any other account requires a password here.
            Fail-Json -obj $result -message "User without password is informed for service ""$name"""
        }
    }
}


$service_exists = Test-NssmServiceExist -service $name

if ($state -eq 'absent') {
    if ($service_exists) {
        if (-not $check_mode) {
            if ((Get-Service -Name $name).Status -ne "Stopped") {
                $nssm_result = Invoke-NssmStop -service $name
            }

            $nssm_result = Invoke-NssmCommand -arguments @("remove", $name, "confirm")

            if ($nssm_result.rc -ne 0) {
                $result.nssm_error_cmd = $nssm_result.arguments
                $result.nssm_error_log = $nssm_result.stderr
                Fail-Json -obj $result -message "Error removing service ""$name"""
            }
        }

        $diff_text += "-[$name]"
        $result.changed_by = "remove_service"
        $result.changed = $true
    }
}
else {
    $diff_text_added_prefix = ''
    if (-not $service_exists) {
        if (-not $check_mode) {
            $nssm_result = Invoke-NssmCommand -arguments @("install", $name, $application)

            if ($nssm_result.rc -ne 0) {
                $result.nssm_error_cmd = $nssm_result.arguments
                $result.nssm_error_log = $nssm_result.stderr
                Fail-Json -obj $result -message "Error installing service ""$name"""
            }
            $service_exists = $true
        }

        $diff_text_added_prefix = '+'
        $result.changed_by = "install_service"
        $result.changed = $true
    }

    $diff_text += "$diff_text_added_prefix[$name]`n"

    # We cannot configure a service that was created above in check mode as it won't actually exist
    if ($service_exists) {
        $common_params = @{
            service = $name
            WhatIf = $check_mode
        }

        Update-NssmServiceParameter -parameter "Application" -value $application @common_params
        Update-NssmServiceParameter -parameter "DisplayName" -value $display_name @common_params
        Update-NssmServiceParameter -parameter "Description" -value $description @common_params

        Update-NssmServiceParameter -parameter "AppDirectory" -value $appDirectory @common_params


        if ($null -ne $appArguments) {
            $singleLineParams = ""
            if ($appArguments -is [array]) {
                $singleLineParams = Argv-ToString -arguments $appArguments
            }
            else {
                $singleLineParams = $appArguments.ToString()
            }

            $result.nssm_app_parameters = $appArguments
            $result.nssm_single_line_app_parameters = $singleLineParams

            Update-NssmServiceParameter -parameter "AppParameters" -value $singleLineParams @common_params
        }


        Update-NssmServiceParameter -parameter "AppStdout" -value $stdoutFile @common_params
        Update-NssmServiceParameter -parameter "AppStderr" -value $stderrFile @common_params

        # set app environment, only do this for now when explicitly requested by caller to
        # avoid breaking playbooks which use another / custom scheme for configuring app_env
        if ($null -ne $app_env) {
            # note: convert app_env dictionary to list of strings in the form key=value and pass that a long as value
            $app_env_str = $app_env.GetEnumerator() | ForEach-Object { "$($_.Name)=$($_.Value)" }

            # note: this is important here to make an empty envvar set working properly (in the sense that appenv is reset)
            if ($null -eq $app_env_str) {
                $app_env_str = ''
            }

            Update-NssmServiceParameter -parameter "AppEnvironmentExtra" -value $app_env_str @common_params
        }

        ###
        # Setup file rotation so we don't accidentally consume too much disk
        ###

        #set files to overwrite
        Update-NssmServiceParameter -parameter "AppStdoutCreationDisposition" -value 2 @common_params
        Update-NssmServiceParameter -parameter "AppStderrCreationDisposition" -value 2 @common_params

        #enable file rotation
        Update-NssmServiceParameter -parameter "AppRotateFiles" -value 1 @common_params

        #don't rotate until the service restarts
        Update-NssmServiceParameter -parameter "AppRotateOnline" -value $app_rotate_online @common_params

        #both of the below conditions must be met before rotation will happen
        #minimum age before rotating
        Update-NssmServiceParameter -parameter "AppRotateSeconds" -value 86400 @common_params

        #minimum size before rotating
        Update-NssmServiceParameter -parameter "AppRotateBytes" -value $app_rotate_bytes @common_params

        Update-NssmServiceParameter -parameter "DependOnService" -arguments $dependencies @common_params
        if ($user) {
            # Use custom compare callback to test only the username (and not the password)
            Update-NssmServiceParameter -parameter "ObjectName" -arguments @($user, $password) -compare {
                param($actual, $expected)

                $actualUser = ConvertTo-NormalizedUser -InputObject $actual[0]
                $expectedUser = ConvertTo-NormalizedUser -InputObject $expected[0]

                $actualUser -eq $expectedUser
            } @common_params
        }
        $mappedMode = $start_modes_map.$startMode
        Update-NssmServiceParameter -parameter "Start" -value $mappedMode @common_params
        if ($state -in "stopped", "restarted") {
            Stop-NssmService @common_params
        }

        if ($state -in "started", "restarted") {
            Start-NssmService @common_params
        }

        # Added per users` requests
        if ($null -ne $app_stop_method_console) {
            Update-NssmServiceParameter -parameter "AppStopMethodConsole" -value $app_stop_method_console @common_params
        }

        if ($null -ne $app_stop_method_skip) {
            Update-NssmServiceParameter -parameter "AppStopMethodSkip" -value $app_stop_method_skip @common_params
        }
    }
}

if ($diff_mode -and $result.changed -eq $true) {
    $result.diff = @{
        prepared = $diff_text
    }
}

Exit-Json $result
