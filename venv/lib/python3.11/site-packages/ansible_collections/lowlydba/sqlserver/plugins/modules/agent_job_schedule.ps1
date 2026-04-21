#!powershell
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ansible_collections.lowlydba.sqlserver.plugins.module_utils._SqlServerUtils
#Requires -Modules @{ ModuleName="dbatools"; ModuleVersion="2.0.0" }

$ErrorActionPreference = "Stop"

$spec = @{
    supports_check_mode = $true
    options = @{
        schedule = @{type = 'str'; required = $true }
        job = @{type = 'str'; required = $true }
        enabled = @{type = 'bool'; required = $false }
        force = @{type = 'bool'; required = $false }
        frequency_type = @{type = 'str'; required = $false
            choices = @('Once', 'OneTime', 'Daily', 'Weekly', 'Monthly', 'MonthlyRelative', 'AgentStart', 'AutoStart', 'IdleComputer', 'OnIdle')
        }
        frequency_interval = @{type = 'str'; required = $false; }
        frequency_subday_type = @{type = 'str'; required = $false; choices = @('Time', 'Seconds', 'Minutes', 'Hours') }
        frequency_subday_interval = @{type = 'int'; required = $false }
        frequency_relative_interval = @{type = 'str'; required = $false; choices = @('Unused', 'First', 'Second', 'Third', 'Fourth', 'Last') }
        frequency_recurrence_factor = @{type = 'int'; required = $false }
        start_date = @{type = 'str'; required = $false }
        end_date = @{type = 'str'; required = $false }
        start_time = @{type = 'str'; required = $false }
        end_time = @{type = 'str'; required = $false }
        state = @{type = 'str'; required = $false; default = 'present'; choices = @('present', 'absent') }
    }
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$schedule = $module.Params.schedule
$job = $module.Params.job
[nullable[bool]]$enabled = $module.Params.enabled
$force = $module.Params.force
$frequencyType = $module.Params.frequency_type
$frequencyInterval = $module.Params.frequency_interval
$frequencySubdayType = $module.Params.frequency_subday_type
[nullable[int]]$frequencySubdayInterval = $module.Params.frequency_subday_interval
$frequencyRelativeInterval = $module.Params.frequency_relative_interval
[nullable[int]]$frequencyRecurrenceFactor = $module.Params.frequency_recurrence_factor
$startDate = $module.Params.start_date
$endDate = $module.Params.end_date
$startTime = $module.Params.start_time
$endTime = $module.Params.end_time
$state = $module.Params.state
$checkMode = $module.CheckMode
$module.Result.changed = $false
$PSDefaultParameterValues = @{ "*:EnableException" = $true; "*:Confirm" = $false; "*:WhatIf" = $checkMode }

$scheduleParams = @{
    SqlInstance = $SqlInstance
    SqlCredential = $sqlCredential
    Force = $force
    Schedule = $schedule
}

if ($enabled -eq $false) {
    $scheduleParams.add("Disabled", $true)
}
if ($null -ne $job) {
    $scheduleParams.add("Job", $job)
}
if ($null -ne $startDate) {
    $scheduleParams.add("StartDate", $startDate)
}
if ($null -ne $endDate) {
    $scheduleParams.add("EndDate", $endDate)
}
if ($null -ne $startTime) {
    $scheduleParams.add("StartTime", $startTime)
}
if ($null -ne $endTime) {
    $scheduleParams.add("EndTime", $endTime)
}
if ($null -ne $frequencyType) {
    $scheduleParams.add("FrequencyType", $frequencyType)
}
if ($null -ne $frequencyInterval) {
    $scheduleParams.add("FrequencyInterval", $frequencyInterval)
}
if ($null -ne $frequencySubdayType) {
    $scheduleParams.add("FrequencySubdayType", $frequencySubdayType)
}
if ($null -ne $frequencySubdayInterval) {
    $scheduleParams.add("FrequencySubdayInterval", $frequencySubdayInterval)
}
if ($null -ne $frequencyRelativeInterval) {
    $scheduleParams.add("FrequencyRelativeInterval", $frequencyRelativeInterval)
}
if ($null -ne $frequencyRecurrenceFactor) {
    $scheduleParams.add("FrequencyRecurrenceFactor", $frequencyRecurrenceFactor)
}

try {
    $existingSchedule = Get-DbaAgentSchedule -SqlInstance $SqlInstance -SqlCredential $sqlCredential -Schedule $schedule
    if ($state -eq "present") {
        # Update schedule
        if ($null -ne $existingSchedule) {
            if ($enabled -eq $true) {
                $scheduleParams.Add("Enabled", $true)
            }
            # Need to serialize to prevent SMO auto refreshing
            $old = ConvertTo-SerializableObject -InputObject $existingSchedule -UseDefaultProperty $false
            $output = Set-DbaAgentSchedule @scheduleParams
            if ($null -ne $output) {
                $compareProperty = @(
                    "ActiveEndDate"
                    "ActiveEndTimeOfDay"
                    "ActiveStartDate"
                    "ActiveStartTimeOfDay"
                    "Description"
                    "FrequencyInterval"
                    "FrequencyRecurrenceFactor"
                    "FrequencyRelativeIntervals"
                    "FrequencySubDayInterval"
                    "FrequencySubDayTypes"
                    "FrequencyTypes"
                    "IsEnabled"
                    "ScheduleName"
                )
                $diff = Compare-Object -ReferenceObject $output -DifferenceObject $old -Property $compareProperty

                # # Check if schedule was actually changed
                # $modifiedSchedule = Get-DbaAgentSchedule -SqlInstance $SqlInstance -SqlCredential $sqlCredential -Schedule $ScheduleName -EnableException
                # $scheduleDiff = Compare-Object -ReferenceObject $existingSchedule -DifferenceObject $modifiedSchedule
                if ($diff -or $checkMode) {
                    $module.Result.changed = $true
                }
            }
        }
        # Create schedule
        else {
            $output = New-DbaAgentSchedule @scheduleParams
            if ($null -ne $job) {
                # https://github.com/dataplat/dbatools/issues/8933
                if ($null -ne $output -and ($null -ne ($output | Get-Member -Name 'Refresh'))) {
                    $output.Refresh()
                }
            }
            $module.Result.changed = $true
        }
    }
    elseif ($state -eq "absent") {
        # Nothing to remove
        if ($null -eq $existingSchedule) {
            $module.ExitJson()
        }
        # Remove schedule
        else {
            $output = $existingSchedule | Remove-DbaAgentSchedule -Force
            $module.Result.changed = $true
        }
    }

    if ($null -ne $output) {
        $resultData = ConvertTo-SerializableObject -InputObject $output
        $module.Result.data = $resultData
    }
    $module.ExitJson()
}
catch {
    $module.FailJson("Error configuring SQL Agent job schedule.", $_)
}
