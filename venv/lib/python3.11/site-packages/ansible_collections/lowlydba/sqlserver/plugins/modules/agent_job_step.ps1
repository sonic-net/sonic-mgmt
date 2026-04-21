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
        job = @{type = 'str'; required = $true }
        step_id = @{type = 'int'; required = $false }
        step_name = @{type = 'str'; required = $false }
        database = @{type = 'str'; required = $false; default = 'master' }
        subsystem = @{type = 'str'; required = $false; default = 'TransactSql'
            choices = @('CmdExec', 'Distribution', 'LogReader', 'Merge', 'PowerShell', 'QueueReader', 'Snapshot', 'Ssis', 'TransactSql')
        }
        command = @{type = 'str'; required = $false }
        on_success_action = @{type = 'str'; required = $false; default = 'QuitWithSuccess'
            choices = @('QuitWithSuccess', 'QuitWithFailure', 'GoToNextStep', 'GoToStep')
        }
        on_success_step_id = @{type = 'int'; required = $false; default = 0 }
        on_fail_action = @{type = 'str'; required = $false; default = 'QuitWithFailure'
            choices = @('QuitWithSuccess', 'QuitWithFailure', 'GoToNextStep', 'GoToStep')
        }
        on_fail_step_id = @{type = 'int'; required = $false; default = 0 }
        retry_attempts = @{type = 'int'; required = $false; default = 0 }
        retry_interval = @{type = 'int'; required = $false; default = 0 }
        output_file = @{type = 'str'; required = $false }
        state = @{type = 'str'; required = $false; default = 'present'; choices = @('present', 'absent') }
    }
    required_together = @(
        , @('retry_attempts', 'retry_interval')
    )
    required_one_of = @(
        , @('step_id', 'step_name')
    )
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-LowlyDbaSqlServerAuthSpec))
$sqlInstance, $sqlCredential = Get-SqlCredential -Module $module
$job = $module.Params.job
$stepId = $module.Params.step_id
$stepName = $module.Params.step_name
$database = $module.Params.database
$subsystem = $module.Params.subsystem
$command = $module.Params.command
$onSuccessAction = $module.Params.on_success_action
[nullable[int]]$onSuccessStepId = $module.Params.on_success_step_id
$onFailAction = $module.Params.on_fail_action
[nullable[int]]$onFailStepId = $module.Params.on_fail_step_id
[int]$retryAttempts = $module.Params.retry_attempts
[nullable[int]]$retryInterval = $module.Params.retry_interval
$outputFile = $module.Params.output_file
$state = $module.Params.state
$checkMode = $module.CheckMode
$module.Result.changed = $false
$PSDefaultParameterValues = @{ "*:EnableException" = $true; "*:Confirm" = $false; "*:WhatIf" = $checkMode }

# Configure Agent job step
try {
    $existingJobSteps = Get-DbaAgentJobStep -SqlInstance $SqlInstance -SqlCredential $sqlCredential -Job $job
    $existingJobStep = $existingJobSteps | Where-Object Name -eq $stepName

    if ($state -eq "absent") {
        if ($null -eq $existingJobStep) {
            # try fetching name by id if we only care about removing
            $existingJobStep = $existingJobSteps | Where-Object Id -eq $stepId
            $stepName = $existingJobStep.Name
        }
        if ($existingJobStep) {
            $removeStepSplat = @{
                SqlInstance = $sqlInstance
                SqlCredential = $sqlCredential
                Job = $job
                StepName = $stepName
            }
            $output = Remove-DbaAgentJobStep @removeStepSplat
            $module.Result.changed = $true
        }
    }
    elseif ($state -eq "present") {
        if (!($stepName) -or !($stepId)) {
            $module.FailJson("Step name and step_id must be specified when state=present.")
        }
        $jobStepParams = @{
            SqlInstance = $sqlInstance
            SqlCredential = $sqlCredential
            Job = $job
            StepName = $stepName
            Database = $database
            SubSystem = $subsystem
            OnSuccessAction = $onSuccessAction
            OnSuccessStepId = $onSuccessStepId
            OnFailAction = $onFailAction
            OnFailStepId = $onFailStepId
            RetryAttempts = $retryAttempts
            RetryInterval = $retryInterval
        }
        if ($null -ne $command) {
            $jobStepParams.Add("Command", $command)
        }

        # No existing job step
        if ($null -eq $existingJobStep) {
            $jobStepParams.Add("StepId", $stepId)
            $output = New-DbaAgentJobStep @jobStepParams
            $module.Result.changed = $true

            # Set output file if specified
            if ($null -ne $outputFile -and $outputFile -ne "") {
                $setOutputFileSplat = @{
                    SqlInstance = $sqlInstance
                    SqlCredential = $sqlCredential
                    Job = $job
                    Step = $stepName
                    OutputFile = $outputFile
                }
                $outputFileResult = Set-DbaAgentJobOutputFile @setOutputFileSplat
                if ($null -ne $outputFileResult) {
                    $module.Result.changed = $true
                    # Add the OutputFileName property from the Set-DbaAgentJobOutputFile result
                    if ($null -ne $outputFileResult.OutputFileName) {
                        Add-Member -InputObject $output -MemberType NoteProperty -Name "OutputFileName" -Value $outputFileResult.OutputFileName -Force
                    }
                }
            }

            # Ensure OutputFileName property is always available for consistency
            if ($null -ne $output -and -not ($output.PSObject.Properties.Name -contains "OutputFileName")) {
                Add-Member -InputObject $output -MemberType NoteProperty -Name "OutputFileName" -Value $output.OutputFileName -Force
            }
        }
        # Update existing
        else {
            # Validate step name isn't taken already - must be unique within a job
            if ($existingJobStep.Name -eq $StepName -and $existingJobStep.ID -ne $stepId) {
                $module.FailJson("There is already a step named '$StepName' for this job with an ID of $($existingJobStep.ID).")
            }

            # Reference by old name in case new name differs for step id
            $jobStepParams.StepName = $existingJobStep.Name
            $jobStepParams.Add("NewName", $StepName)

            # Need to serialize to prevent SMO auto refreshing
            $old = ConvertTo-SerializableObject -InputObject $existingJobStep -UseDefaultProperty $false
            $output = Set-DbaAgentJobStep @jobStepParams
            if ($null -ne $output) {
                $compareProperty = @(
                    "Name"
                    "DatabaseName"
                    "Command"
                    "Subsystem"
                    "OnFailAction"
                    "OnFailActionStep"
                    "OnSuccessAction"
                    "OnSuccessActionStep"
                    "RetryAttempts"
                    "RetryInterval"
                    "OutputFileName"
                )
                $diff = Compare-Object -ReferenceObject $output -DifferenceObject $old -Property $compareProperty
            }

            # Set output file if specified and different from current
            if ($null -ne $outputFile -and $outputFile -ne "" -and $existingJobStep.OutputFileName -ne $outputFile) {
                $setOutputFileSplat = @{
                    SqlInstance = $sqlInstance
                    SqlCredential = $sqlCredential
                    Job = $job
                    Step = $stepName  # Use the new step name since Set-DbaAgentJobStep already renamed it
                    OutputFile = $outputFile
                }
                $outputFileResult = Set-DbaAgentJobOutputFile @setOutputFileSplat
                if ($null -ne $outputFileResult) {
                    $module.Result.changed = $true
                    # Add the OutputFileName property from the Set-DbaAgentJobOutputFile result
                    if ($null -ne $outputFileResult.OutputFileName) {
                        Add-Member -InputObject $output -MemberType NoteProperty -Name "OutputFileName" -Value $outputFileResult.OutputFileName -Force
                    }
                }
            }

            # Ensure OutputFileName property is always available
            if ($null -ne $output -and -not ($output.PSObject.Properties.Name -contains "OutputFileName")) {
                Add-Member -InputObject $output -MemberType NoteProperty -Name "OutputFileName" -Value $output.OutputFileName -Force
            }

            if ($diff -or $checkMode) {
                $module.Result.changed = $true
            }
        }
    }

    if ($null -ne $output) {
        $resultData = ConvertTo-SerializableObject -InputObject $output
        $module.Result.data = $resultData
    }
    $module.ExitJson()
}
catch {
    $module.FailJson("Error configuring SQL Agent job step.", $_)
}
