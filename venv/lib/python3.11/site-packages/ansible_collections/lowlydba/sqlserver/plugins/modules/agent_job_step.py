#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: agent_job_step
short_description: Configures a SQL Agent job step
description:
  - Configures a step for an agent job.
version_added: 0.1.0
options:
  job:
    description:
      - The name of the job to which to add the step.
    required: true
    type: str
  step_id:
    description:
      - The sequence identification number for the job step. Step identification numbers start at C(1) and increment without gaps.
      - Required if I(state=present).
    required: false
    type: int
  step_name:
    description:
      - The name of the step. Required if I(state=present).
    required: false
    type: str
  database:
    description:
      - The name of the database in which to execute a Transact-SQL step.
    required: false
    type: str
    default: 'master'
  subsystem:
    description:
      - The subsystem used by the SQL Server Agent service to execute command.
    required: false
    type: str
    default: 'TransactSql'
    choices: ['CmdExec', 'Distribution', 'LogReader', 'Merge', 'PowerShell', 'QueueReader', 'Snapshot', 'Ssis', 'TransactSql']
  command:
    description:
      - The commands to be executed by SQLServerAgent service through subsystem.
    required: false
    type: str
  on_success_action:
    description:
      - The action to perform if the step succeeds.
    required: false
    type: str
    default: 'QuitWithSuccess'
    choices: ['QuitWithSuccess', 'QuitWithFailure', 'GoToNextStep', 'GoToStep']
  on_success_step_id:
    description:
      - The ID of the step in this job to execute if the step succeeds and I(on_success_action=GoToStep).
    required: false
    type: int
    default: 0
  on_fail_action:
    description:
      - The action to perform if the step fails.
    required: false
    type: str
    default: 'QuitWithFailure'
    choices: ['QuitWithSuccess', 'QuitWithFailure', 'GoToNextStep', 'GoToStep']
  on_fail_step_id:
    description:
      - The ID of the step in this job to execute if the step fails and I(on_fail_action=GoToStep).
    required: false
    type: int
    default: 0
  retry_attempts:
    description:
      - The number of retry attempts to use if this step fails. The default is C(0).
    required: false
    type: int
    default: 0
  retry_interval:
    description:
      - The amount of time in minutes between retry attempts.
    required: false
    type: int
    default: 0
  output_file:
    description:
      - The full path to the output file for the job step.
      - This specifies where the output of the job step will be written.
    version_added: 2.7.0
    required: false
    type: str
author: "John McCall (@lowlydba)"
requirements:
  - L(dbatools,https://www.powershellgallery.com/packages/dbatools/) PowerShell module
extends_documentation_fragment:
  - lowlydba.sqlserver.sql_credentials
  - lowlydba.sqlserver.attributes.check_mode
  - lowlydba.sqlserver.attributes.platform_all
  - lowlydba.sqlserver.state
'''

EXAMPLES = r'''
- name: Create a job
  lowlydba.sqlserver.agent_job:
    sql_instance: sql-01.myco.io
    job: MyJob
    force: true

- name: Create a job step
  lowlydba.sqlserver.agent_job_step:
    sql_instance: sql-01.myco.io
    job: MyJob
    step_name: Step1
    step_id: 1
    command: "TRUNCATE TABLE dbo.TestData;"

- name: Create a job step with output file
  lowlydba.sqlserver.agent_job_step:
    sql_instance: sql-01.myco.io
    job: MyJob
    step_name: Step2
    step_id: 2
    command: "SELECT * FROM sys.databases;"
    output_file: "C:\\Logs\\MyJob_Step2.log"
'''

RETURN = r'''
data:
  description: Output from the C(New-DbaAgentJobStep), C(Set-DbaAgentJobStep), or C(Remove-DbaAgentJobStep) function.
  returned: success, but not in check_mode.
  type: dict
'''
