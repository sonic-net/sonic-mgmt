#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: agent_job_schedule
short_description: Configures a SQL Agent job schedule
description:
  - Configures settings for an agent schedule that can be applied to one or more agent jobs.
version_added: 0.1.0
options:
  schedule:
    description:
      - The name of the schedule.
    type: str
    required: true
  job:
    description:
      - The name of the job that has the schedule.
      - Schedules and jobs can also be associated via M(lowlydba.sqlserver.agent_job).
      - See U(https://docs.dbatools.io/New-DbaAgentSchedule) for more detailed usage.
    type: str
    required: true
  enabled:
    description:
      - Whether the schedule is enabled or disabled.
    type: bool
    required: false
  force:
    description:
      - The force option will ignore some errors in the options and assume defaults.
      - It will also remove the any present schedules with the same name for the specific job.
    type: bool
  frequency_type:
    description:
      - A value indicating when a job is to be executed.
      - If I(force=true) the default will be C(Once).
    type: str
    required: false
    choices: ['Once', 'OneTime', 'Daily', 'Weekly', 'Monthly', 'MonthlyRelative', 'AgentStart', 'AutoStart', 'IdleComputer', 'OnIdle']
  frequency_interval:
    description:
      - The days that a job is executed.
      - Allowed values for I(frequency_type=Daily) - C(EveryDay) or a number between C(1) and C(365) inclusive.
      - >-
        Allowed values for I(frequency_type=Weekly) -
        C(Sunday), C(Monday), C(Tuesday), C(Wednesday), C(Thursday), C(Friday), C(Saturday),
        C(Weekdays), C(Weekend) or C(EveryDay).
      - Allowed values for I(frequency_type=Monthly) - Numbers C(1) through C(31) for each day of the month.
      - If C(Weekdays), C(Weekend) or C(EveryDay) is used it overwrites any other value that has been passed before.
      - If I(force=true) the default will be C(1).
    type: str
    required: false
  frequency_subday_type:
    description:
      - Specifies the units for the subday I(frequency_interval).
    type: str
    required: false
    choices: ['Time', 'Seconds', 'Minutes', 'Hours']
  frequency_subday_interval:
    description:
      - The number of subday type periods to occur between each execution of a job.
    type: int
    required: false
  frequency_relative_interval:
    description:
      - A job's occurrence of I(frequency_interval) in each month. If I(frequency_interval=32) (C(MonthlyRelative)).
    type: str
    required: false
    choices: ['Unused', 'First', 'Second', 'Third', 'Fourth', 'Last']
  frequency_recurrence_factor:
    description:
      - The number of weeks or months between the scheduled execution of a job.
      - Required if I(frequency_type=Weekly), I(frequency_type=Monthly) or I(frequency_type=MonthlyRelative).
    type: int
    required: false
  start_date:
    description:
      - The date on which execution of a job can begin.
      - If I(force=true) the start date will be the current day.
      - Format is C(yyyyMMdd).
    type: str
    required: false
  end_date:
    description:
      - The date on which execution of a job can stop.
      - If I(force=true) the end date will be C(99991231), via dbatools.
      - Format is C(yyyyMMdd).
    type: str
    required: false

  start_time:
    description:
      - The time on any day to begin execution of a job. Format C(HHMMSS) (24 hour clock).
      - If I(force=true) the start time will be C(00:00:00).
    type: str
    required: false
  end_time:
    description:
      - The time on any day to end execution of a job. Format C(HHMMSS) (24 hour clock).
      - If (force=true) the start time will be C(23:59:59).
    type: str
    required: false
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
- name: Create a job schedule
  lowlydba.sqlserver.agent_job_schedule:
    sql_instance: sql-01.myco.io
    schedule: DailySchedule
    force: true
    enabled: true
    start_date: 2020-05-25  # May 25, 2020
    end_date: 2099-05-25    # May 25, 2099
    start_time: 010500      # 01:05:00 AM
    end_time: 140030        # 02:00:30 PM
    state: present

- name: Create a job with schedule
  lowlydba.sqlserver.agent_job:
    sql_instance: sql-01.myco.io
    job: MyJob
    force: true
    schedule: DailySchedule
'''

RETURN = r'''
data:
  description: Output from the C(New-DbaAgentJobSchedule) or C(Remove-DbaAgentJobSchedule) function.
  returned: success, but not in check_mode.
  type: dict
'''
