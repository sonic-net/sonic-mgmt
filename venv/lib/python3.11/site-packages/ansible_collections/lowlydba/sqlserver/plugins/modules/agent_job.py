#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: agent_job
short_description: Configures a SQL Agent job
description:
  - Configure a SQL Agent job, including which schedules and category it belongs to.
version_added: 0.1.0
options:
  job:
    description:
      - The name of the target SQL Agent job.
    type: str
    required: true
  description:
    description:
      - Description for the SQL Agent job.
    type: str
    required: false
  category:
    description:
      - Category for the target SQL Agent job. Must already exist.
    type: str
    required: false
  enabled:
    description:
      - Whether the SQL Agent job should be enabled or disabled.
    type: bool
    required: false
    default: true
    version_added: '0.4.0'
  owner_login:
    description:
      - The owning login for the database. Will default to the current user if
        the database is being created and none supplied.
    type: str
    required: false
  start_step_id:
    description:
      - What step number the job should begin with when run.
    type: int
    required: false
  schedule:
    description:
      - The name of the schedule the job should be associated with. Only one schedule per job is supported.
    type: str
    required: false
  force:
    description:
      - If I(force=true), any job categories will be created if they don't exist already.
    type: bool
    default: false
author: "John McCall (@lowlydba)"
notes:
  - On slower hardware, stale job component data may be returned (i.e., a previous or default job category).
    Configuring each component (schedule, step, category, etc.) individually is recommended for this reason.
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
'''

RETURN = r'''
data:
  description: Output from the C(New-DbaAgentJob), C(Set-DbaAgentJob), or C(Remove-DbaAgentJob) function.
  returned: success, but not in check_mode.
  type: dict
'''
