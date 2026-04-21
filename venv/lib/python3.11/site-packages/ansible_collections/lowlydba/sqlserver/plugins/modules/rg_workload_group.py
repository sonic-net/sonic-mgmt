#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: rg_workload_group
short_description: Configures a workload group for use by the Resource Governor
description:
  - Creates or modifies a workload group to be used by the Resource Governor. Default values are handled by the Powershell functions themselves.
version_added: 0.1.0
options:
  workload_group:
    description:
      - Name of the target workload group.
    type: str
    required: true
  resource_pool:
    description:
      - Name of the resource pool for the workload group.
    type: str
    required: true
  resource_pool_type:
    description:
      - Specify the type of resource pool.
    type: str
    required: false
    default: 'Internal'
    choices: ['Internal', 'External']
  group_max_requests:
    description:
      - Specifies the maximum number of simultaneous requests that are allowed to execute in the workload group.
    type: int
    required: false
  importance:
    description:
      - Specifies the relative importance of a request in the workload group.
    type: str
    required: false
    choices: ['Low', 'Medium', 'High']
  max_dop:
    description:
      - Specifies the maximum degree of parallelism (MAXDOP) for parallel query execution.
    type: int
    required: false
  request_max_cpu_time:
    description:
      - Specifies the maximum amount of CPU time, in seconds, that a request can use.
    type: int
    required: false
  request_max_mem_grant_perc:
    description:
      - Specifies the maximum amount of memory that a single request can take from the pool.
    type: int
    required: false
  request_mem_grant_timeout_sec:
    description:
      - Specifies the maximum time, in seconds, that a query can wait for a memory grant (work buffer memory) to become available.
    type: int
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
- name: Enable resource governor
  lowlydba.sqlserver.resource_governor:
    sql_instance: sql-01.myco.io
    enabled: true

- name: Create rg resource pool
  lowlydba.sqlserver.rg_resource_pool:
    sql_instance: sql-01.myco.io
    resource_pool: "rpLittle"
    max_cpu_perc: 5

- name: Create rg workload group
  lowlydba.sqlserver.rg_workload_group:
    sql_instance: sql-01.myco.io
    workload_group: rgMyGroup
    resource_pool: rpLittle
    resource_pool_type: Internal
    max_dop: 2
    state: present
'''

RETURN = r'''
data:
  description: Output from the C(Set-DbaRgWorkloadGroup), C(New-DbaRgWorkloadGroup), or C(Remove-DbaRgWorkloadGroup) function.
  returned: success, but not in check_mode.
  type: dict
'''
