#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: rg_resource_pool
short_description: Configures a resource pool for use by the Resource Governor
description:
  - Creates or modifies a resource pool to be used by the Resource Governor. Default values are handled by the Powershell functions themselves.
version_added: 0.1.0
options:
  resource_pool:
    description:
      - Name of the target resource pool.
    type: str
    required: true
  type:
    description:
      - Specify the type of resource pool.
    type: str
    required: false
    default: 'Internal'
    choices: ['Internal', 'External']
  max_cpu_perc:
    description:
      - Maximum CPU Percentage able to be used by queries in this resource pool.
    type: int
    required: false
  min_cpu_perc:
    description:
      - Minimum CPU Percentage able to be used by queries in this resource pool.
    type: int
    required: false
  cap_cpu_perc:
    description:
      - Cap CPU Percentage able to be used by queries in this resource pool.
    type: int
    required: false
  max_mem_perc:
    description:
      - Maximum Memory Percentage able to be used by queries in this resource pool.
    type: int
    required: false
  min_mem_perc:
    description:
      - Minimum Memory Percentage able to be used by queries in this resource pool.
    type: int
    required: false
  max_iops_per_vol:
    description:
      - Maximum IOPS/volume able to be used by queries in this resource pool.
    type: int
    required: false
  min_iops_per_vol:
    description:
      - Minimum IOPS/volume able to be used by queries in this resource pool.
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
'''

RETURN = r'''
data:
  description: Output from the C(Set-DbaRgResourcePool), C(New-DbaRgResourcePool), or C(Remove-DbaRgResourcePool) function.
  returned: success, but not in check_mode.
  type: dict
'''
