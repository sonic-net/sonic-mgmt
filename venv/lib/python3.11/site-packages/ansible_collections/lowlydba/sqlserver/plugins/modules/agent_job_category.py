#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: agent_job_category
short_description: Configures a SQL Agent job category
description:
  - Configures a SQL Agent job category. Creates if it does not exist, else does nothing.
version_added: 0.1.0
options:
  category:
    description:
      - Name of the category.
    required: true
    type: str
  category_type:
    description:
      - The type of category.
    required: false
    type: str
    choices: ['LocalJob', 'MultiServerJob', 'None']
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
- name: Create a maintenance job category
  lowlydba.sqlserver.agent_job_category:
    sql_instance: sql-01.myco.io
    category: "Index Maintenance"
'''

RETURN = r'''
data:
  description: Output from the C(New-DbaAgentJobCategory) or C(Remove-DbaAgentJobCategory) function.
  returned: success, but not in check_mode.
  type: dict
'''
