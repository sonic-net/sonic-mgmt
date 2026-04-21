#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: resource_governor
short_description: Configures the resource governor on a SQL Server instance
description:
  - Enables or disables and optionally sets the classifier function for the resource governor feature.
version_added: 0.1.0
options:
  enabled:
    description:
      - Whether to enable or disable resource governor.
    type: bool
    required: false
    default: true
  classifier_function:
    description:
      - The name of the classifier function that resource governor will use. To clear the function, use the string C(NULL).
    type: str
    required: false
author: "John McCall (@lowlydba)"
requirements:
  - L(dbatools,https://www.powershellgallery.com/packages/dbatools/) PowerShell module
extends_documentation_fragment:
  - lowlydba.sqlserver.sql_credentials
  - lowlydba.sqlserver.attributes.check_mode
  - lowlydba.sqlserver.attributes.platform_all
'''

EXAMPLES = r'''
- name: Enable resource governor
  lowlydba.sqlserver.resource_governor:
    sql_instance: sql-01.myco.io
    enabled: true
'''

RETURN = r'''
data:
  description: Output from the C(Set-DbaResourceGovernor) function.
  returned: success, but not in check_mode.
  type: dict
'''
