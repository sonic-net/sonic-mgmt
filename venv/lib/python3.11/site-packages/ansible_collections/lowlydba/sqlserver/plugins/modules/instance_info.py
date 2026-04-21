#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: instance_info
short_description: Returns basic information for a SQL Server instance
description:
  - Returns basic information for a SQL Server instance.
version_added: 0.2.0
author: "John McCall (@lowlydba)"
requirements:
  - L(dbatools,https://www.powershellgallery.com/packages/dbatools/) PowerShell module
extends_documentation_fragment:
  - lowlydba.sqlserver.sql_credentials
  - lowlydba.sqlserver.attributes.check_mode_read_only
  - lowlydba.sqlserver.attributes.platform_all
'''

EXAMPLES = r'''
- name: Get basic info for an instance
  lowlydba.sqlserver.instance_info:
    sql_instance: sql-01.myco.io
'''

RETURN = r'''
data:
  description: Instance level properties of the SQL Server instance.
  returned: always
  type: dict
'''
