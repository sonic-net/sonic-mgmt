#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: dba_multitool
short_description: Install/update the DBA Multitool suite by John McCall
description:
  - A wrapper for C(Install-DbaMultiTool) to fetch the latest version of the scripts, or install from a local cached version.
version_added: 0.7.0
options:
  sql_instance:
    description:
      - The target SQL Server instance or instances. Server version must be SQL Server version 2005 or higher.
    type: str
    required: true
  local_file:
    description:
      - Specifies the path to a local file to install DBA MultiTool from. This should be the zip file as distributed by the maintainers.
      - If this option is not specified, the latest version will be downloaded and installed from https://github.com/LowlyDBA/dba-multitool/.
    type: str
    required: false
  branch:
    description:
      - Specifies an alternate branch of the DBA MultiTool to install.
    type: str
    required: false
    choices: ['master', 'development']
  database:
    description:
      - Name of the target database.
    type: str
    required: true
  force:
    description:
      - If this switch is enabled, the DBA MultiTool will be downloaded from the internet even if previously cached.
    type: bool
    default: false
author: "John McCall (@lowlydba)"
requirements:
  - L(dbatools,https://www.powershellgallery.com/packages/dbatools/) PowerShell module
extends_documentation_fragment:
  - lowlydba.sqlserver.sql_credentials
  - lowlydba.sqlserver.attributes.check_mode
  - lowlydba.sqlserver.attributes.platform_all
'''

EXAMPLES = r'''
- name: Install DBA MultiTool
  lowlydba.sqlserver.dba_multitool:
    sql_instance: test-server.my.company.com
    database: dba_tools
'''

RETURN = r'''
data:
  description: Modified output from the C(Install-DbaMultitool) function.
  returned: success, but not in check_mode.
  type: dict
'''
