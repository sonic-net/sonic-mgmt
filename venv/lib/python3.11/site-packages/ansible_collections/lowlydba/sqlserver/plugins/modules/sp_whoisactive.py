#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: sp_whoisactive
short_description: Install/update C(sp_whoisactive) by Adam Mechanic
description:
  - A wrapper for C(Install-DbaWhoIsActive) to fetch the latest version of the script, or install from a local cached version.
version_added: 0.1.0
options:
  local_file:
    description:
      - Specifies the path to a local file to install sp_WhoisActive from.
      - This can be either the zip file as distributed by the website or the expanded SQL script.
      - If this option is not specified, the latest version will be downloaded and installed from https://github.com/amachanic/sp_whoisactive/releases
    type: str
    required: false
  database:
    description:
      - Name of the target database.
    type: str
    required: true
  force:
    description:
      - If this switch is enabled, then C(sp_WhoisActive) will be downloaded from the internet even if previously cached.
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
- name: Install/Update sp_whoisactive
  lowlydba.sqlserver.sp_whoisactive:
    sql_instance: sql-01.myco.io
    database: lowlydb
'''

RETURN = r'''
data:
  description: Output from the C(Install-DbaWhoIsActive) function.
  returned: success, but not in check_mode.
  type: dict
'''
