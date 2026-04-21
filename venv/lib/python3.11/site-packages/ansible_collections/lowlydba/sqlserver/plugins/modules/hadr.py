#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: hadr
short_description: Enable or disable HADR
description:
  - Enable or disable the High Availability Disaster Recovery (HADR) feature.
version_added: 0.4.0
options:
  sql_instance:
    description:
      - The SQL Server instance to modify.
    type: str
    required: true
  username:
    description:
      - Username for alternative credential to authenticate with Windows.
    type: str
    required: false
  password:
    description:
      - Password for alternative credential to authenticate with Windows.
    type: str
    required: false
  enabled:
    description:
      - Flag to enable or disable the feature.
    type: bool
    required: false
    default: true
  force:
    description:
      - Restart SQL Server and SQL Agent services automatically.
    type: bool
    required: false
    default: false
author: "John McCall (@lowlydba)"
requirements:
  - L(dbatools,https://www.powershellgallery.com/packages/dbatools/) PowerShell module
extends_documentation_fragment:
  - lowlydba.sqlserver.sql_credentials
  - lowlydba.sqlserver.attributes.check_mode
  - lowlydba.sqlserver.attributes.platform_win
'''

EXAMPLES = r'''
- name: Enable hadr with service restart
  lowlydba.sqlserver.hadr:
    sql_instance: sql-01.myco.io
    enabled: true
    force: true
'''

RETURN = r'''
data:
  description:
    - Output from the C(Enable-DbaAgHadr) or C(Disable-DbaAgHadr) function.
    - RestartRequired returned if the setting requires a service restart to take effect.
  returned: success, but not in check_mode.
  type: dict
'''
