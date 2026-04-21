#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# (c) 2021, Sudhir Koduri (@kodurisudhir)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: sp_configure
short_description: Make instance level system configuration changes via C(sp_configure)
description:
  - Read instance level system configuration for a given configuration and update to a new value as provided.
version_added: 0.1.0
options:
  name:
    description:
      - Name of the configuration that will be changed.
    type: str
    required: true
  value:
    description:
      - New value the configuration will be set to.
    type: int
    required: true
author: "Sudhir Koduri (@kodurisudhir)"
requirements:
  - L(dbatools,https://www.powershellgallery.com/packages/dbatools/) PowerShell module
extends_documentation_fragment:
  - lowlydba.sqlserver.sql_credentials
  - lowlydba.sqlserver.attributes.check_mode
  - lowlydba.sqlserver.attributes.platform_all
'''

EXAMPLES = r'''
- name: Enable remote DAC connection
  lowlydba.sqlserver.sp_configure:
    sql_instance: sql-01.myco.io
    name: RemoteDacConnectionsEnabled
    value: 1
'''

RETURN = r'''
data:
  description:
    - Output from the C(Set-DbaSpConfigure) function.
    - RestartRequired returned if the setting requires a service restart to take effect.
  returned: success, but not in check_mode.
  type: dict
'''
