#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: login_role
short_description: Configures a login's  server roles.
description:
  - Adds or removes a login's server role.
version_added: 2.5.0
options:
  login:
    description:
      - Name of the login.
    type: str
    required: true
  server_role:
    description:
      - The server role for the login to be modified.
    type: str
    required: true
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
- name: Add a user to a fixed server role
  lowlydba.sqlserver.login_role:
    sql_instance: sql-01.myco.io
    login: TheIntern
    server_role: sysadmin

- name: Remove a user from a fixed server role
  lowlydba.sqlserver.login_role:
    sql_instance: sql-01.myco.io
    login: TheIntern
    server_role: sysadmin
    state: absent

- name: Add a user to a custom server role
  lowlydba.sqlserver.login_role:
    sql_instance: sql-01.myco.io
    login: TheIntern
    server_role: demi-admin
'''

RETURN = r'''
data:
  description: Output from the C(Remove-DbaServerRoleMember), (Get-DbaServerRoleMember), or C(Add-DbaServerRoleMember) functions.
  returned: success, but not in check_mode.
  type: dict
'''
