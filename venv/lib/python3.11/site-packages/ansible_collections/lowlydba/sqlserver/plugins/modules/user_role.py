#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: user_role
short_description: Configures a user's role in a database.
description:
  - Adds or removes a user's role in a database.
version_added: 2.4.0
options:
  database:
    description:
      - Database for the user.
    type: str
    required: true
  username:
    description:
      - Name of the user.
    type: str
    required: true
  role:
    description:
      - The database role for the user to be modified.
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
- name: Add a user to a fixed db role
  lowlydba.sqlserver.user_role:
    sql_instance: sql-01.myco.io
    username: TheIntern
    database: InternProject1
    role: db_owner

- name: Remove a user from a fixed db role
  lowlydba.sqlserver.login:
    sql_instance: sql-01.myco.io
    username: TheIntern
    database: InternProject1
    role: db_owner
    state: absent

- name: Add a user to a custom db role
  lowlydba.sqlserver.login:
    sql_instance: sql-01.myco.io
    username: TheIntern
    database: InternProject1
    role: db_intern
    state: absent
'''

RETURN = r'''
data:
  description: Output from the C(Remove-DbaDbRoleMember), (Get-DbaDbRoleMember), or C(Add-DbaDbRoleMember) functions.
  returned: success, but not in check_mode.
  type: dict
'''
