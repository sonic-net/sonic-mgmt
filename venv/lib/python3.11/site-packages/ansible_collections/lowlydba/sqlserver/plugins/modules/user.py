#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: user
short_description: Configures a user within a database
description:
  - Creates, modifies, or removes a user in a database.
version_added: 1.1.0
options:
  login:
    description:
      - Name of the login that the user is mapped to.
    type: str
    required: true
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
  external_provider:
    description:
      - Specifies that the user is for Azure AD Authentication. Only used when creating a new user, this cannot be modified for an existing user.
    type: bool
    required: false
  default_schema:
    description:
      - The default database schema for the user.
    type: str
    required: false
    default: "dbo"
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
- name: Create a user
  lowlydba.sqlserver.user:
    sql_instance: sql-01.myco.io
    login: TheIntern
    username: TheIntern
    database: InternProject1

- name: Change user's schema
  lowlydba.sqlserver.login:
    sql_instance: sql-01.myco.io
    login: TheIntern
    username: TheIntern
    database: InternProject1
    default_schema: dev

- name: Remove a user
  lowlydba.sqlserver.login:
    sql_instance: sql-01.myco.io
    login: TheIntern
    username: TheIntern
    database: InternProject1
    state: absent
'''

RETURN = r'''
data:
  description: Output from the C(New-DbaDbUser), C(Get-DbaDbUser), or C(Remove-DbaDbUser) function.
  returned: success, but not in check_mode.
  type: dict
'''
