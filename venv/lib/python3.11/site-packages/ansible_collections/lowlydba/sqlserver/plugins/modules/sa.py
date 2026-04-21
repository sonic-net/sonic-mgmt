#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: sa
short_description: Configure the C(sa) login for security best practices
description:
  - Rename, disable, and reset the password for the C(sa) login on a SQL Server instance per best practices.
options:
  password:
    description:
      - Password for the login.
    type: str
    required: false
  new_name:
    description:
      - The new name to rename the C(sa) login to.
    type: str
    required: false
  enabled:
    description:
      - Whether the login is enabled or disabled.
    type: bool
    required: false
    default: true
    version_added: '0.4.0'
  password_must_change:
    description:
      - Enforces user must change password at next login.
      - When specified, will enforce I(password_expiration_enabled) and I(password_policy_enforced) as they are required.
    type: bool
    required: false
  password_policy_enforced:
    description:
      - Enforces password complexity policy.
    type: bool
    required: false
  password_expiration_enabled:
    description:
      - Enforces password expiration policy. Requires I(password_policy_enforced=true).
    type: bool
    required: false
version_added: 0.3.0
author: "John McCall (@lowlydba)"
requirements:
  - L(dbatools,https://www.powershellgallery.com/packages/dbatools/) PowerShell module
extends_documentation_fragment:
  - lowlydba.sqlserver.sql_credentials
  - lowlydba.sqlserver.attributes.check_mode
  - lowlydba.sqlserver.attributes.platform_all
'''

EXAMPLES = r'''
- name: Disable sa login
  lowlydba.sqlserver.sa:
    sql_instance: sql-01.myco.io
    enabled: false

- name: Rename sa login
  lowlydba.sqlserver.sa:
    sql_instance: sql-01.myco.io
    new_name: 'notthesayourelookingfor'
'''

RETURN = r'''
data:
  description: Output from the C(Set-DbaLogin) function.
  returned: success, but not in check_mode.
  type: dict
'''
