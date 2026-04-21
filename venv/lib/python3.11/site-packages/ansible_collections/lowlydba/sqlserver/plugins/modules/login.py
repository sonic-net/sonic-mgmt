#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: login
short_description: Configures a login for the target SQL Server instance
description:
  - Creates, modifies, or removes a Windows or SQL Authentication login on a SQL Server instance.
version_added: 0.1.0
options:
  login:
    description:
      - Name of the login to configure.
    type: str
    required: true
  password:
    description:
      - Password for the login, if SQL Authentication login.
    type: str
    required: false
  enabled:
    description:
      - Whether the login is enabled or disabled.
    type: bool
    required: false
    default: true
    version_added: '0.4.0'
  default_database:
    description:
      - Default database for the login.
    type: str
    required: false
  language:
    description:
      - Default language for the login. Only used when creating a new login, not when modifying an existing one.
    type: str
    required: false
  password_must_change:
    description:
      - Enforces user must change password at next login.
      - When specified will enforce I(password_expiration_enabled) and I(password_policy_enforced) as they are required.
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
  sid:
    description:
      - Provide an explicit Sid that should be used when creating the account.
    type: str
    required: false
    version_added: '2.1.0'
  skip_password_reset:
    description:
      - Skips the password reset if the login exists and I(password) is set.
    type: bool
    required: false
    default: false
    version_added: '2.3.0'
author: "John McCall (@lowlydba)"
notes:
  - Module will always return changed if a password is supplied.
requirements:
  - L(dbatools,https://www.powershellgallery.com/packages/dbatools/) PowerShell module
extends_documentation_fragment:
  - lowlydba.sqlserver.sql_credentials
  - lowlydba.sqlserver.attributes.check_mode
  - lowlydba.sqlserver.attributes.platform_all
  - lowlydba.sqlserver.state
'''

EXAMPLES = r'''
- name: Create a login
  lowlydba.sqlserver.login:
    sql_instance: sql-01.myco.io
    login: TheIntern
    password: ReallyComplexStuff12345!

- name: Disable a login
  lowlydba.sqlserver.login:
    sql_instance: sql-01.myco.io
    login: TheIntern
    enabled: false
'''

RETURN = r'''
data:
  description: Output from the C(New-DbaLogin), C(Set-DbaLogin), or C(Remove-DbaLogin) function.
  returned: success, but not in check_mode.
  type: dict
'''
