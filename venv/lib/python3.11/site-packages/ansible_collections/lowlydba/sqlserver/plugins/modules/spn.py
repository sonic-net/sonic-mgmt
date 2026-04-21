#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: spn
short_description: Configures SPNs for SQL Server
description:
  - Configures SPNs for SQL Server.
version_added: 0.6.0
options:
  computer_username:
    description:
      - Username of a credential to connect to Active Directory with.
    type: str
    required: false
  computer_password:
    description:
      - Password of a credential to connect to Active Directory with.
    type: str
    required: false
  computer:
    description:
      - The host or alias to configure the SPN for. Can include the port in the format C(host:port).
    type: str
    required: true
  service_account:
    description:
      - The account you want the SPN added to. Will be looked up if not provided.
    type: str
    required: true
author: "John McCall (@lowlydba)"
requirements:
  - L(dbatools,https://www.powershellgallery.com/packages/dbatools/) PowerShell module
extends_documentation_fragment:
  - lowlydba.sqlserver.state
  - lowlydba.sqlserver.attributes.check_mode
  - lowlydba.sqlserver.attributes.platform_win
'''

EXAMPLES = r'''
- name: Add server SPN
  lowlydba.sqlserver.spn:
    computer: sql-01.myco.io
    service_account: myco\sql-svc

- name: Create an AG Listener
  lowlydba.sqlserver.ag_listener:
    sql_instance_primary: sql-01.myco.io
    ag_name: AG_MyDatabase
    listener_name: aglMyDatabase
    ip_address:
      - 10.0.20.20
      - 10.1.77.77
    subnet_ip:
      - 255.255.252.0
    subnet_mask:
      - 255.255.255.0

- name: Add SPN for new AG listener on port 1433
  lowlydba.sqlserver.spn:
    computer: aglMyDatabase.myco.io:1433
    service_account: myco\sql-svc
'''

RETURN = r'''
data:
  description: Output from the C(Set-DbaSpn) or C(Remove-DbaSpn) function.
  returned: success, but not in check_mode.
  type: dict
'''
