#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: ag_listener
short_description: Configures an availability group listener
description:
  - Creates an Availability Group Listener for an existing availability group.
version_added: 0.5.0
options:
  ag_name:
    description:
      - Name of the target availability group.
    type: str
    required: true
  listener_name:
    description:
      - Name of the Listener to be configured.
    type: str
    required: true
  ip_address:
    description:
      - IP address(es) of the listener. Comma separated if multiple.
    type: list
    elements: str
    required: false
  subnet_ip:
    description:
      - Subnet IP address(es) of the listener. Comma separated if multiple.
    type: list
    elements: str
    required: false
  subnet_mask:
    description:
      - Sets the subnet IP mask(s) of the availability group listener. Comma separated if multiple.
    type: list
    elements: str
    required: false
    default: 255.255.255.0
  port:
    description:
      - Sets the port number used to communicate with the availability group.
    type: int
    required: false
    default: 1433
  dhcp:
    description:
      - Indicates whether the listener uses DHCP.
    type: bool
    required: false
    default: false
author: "John McCall (@lowlydba)"
requirements:
  - L(dbatools,https://www.powershellgallery.com/packages/dbatools/) PowerShell module
extends_documentation_fragment:
  - lowlydba.sqlserver.attributes.check_mode
  - lowlydba.sqlserver.attributes.platform_all
  - lowlydba.sqlserver.sql_credentials
  - lowlydba.sqlserver.state
'''

EXAMPLES = r'''
- name: Create Availability Group
  lowlydba.sqlserver.availability_group:
    sql_instance: sql-01.myco.io
    ag_name: AG_MyDatabase

- name: Create AG Listener
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
'''

RETURN = r'''
data:
  description: Output from the C(Add-DbaAgListener) or C(Set-DbaAgListener) function.
  returned: success, but not in check_mode.
  type: dict
'''
