#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: security_threats_rogue_allowed_list
short_description: Resource module for Security Threats
  Rogue Allowed-List
description:
  - Manage operations create and delete of the resource
    Security Threats Rogue Allowed-List.
  - Intent API to add the threat mac address to allowed
    list.
  - Intent API to remove the threat mac address from
    allowed list.
version_added: '6.16.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  macAddress:
    description: MacAddress path parameter. Threat mac
      address which needs to be removed from the allowed
      list. Multiple mac addresses will be removed if
      provided as comma separated values (example 00
      2A 10 51 22 43,00 2A 10 51 22 44). Note In one
      request, maximum 100 mac addresses can be removed.
    type: str
  payload:
    description: Security Threats Rogue Allowed List's
      payload.
    elements: dict
    suboptions:
      category:
        description: Category.
        type: int
      macAddress:
        description: Mac Address.
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      AddAllowedMacAddress
    description: Complete reference of the AddAllowedMacAddress
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-allowed-mac-address
  - name: Cisco DNA Center documentation for Devices
      RemoveAllowedMacAddress
    description: Complete reference of the RemoveAllowedMacAddress
      API.
    link: https://developer.cisco.com/docs/dna-center/#!remove-allowed-mac-address
notes:
  - SDK Method used are
    devices.Devices.add_allowed_mac_address,
    devices.Devices.remove_allowed_mac_address,
  - Paths used are
    post /dna/intent/api/v1/security/threats/rogue/allowed-list,
    delete /dna/intent/api/v1/security/threats/rogue/allowed-list/{macAddress},
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.security_threats_rogue_allowed-list:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - category: 0
        macAddress: string
- name: Delete by id
  cisco.dnac.security_threats_rogue_allowed-list:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    macAddress: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": "string",
      "error": {}
    }
"""
