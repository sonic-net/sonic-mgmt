#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: security_threats_rogue_allowed_list_count_info
short_description: Information module for Security Threats
  Rogue Allowed-List Count
description:
  - Get all Security Threats Rogue Allowed-List Count.
  - Intent API to fetch the count of allowed mac addresses
    in the system.
version_added: '6.16.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      GetAllowedMacAddressCount
    description: Complete reference of the GetAllowedMacAddressCount
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-allowed-mac-address-count
notes:
  - SDK Method used are
    devices.Devices.get_allowed_mac_address_count,
  - Paths used are
    get /dna/intent/api/v1/security/threats/rogue/allowed-list/count,
"""

EXAMPLES = r"""
---
- name: Get all Security Threats Rogue Allowed-List
    Count
  cisco.dnac.security_threats_rogue_allowed-list_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": 0,
      "version": "string"
    }
"""
