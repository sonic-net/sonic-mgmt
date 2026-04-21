#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: snmp_properties_info
short_description: Information module for Snmp Properties
description:
  - Get all Snmp Properties.
  - Returns SNMP properties.
version_added: '3.1.0'
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
  - name: Cisco DNA Center documentation for Discovery
      GetSNMPProperties
    description: Complete reference of the GetSNMPProperties
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-snmp-properties
notes:
  - SDK Method used are
    discovery.Discovery.get_snmp_properties,
  - Paths used are
    get /dna/intent/api/v1/snmp-property,
"""

EXAMPLES = r"""
---
- name: Get all Snmp Properties
  cisco.dnac.snmp_properties_info:
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
      "response": [
        {
          "id": "string",
          "instanceTenantId": "string",
          "instanceUuid": "string",
          "intValue": 0,
          "systemPropertyName": "string"
        }
      ],
      "version": "string"
    }
"""
