#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: snmp_properties
short_description: Resource module for Snmp Properties
description:
  - Manage operation create of the resource Snmp Properties.
  - Adds SNMP properties.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  payload:
    description: Snmp Properties's payload.
    elements: dict
    suboptions:
      id:
        description: Snmp Properties's id.
        type: str
      instanceTenantId:
        description: Snmp Properties's instanceTenantId.
        type: str
      instanceUuid:
        description: Snmp Properties's instanceUuid.
        type: str
      intValue:
        description: Snmp Properties's intValue.
        type: int
      systemPropertyName:
        description: Snmp Properties's systemPropertyName.
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Discovery
      CreateUpdateSNMPProperties
    description: Complete reference of the CreateUpdateSNMPProperties
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-update-snmp-properties
notes:
  - SDK Method used are
    discovery.Discovery.create_update_snmp_properties,
  - Paths used are
    post /dna/intent/api/v1/snmp-property,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.snmp_properties:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - id: string
        instanceTenantId: string
        instanceUuid: string
        intValue: 0
        systemPropertyName: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""
