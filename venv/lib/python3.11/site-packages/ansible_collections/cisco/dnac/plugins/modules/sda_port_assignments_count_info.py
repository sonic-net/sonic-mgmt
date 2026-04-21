#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_port_assignments_count_info
short_description: Information module for Sda Port Assignments
  Count
description:
  - Get all Sda Port Assignments Count.
  - Returns the count of port assignments that match
    the provided query parameters.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  fabricId:
    description:
      - FabricId query parameter. ID of the fabric the
        device is assigned to.
    type: str
  networkDeviceId:
    description:
      - NetworkDeviceId query parameter. Network device
        ID of the port assignment.
    type: str
  interfaceName:
    description:
      - InterfaceName query parameter. Interface name
        of the port assignment.
    type: str
  dataVlanName:
    description:
      - DataVlanName query parameter. Data VLAN name
        of the port assignment.
    type: str
  voiceVlanName:
    description:
      - VoiceVlanName query parameter. Voice VLAN name
        of the port assignment.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA GetPortAssignmentCount
    description: Complete reference of the GetPortAssignmentCount
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-port-assignment-count
notes:
  - SDK Method used are
    sda.Sda.get_port_assignment_count,
  - Paths used are
    get /dna/intent/api/v1/sda/portAssignments/count,
"""

EXAMPLES = r"""
---
- name: Get all Sda Port Assignments Count
  cisco.dnac.sda_port_assignments_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    fabricId: string
    networkDeviceId: string
    interfaceName: string
    dataVlanName: string
    voiceVlanName: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "count": 0
      },
      "version": "string"
    }
"""
