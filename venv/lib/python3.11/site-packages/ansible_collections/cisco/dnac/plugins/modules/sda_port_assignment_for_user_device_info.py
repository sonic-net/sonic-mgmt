#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_port_assignment_for_user_device_info
short_description: Information module for Sda Port Assignment
  For User Device
description:
  - Get all Sda Port Assignment For User Device.
  - Get Port assignment for user device in SDA Fabric.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  deviceManagementIpAddress:
    description:
      - DeviceManagementIpAddress query parameter.
    type: str
  interfaceName:
    description:
      - InterfaceName query parameter.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA GetPortAssignmentForUserDeviceInSDAFabric
    description: Complete reference of the GetPortAssignmentForUserDeviceInSDAFabric
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-port-assignment-for-user-device-in-sda-fabric
notes:
  - SDK Method used are
    sda.Sda.get_port_assignment_for_user_device,
  - Paths used are
    get /dna/intent/api/v1/business/sda/hostonboarding/user-device,
"""

EXAMPLES = r"""
---
- name: Get all Sda Port Assignment For User Device
  cisco.dnac.sda_port_assignment_for_user_device_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    deviceManagementIpAddress: string
    interfaceName: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "status": "string",
      "description": "string",
      "siteNameHierarchy": "string",
      "deviceManagementIpAddress": "string",
      "interfaceName": "string",
      "dataIpAddressPoolName": "string",
      "voiceIpAddressPoolName": "string",
      "scalableGroupName": "string",
      "authenticateTemplateName": "string"
    }
"""
