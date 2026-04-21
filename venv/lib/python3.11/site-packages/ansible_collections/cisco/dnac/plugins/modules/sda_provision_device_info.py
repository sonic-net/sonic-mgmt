#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_provision_device_info
short_description: Information module for Sda Provision
  Device
description:
  - Get all Sda Provision Device.
  - Get Provisioned Wired Device.
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
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA GetProvisionedWiredDevice
    description: Complete reference of the GetProvisionedWiredDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-provisioned-wired-device
notes:
  - SDK Method used are
    sda.Sda.get_provisioned_wired_device,
  - Paths used are
    get /dna/intent/api/v1/business/sda/provision-device,
"""

EXAMPLES = r"""
---
- name: Get all Sda Provision Device
  cisco.dnac.sda_provision_device_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    deviceManagementIpAddress: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "deviceManagementIpAddress": "string",
      "siteNameHierarchy": "string",
      "status": "string",
      "description": "string"
    }
"""
