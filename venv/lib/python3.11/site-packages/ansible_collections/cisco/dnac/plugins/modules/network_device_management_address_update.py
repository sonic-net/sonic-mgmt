#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_management_address_update
short_description: Resource module for Network Device
  Management Address Update
description:
  - Manage operation update of the resource Network
    Device Management Address Update.
  - This is a simple PUT API to edit the management
    IP Address of the device.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  deviceid:
    description: Deviceid path parameter. The UUID of
      the device whose management IP address is to be
      updated.
    type: str
  newIP:
    description: New IP Address of the device to be
      Updated.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      UpdateDeviceManagementAddress
    description: Complete reference of the UpdateDeviceManagementAddress
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-device-management-address
notes:
  - SDK Method used are
    devices.Devices.update_device_management_address,
  - Paths used are
    put /dna/intent/api/v1/network-device/{deviceid}/management-address,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.network_device_management_address_update:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    deviceid: string
    newIP: string
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
