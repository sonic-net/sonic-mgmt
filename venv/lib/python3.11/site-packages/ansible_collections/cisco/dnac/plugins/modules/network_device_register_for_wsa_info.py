#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_register_for_wsa_info
short_description: Information module for Network Device
  Register For Wsa
description:
  - Get all Network Device Register For Wsa. - > It
    fetches devices which are registered to receive
    WSA notifications. The device serial number and/or
    MAC address are required to be provided as query
    parameters.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  serialNumber:
    description:
      - SerialNumber query parameter. Serial number
        of the device.
    type: str
  macaddress:
    description:
      - Macaddress query parameter. Mac addres of the
        device.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      GetDevicesRegisteredForWSANotification
    description: Complete reference of the GetDevicesRegisteredForWSANotification
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-devices-registered-for-wsa-notification
notes:
  - SDK Method used are
    devices.Devices.get_devices_registered_for_wsa_notification,
  - Paths used are
    get /dna/intent/api/v1/network-device/tenantinfo/macaddress,
"""

EXAMPLES = r"""
---
- name: Get all Network Device Register For Wsa
  cisco.dnac.network_device_register_for_wsa_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    serialNumber: string
    macaddress: string
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
        "macAddress": "string",
        "modelNumber": "string",
        "name": "string",
        "serialNumber": "string",
        "tenantId": "string"
      },
      "version": "string"
    }
"""
