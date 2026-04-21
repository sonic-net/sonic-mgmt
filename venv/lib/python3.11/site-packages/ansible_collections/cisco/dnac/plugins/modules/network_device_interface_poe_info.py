#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_interface_poe_info
short_description: Information module for Network Device
  Interface Poe
description:
  - Get all Network Device Interface Poe. - > Returns
    POE interface details for the device, where deviceuuid
    is mandatory & accepts comma seperated interface
    names which is optional and returns information
    for that particular interfaces where operStatus
    = operationalStatus .
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  deviceUuid:
    description:
      - DeviceUuid path parameter. Uuid of the device.
    type: str
  interfaceNameList:
    description:
      - InterfaceNameList query parameter. Comma seperated
        interface names.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      ReturnsPOEInterfaceDetailsForTheDevice
    description: Complete reference of the ReturnsPOEInterfaceDetailsForTheDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!returns-poe-interface-details-for-the-device
notes:
  - SDK Method used are
    devices.Devices.poe_interface_details,
  - Paths used are
    get /dna/intent/api/v1/network-device/{deviceUuid}/interface/poe-detail,
"""

EXAMPLES = r"""
---
- name: Get all Network Device Interface Poe
  cisco.dnac.network_device_interface_poe_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    interfaceNameList: string
    deviceUuid: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "version": "string",
      "response": [
        {
          "adminStatus": "string",
          "operStatus": "string",
          "interfaceName": "string",
          "maxPortPower": "string",
          "allocatedPower": "string",
          "portPowerDrawn": "string"
        }
      ]
    }
"""
