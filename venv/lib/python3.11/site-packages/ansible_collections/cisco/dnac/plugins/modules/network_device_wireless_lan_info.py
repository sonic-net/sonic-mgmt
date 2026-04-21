#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_wireless_lan_info
short_description: Information module for Network Device
  Wireless Lan
description:
  - Get all Network Device Wireless Lan.
  - Returns the wireless lan controller info with given
    device ID.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. Device ID.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      GetWirelessLanControllerDetailsById
    description: Complete reference of the GetWirelessLanControllerDetailsById
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-wireless-lan-controller-details-by-id
notes:
  - SDK Method used are
    devices.Devices.get_wireless_lan_controller_details_by_id,
  - Paths used are
    get /dna/intent/api/v1/network-device/{id}/wireless-info,
"""

EXAMPLES = r"""
---
- name: Get all Network Device Wireless Lan
  cisco.dnac.network_device_wireless_lan_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "adminEnabledPorts": [
        0
      ],
      "apGroupName": "string",
      "deviceId": "string",
      "ethMacAddress": "string",
      "flexGroupName": "string",
      "id": "string",
      "instanceTenantId": "string",
      "instanceUuid": "string",
      "lagModeEnabled": true,
      "netconfEnabled": true,
      "wirelessLicenseInfo": "string",
      "wirelessPackageInstalled": true
    }
"""
