#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: fabrics_fabric_id_switch_wireless_setting_info
short_description: Information module for Fabrics Fabric
  Id Switch Wireless Setting
description:
  - Get all Fabrics Fabric Id Switch Wireless Setting.
    - > Get the SDA Wireless details from the switches
    on the fabric site that have wireless capability
    enabled. A maximum of two switches can have a wireless
    role in a fabric site.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  fabricId:
    description:
      - >
        FabricId path parameter. The 'fabricId' represents
        the Fabric ID of a particular Fabric Site. The
        'fabricId' can be obtained using the api /dna/intent/api/v1/sda/fabricSites.
        Example e290f1ee-6c54-4b01-90e6-d701748f0851.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Fabric
      Wireless GetSDAWirelessDetailsFromSwitches
    description: Complete reference of the GetSDAWirelessDetailsFromSwitches
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-sda-wireless-details-from-switches
notes:
  - SDK Method used are
    fabric_wireless.FabricWireless.get_sda_wireless_details_from_switches,
  - Paths used are
    get /dna/intent/api/v1/sda/fabrics/{fabricId}/switchWirelessSetting,
"""

EXAMPLES = r"""
---
- name: Get all Fabrics Fabric Id Switch Wireless Setting
  cisco.dnac.fabrics_fabric_id_switch_wireless_setting_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    fabricId: string
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
          "enableWireless": true,
          "rollingApUpgrade": {
            "enableRollingApUpgrade": true,
            "apRebootPercentage": 0
          }
        }
      ],
      "version": "string"
    }
"""
