#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sites_device_credentials_status_info
short_description: Information module for Sites Device
  Credentials Status
description:
  - Get all Sites Device Credentials Status.
  - Get network devices credentials sync status at a
    given site.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. Site Id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings GetNetworkDevicesCredentialsSyncStatus
    description: Complete reference of the GetNetworkDevicesCredentialsSyncStatus
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-network-devices-credentials-sync-status
notes:
  - SDK Method used are
    network_settings.NetworkSettings.get_network_devices_credentials_sync_status,
  - Paths used are
    get /dna/intent/api/v1/sites/{id}/deviceCredentials/status,
"""

EXAMPLES = r"""
---
- name: Get all Sites Device Credentials Status
  cisco.dnac.sites_device_credentials_status_info:
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
      "response": {
        "cli": [
          {
            "deviceCount": 0,
            "status": "string"
          }
        ],
        "snmpV2Read": [
          {
            "deviceCount": 0,
            "status": "string"
          }
        ],
        "snmpV2Write": [
          {
            "deviceCount": 0,
            "status": "string"
          }
        ],
        "snmpV3": [
          {
            "deviceCount": 0,
            "status": "string"
          }
        ]
      },
      "version": "string"
    }
"""
