#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pnp_virtual_account_sync_result_info
short_description: Information module for Pnp Virtual
  Account Sync Result
description:
  - Get all Pnp Virtual Account Sync Result.
  - Returns the summary of devices synced from the given
    smart account & virtual account with PnP Deprecated
    .
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  domain:
    description:
      - Domain path parameter. Smart Account Domain.
    type: str
  name:
    description:
      - Name path parameter. Virtual Account Name.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Device
      Onboarding (PnP) GetSyncResultForVirtualAccount
    description: Complete reference of the GetSyncResultForVirtualAccount
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-sync-result-for-virtual-account
notes:
  - SDK Method used are
    device_onboarding_pnp.DeviceOnboardingPnp.get_sync_result_for_virtual_account,
  - Paths used are
    get /dna/intent/api/v1/onboarding/pnp-device/sacct/{domain}/vacct/{name}/sync-result,
"""

EXAMPLES = r"""
---
- name: Get all Pnp Virtual Account Sync Result
  cisco.dnac.pnp_virtual_account_sync_result_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    domain: string
    name: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "virtualAccountId": "string",
      "autoSyncPeriod": 0,
      "syncResultStr": "string",
      "profile": {
        "proxy": true,
        "makeDefault": true,
        "port": 0,
        "profileId": "string",
        "name": "string",
        "addressIpV4": "string",
        "cert": "string",
        "addressFqdn": "string"
      },
      "ccoUser": "string",
      "syncResult": {
        "syncList": [
          {
            "syncType": "string",
            "deviceSnList": [
              "string"
            ]
          }
        ],
        "syncMsg": "string"
      },
      "token": "string",
      "syncStartTime": 0,
      "lastSync": 0,
      "tenantId": "string",
      "smartAccountId": "string",
      "expiry": 0,
      "syncStatus": "string"
    }
"""
