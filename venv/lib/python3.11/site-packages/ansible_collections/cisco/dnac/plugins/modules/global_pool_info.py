#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: global_pool_info
short_description: Information module for Global Pool
description:
  - Get all Global Pool.
  - API to get the global pool.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  offset:
    description:
      - Offset query parameter. Offset/starting row.
        Indexed from 1. Default value of 1.
    type: float
  limit:
    description:
      - Limit query parameter. Number of Global Pools
        to be retrieved. Default is 25 if not specified.
    type: float
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings GetGlobalPool
    description: Complete reference of the GetGlobalPool
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-global-pool
notes:
  - SDK Method used are
    network_settings.NetworkSettings.get_global_pool,
  - Paths used are
    get /dna/intent/api/v1/global-pool,
"""

EXAMPLES = r"""
---
- name: Get all Global Pool
  cisco.dnac.global_pool_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    offset: 0
    limit: 0
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
          "ipPoolName": "string",
          "dhcpServerIps": [
            "string"
          ],
          "gateways": [
            "string"
          ],
          "createTime": 0,
          "lastUpdateTime": 0,
          "totalIpAddressCount": 0,
          "usedIpAddressCount": 0,
          "parentUuid": "string",
          "owner": "string",
          "shared": true,
          "overlapping": true,
          "configureExternalDhcp": true,
          "usedPercentage": "string",
          "clientOptions": {},
          "ipPoolType": "string",
          "unavailableIpAddressCount": 0,
          "availableIpAddressCount": 0,
          "totalAssignableIpAddressCount": 0,
          "dnsServerIps": [
            "string"
          ],
          "hasSubpools": true,
          "defaultAssignedIpAddressCount": 0,
          "context": [
            {
              "owner": "string",
              "contextKey": "string",
              "contextValue": "string"
            }
          ],
          "ipv6": true,
          "id": "string",
          "ipPoolCidr": "string"
        }
      ],
      "version": "string"
    }
"""
