#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: discovery_range_info
short_description: Information module for Discovery
  Range
description:
  - Get all Discovery Range.
  - Returns the discoveries by specified range.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  startIndex:
    description:
      - StartIndex path parameter. Starting index for
        the records.
    type: int
  recordsToReturn:
    description:
      - RecordsToReturn path parameter. Number of records
        to fetch from the starting index.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Discovery
      GetDiscoveriesByRange
    description: Complete reference of the GetDiscoveriesByRange
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-discoveries-by-range
notes:
  - SDK Method used are
    discovery.Discovery.get_discoveries_by_range,
  - Paths used are
    get /dna/intent/api/v1/discovery/{startIndex}/{recordsToReturn},
"""

EXAMPLES = r"""
---
- name: Get all Discovery Range
  cisco.dnac.discovery_range_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    startIndex: 0
    recordsToReturn: 0
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
          "attributeInfo": {},
          "cdpLevel": 0,
          "deviceIds": "string",
          "discoveryCondition": "string",
          "discoveryStatus": "string",
          "discoveryType": "string",
          "enablePasswordList": "string",
          "globalCredentialIdList": [
            "string"
          ],
          "httpReadCredential": {
            "comments": "string",
            "credentialType": "string",
            "description": "string",
            "id": "string",
            "instanceTenantId": "string",
            "instanceUuid": "string",
            "password": "string",
            "port": 0,
            "secure": true,
            "username": "string"
          },
          "httpWriteCredential": {
            "comments": "string",
            "credentialType": "string",
            "description": "string",
            "id": "string",
            "instanceTenantId": "string",
            "instanceUuid": "string",
            "password": "string",
            "port": 0,
            "secure": true,
            "username": "string"
          },
          "id": "string",
          "ipAddressList": "string",
          "ipFilterList": "string",
          "isAutoCdp": true,
          "lldpLevel": 0,
          "name": "string",
          "netconfPort": "string",
          "numDevices": 0,
          "parentDiscoveryId": "string",
          "passwordList": "string",
          "preferredMgmtIPMethod": "string",
          "protocolOrder": "string",
          "retryCount": 0,
          "snmpAuthPassphrase": "string",
          "snmpAuthProtocol": "string",
          "snmpMode": "string",
          "snmpPrivPassphrase": "string",
          "snmpPrivProtocol": "string",
          "snmpRoCommunity": "string",
          "snmpRoCommunityDesc": "string",
          "snmpRwCommunity": "string",
          "snmpRwCommunityDesc": "string",
          "snmpUserName": "string",
          "timeout": 0,
          "updateMgmtIp": true,
          "userNameList": "string"
        }
      ],
      "version": "string"
    }
"""
