#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: discovery_info
short_description: Information module for Discovery
description:
  - Get Discovery by id.
  - Returns discovery by Discovery ID. Discovery ID
    can be obtained using the "Get Discoveries by range"
    API.
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
      - Id path parameter. Discovery ID.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Discovery
      GetDiscoveryById
    description: Complete reference of the GetDiscoveryById
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-discovery-by-id
notes:
  - SDK Method used are
    discovery.Discovery.get_discovery_by_id,
  - Paths used are
    get /dna/intent/api/v1/discovery/{id},
"""

EXAMPLES = r"""
---
- name: Get Discovery by id
  cisco.dnac.discovery_info:
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
      },
      "version": "string"
    }
"""
