#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: device_credential_info
short_description: Information module for Device Credential
description:
  - Get all Device Credential.
  - API to get device credential details.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  siteId:
    description:
      - SiteId query parameter. Site id to retrieve
        the credential details associated with the site.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings GetDeviceCredentialDetails
    description: Complete reference of the GetDeviceCredentialDetails
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-device-credential-details
notes:
  - SDK Method used are
    network_settings.NetworkSettings.get_device_credential_details,
  - Paths used are
    get /dna/intent/api/v1/device-credential,
"""

EXAMPLES = r"""
---
- name: Get all Device Credential
  cisco.dnac.device_credential_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    siteId: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "snmp_v3": [
        {
          "username": "string",
          "authPassword": "string",
          "authType": "string",
          "privacyPassword": "string",
          "privacyType": "string",
          "snmpMode": "string",
          "comments": "string",
          "description": "string",
          "credentialType": "string",
          "instanceUuid": "string",
          "instanceTenantId": "string",
          "id": "string"
        }
      ],
      "http_read": [
        {
          "secure": "string",
          "username": "string",
          "password": "string",
          "port": "string",
          "comments": "string",
          "description": "string",
          "credentialType": "string",
          "instanceUuid": "string",
          "instanceTenantId": "string",
          "id": "string"
        }
      ],
      "http_write": [
        {
          "secure": "string",
          "username": "string",
          "password": "string",
          "port": "string",
          "comments": "string",
          "description": "string",
          "credentialType": "string",
          "instanceUuid": "string",
          "instanceTenantId": "string",
          "id": "string"
        }
      ],
      "snmp_v2_write": [
        {
          "writeCommunity": "string",
          "comments": "string",
          "description": "string",
          "credentialType": "string",
          "instanceUuid": "string",
          "instanceTenantId": "string",
          "id": "string"
        }
      ],
      "snmp_v2_read": [
        {
          "readCommunity": "string",
          "comments": "string",
          "description": "string",
          "credentialType": "string",
          "instanceUuid": "string",
          "instanceTenantId": "string",
          "id": "string"
        }
      ],
      "cli": [
        {
          "username": "string",
          "enablePassword": "string",
          "password": "string",
          "comments": "string",
          "description": "string",
          "credentialType": "string",
          "instanceUuid": "string",
          "instanceTenantId": "string",
          "id": "string"
        }
      ]
    }
"""
