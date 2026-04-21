#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_v2_info
short_description: Information module for Network V2
description:
  - Get all Network V2.
  - API to get SNMP, NTP, Network AAA, Client and Endpoint
    AAA, and/or DNS center server settings.
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
      - SiteId query parameter. Site Id to get the network
        settings associated with the site.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings GetNetworkV2
    description: Complete reference of the GetNetworkV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-network-v-2
notes:
  - SDK Method used are
    network_settings.NetworkSettings.get_network_v2,
  - Paths used are
    get /dna/intent/api/v2/network,
"""

EXAMPLES = r"""
---
- name: Get all Network V2
  cisco.dnac.network_v2_info:
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
  type: list
  elements: dict
  sample: >
    [
      {
        "instanceType": "string",
        "instanceUuid": "string",
        "namespace": "string",
        "type": "string",
        "key": "string",
        "version": 0,
        "value": [
          "string"
        ],
        "groupUuid": "string",
        "inheritedGroupUuid": "string",
        "inheritedGroupName": "string"
      }
    ]
"""
