#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: service_provider_v2_info
short_description: Information module for Service Provider
  V2
description:
  - Get all Service Provider V2.
  - API to get Service Provider details QoS .
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings GetServiceProviderDetailsV2
    description: Complete reference of the GetServiceProviderDetailsV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-service-provider-details-v-2
notes:
  - SDK Method used are
    network_settings.NetworkSettings.get_service_provider_details_v2,
  - Paths used are
    get /dna/intent/api/v2/service-provider,
"""

EXAMPLES = r"""
---
- name: Get all Service Provider V2
  cisco.dnac.service_provider_v2_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
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
          "instanceType": "string",
          "instanceUuid": "string",
          "namespace": "string",
          "type": "string",
          "key": "string",
          "version": 0,
          "value": [
            {
              "wanProvider": "string",
              "spProfileName": "string",
              "slaProfileName": "string"
            }
          ],
          "groupUuid": "string",
          "inheritedGroupUuid": "string",
          "inheritedGroupName": "string"
        }
      ],
      "version": "string"
    }
"""
