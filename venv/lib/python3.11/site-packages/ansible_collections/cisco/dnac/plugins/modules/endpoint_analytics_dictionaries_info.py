#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: endpoint_analytics_dictionaries_info
short_description: Information module for Endpoint Analytics
  Dictionaries
description:
  - Get all Endpoint Analytics Dictionaries.
  - Fetches the list of attribute dictionaries.
version_added: '6.16.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  includeAttributes:
    description:
      - >
        IncludeAttributes query parameter. Flag to indicate
        whether attribute list for each dictionary should
        be included in response.
    type: bool
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for AI Endpoint
      Analytics GetAIEndpointAnalyticsAttributeDictionaries
    description: Complete reference of the GetAIEndpointAnalyticsAttributeDictionaries
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-ai-endpoint-analytics-attribute-dictionaries
notes:
  - SDK Method used are
    ai_endpoint_analytics.AiEndpointAnalytics.get_ai_endpoint_analytics_attribute_dictionaries,
  - Paths used are
    get /dna/intent/api/v1/endpoint-analytics/dictionaries,
"""

EXAMPLES = r"""
---
- name: Get all Endpoint Analytics Dictionaries
  cisco.dnac.endpoint_analytics_dictionaries_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    includeAttributes: true
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
        "name": "string",
        "description": "string",
        "attributes": [
          {
            "name": "string",
            "description": "string"
          }
        ]
      }
    ]
"""
