#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: feature_templates_wireless_flex_connect_configurations_id_info
short_description: Information module for Feature Templates
  Wireless Flex Connect Configurations Id
description:
  - Get Feature Templates Wireless Flex Connect Configurations
    Id by id.
  - This API allows users to retrieve a specific Flex
    Connect configuration feature template by ID.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. Flex Connect Configuration
        Feature Template Id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      GetFlexConnectConfigurationFeatureTemplate
    description: Complete reference of the GetFlexConnectConfigurationFeatureTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-flex-connect-configuration-feature-template
notes:
  - SDK Method used are
    wireless.Wireless.get_flex_connect_configuration_feature_template,
  - Paths used are
    get /dna/intent/api/v1/featureTemplates/wireless/flexConnectConfigurations/{id},
"""

EXAMPLES = r"""
---
- name: Get Feature Templates Wireless Flex Connect
    Configurations Id by id
  cisco.dnac.feature_templates_wireless_flex_connect_configurations_id_info:
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
        "designName": "string",
        "id": "string",
        "featureAttributes": {
          "overlapIpEnable": true
        },
        "unlockedAttributes": [
          "string"
        ]
      },
      "version": "string"
    }
"""
