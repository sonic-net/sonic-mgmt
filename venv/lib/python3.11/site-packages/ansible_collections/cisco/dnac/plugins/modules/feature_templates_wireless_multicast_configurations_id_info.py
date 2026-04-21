#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: feature_templates_wireless_multicast_configurations_id_info
short_description: Information module for Feature Templates
  Wireless Multicast Configurations Id
description:
  - Get Feature Templates Wireless Multicast Configurations
    Id by id.
  - This API allows users to retrieve a specific Multicast
    configuration feature template by ID.
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
      - Id path parameter. Multicast Configuration Feature
        Template Id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      GetMulticastConfigurationFeatureTemplate
    description: Complete reference of the GetMulticastConfigurationFeatureTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-multicast-configuration-feature-template
notes:
  - SDK Method used are
    wireless.Wireless.get_multicast_configuration_feature_template,
  - Paths used are
    get /dna/intent/api/v1/featureTemplates/wireless/multicastConfigurations/{id},
"""

EXAMPLES = r"""
---
- name: Get Feature Templates Wireless Multicast Configurations
    Id by id
  cisco.dnac.feature_templates_wireless_multicast_configurations_id_info:
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
          "globalMulticastEnabled": true,
          "multicastIpv4Mode": "string",
          "multicastIpv4Address": "string",
          "multicastIpv6Mode": "string",
          "multicastIpv6Address": "string"
        },
        "unlockedAttributes": [
          "string"
        ]
      },
      "version": "string"
    }
"""
