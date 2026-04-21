#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: feature_templates_wireless_summary_info
short_description: Information module for Feature Templates
  Wireless Summary
description:
  - Get all Feature Templates Wireless Summary.
  - This API allows users to retrieve the feature template
    summary.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  type:
    description:
      - >
        Type query parameter. Feature template name.
        Allowed values EVENT_DRIVEN_RRM_CONFIGURATION,
        DOT11AX_CONFIGURATION, AAA_RADIUS_ATTRIBUTES_CONFIGURATION,
        ADVANCED_SSID_CONFIGURATION, RRM_FRA_CONFIGURATION,
        CLEANAIR_CONFIGURATION, DOT11BE_STATUS_CONFIGURATION,
        FLEX_CONFIGURATION, MULTICAST_CONFIGURATION,
        RRM_GENERAL_CONFIGURATION.
    type: str
  designName:
    description:
      - DesignName query parameter. Feature template
        design name.
    type: str
  limit:
    description:
      - >
        Limit query parameter. The number of records
        to show for this page. Default is 25 if not
        specified. Maximum allowed limit is 25.
    type: int
  offset:
    description:
      - Offset query parameter. The first record to
        show for this page. The first record is numbered
        1.
    type: int
  systemTemplate:
    description:
      - >
        SystemTemplate query parameter. If 'True', it
        signifies a system-generated template; if 'False',
        it denotes a user-modifiable template.
    type: bool
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      GetFeatureTemplateSummary
    description: Complete reference of the GetFeatureTemplateSummary
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-feature-template-summary
notes:
  - SDK Method used are
    wireless.Wireless.get_feature_template_summary,
  - Paths used are
    get /dna/intent/api/v1/featureTemplates/wireless/summary,
"""

EXAMPLES = r"""
---
- name: Get all Feature Templates Wireless Summary
  cisco.dnac.feature_templates_wireless_summary_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    type: string
    designName: string
    limit: 0
    offset: 0
    systemTemplate: true
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
          "type": "string",
          "count": 0,
          "instances": [
            {
              "designName": "string",
              "id": "string",
              "systemTemplate": true
            }
          ]
        }
      ],
      "version": "string"
    }
"""
