#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: feature_templates_wireless_event_driven_r_r_m_configurations_id_info
short_description: Information module for Featuretemplates
  Wireless Eventdrivenrrmconfigurations Id
description:
  - Get Featuretemplates Wireless Eventdrivenrrmconfigurations
    Id by id.
  - This API allows users to retrieve a specific Event
    Driven RRM configuration feature template by ID.
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
      - Id path parameter. Event Driven RRM Configuration
        Feature Template Id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      GetEventDrivenRRMConfigurationFeatureTemplate
    description: Complete reference of the GetEventDrivenRRMConfigurationFeatureTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-event-driven-rrm-configuration-feature-template
notes:
  - SDK Method used are
    wireless.Wireless.get_event_driven_r_r_m_configuration_feature_template,
  - Paths used are
    get /dna/intent/api/v1/featureTemplates/wireless/eventDrivenRRMConfigurations/{id},
"""

EXAMPLES = r"""
---
- name: Get Featuretemplates Wireless Eventdrivenrrmconfigurations
    Id by id
  cisco.dnac.featureTemplates_wireless_eventDrivenRRMConfigurations_id_info:
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
          "radioBand": "string",
          "eventDrivenRrmEnable": true,
          "eventDrivenRrmThresholdLevel": "string",
          "eventDrivenRrmCustomThresholdVal": 0
        },
        "unlockedAttributes": [
          "string"
        ]
      },
      "version": "string"
    }
"""
