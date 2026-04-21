#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: feature_templates_wireless_flex_connect_configurations
short_description: Resource module for Feature Templates
  Wireless Flex Connect Configurations
description:
  - Manage operation create of the resource Feature
    Templates Wireless Flex Connect Configurations.
  - This API allows users to create a Flex Connect configuration
    feature template.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  designName:
    description: The feature template design name. `Note
      ` The following characters are not allowed % &
      < > ' /.
    type: str
  featureAttributes:
    description: Feature Templates Wireless Flex Connect
      Configurations's featureAttributes.
    suboptions:
      overlapIpEnable:
        description: IP Overlap.
        type: bool
    type: dict
  unlockedAttributes:
    description: Attributes unlocked in design can be
      changed at device provision time. `Note ` unlockedAttributes
      can only contain the attributes defined under
      featureAttributes.
    elements: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      CreateFlexConnectConfigurationFeatureTemplate
    description: Complete reference of the CreateFlexConnectConfigurationFeatureTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-flex-connect-configuration-feature-template
notes:
  - SDK Method used are
    wireless.Wireless.create_flex_connect_configuration_feature_template,
  - Paths used are
    post /dna/intent/api/v1/featureTemplates/wireless/flexConnectConfigurations,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.feature_templates_wireless_flex_connect_configurations:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    designName: string
    featureAttributes:
      overlapIpEnable: true
    unlockedAttributes:
      - string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""
