#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: feature_templates_wireless_dot11be_status_configurations
short_description: Resource module for Feature Templates
  Wireless Dot11be Status Configurations
description:
  - Manage operation create of the resource Feature
    Templates Wireless Dot11be Status Configurations.
  - This API allows users to create a Dot11be status
    configuration feature template.
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
    description: Feature Templates Wireless Dot11be
      Status Configurations's featureAttributes.
    suboptions:
      dot11beStatus:
        description: Dot11be Status is supported only
          on Cisco IOS-XE based Wireless Controllers
          running 17.15.1 and above.
        type: bool
      radioBand:
        description: Configuring 802.11be Status will
          result in loss of connectivity of clients.
        type: str
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
      CreateDot11beStatusConfigurationFeatureTemplate
    description: Complete reference of the CreateDot11beStatusConfigurationFeatureTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-dot-11be-status-configuration-feature-template
notes:
  - SDK Method used are
    wireless.Wireless.create_dot11be_status_configuration_feature_template,
  - Paths used are
    post /dna/intent/api/v1/featureTemplates/wireless/dot11beStatusConfigurations,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.feature_templates_wireless_dot11be_status_configurations:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    designName: string
    featureAttributes:
      dot11beStatus: true
      radioBand: string
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
