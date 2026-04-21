#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: feature_templates_wireless_event_driven_rrmconfigurations
short_description: Resource module for Feature Templates
  Wireless Event Driven Rrmconfigurations
description:
  - Manage operation create of the resource Feature
    Templates Wireless Event Driven Rrmconfigurations.
  - This API allows users to create a Event Driven RRM
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
    description: Feature Templates Wireless Event Driven
      Rrmconfigurations's featureAttributes.
    suboptions:
      eventDrivenRrmCustomThresholdVal:
        description: Event Driven Radio Resource Management
          (RRM) Custom Threshold Val is only supported
          for `CUSTOM` Event Driven RRM Threshold Level.
        type: int
      eventDrivenRrmEnable:
        description: Event Driven Radio Resource Management
          (RRM) Enable, when set `true` Event Driven
          RRM is Enabled.
        type: bool
      eventDrivenRrmThresholdLevel:
        description: Event Driven Radio Resource Management
          (RRM) Threshold Level is only supported when
          Event Driven RRM is `Enabled`.
        type: str
      radioBand:
        description: Radio Band.
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
      CreateEventDrivenRRMConfigurationFeatureTemplate
    description: Complete reference of the CreateEventDrivenRRMConfigurationFeatureTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-event-driven-rrm-configuration-feature-template
notes:
  - SDK Method used are
    wireless.Wireless.create_event_driven_r_r_m_configuration_feature_template,
  - Paths used are
    post /dna/intent/api/v1/featureTemplates/wireless/eventDrivenRRMConfigurations,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.feature_templates_wireless_event_driven_rrmconfigurations:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    designName: string
    featureAttributes:
      eventDrivenRrmCustomThresholdVal: 0
      eventDrivenRrmEnable: true
      eventDrivenRrmThresholdLevel: string
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
