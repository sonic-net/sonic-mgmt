#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: feature_templates_wireless_event_driven_rrmconfigurations_id
short_description: Resource module for Feature Templates
  Wireless Event Driven Rrmconfigurations Id
description:
  - Manage operations update and delete of the resource
    Feature Templates Wireless Event Driven Rrmconfigurations
    Id.
  - This API allows users to delete a specific Event
    Driven RRM configuration feature template by ID.
  - This API allows users to update the details of a
    specific Event Driven RRM configuration feature
    template by ID.
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
      Rrmconfigurations Id's featureAttributes.
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
  id:
    description: Id path parameter. Event Driven RRM
      Configuration Feature Template Id.
    type: str
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
      DeleteEventDrivenRRMConfigurationFeatureTemplate
    description: Complete reference of the DeleteEventDrivenRRMConfigurationFeatureTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-event-driven-rrm-configuration-feature-template
  - name: Cisco DNA Center documentation for Wireless
      UpdateEventDrivenRRMConfigurationFeatureTemplate
    description: Complete reference of the UpdateEventDrivenRRMConfigurationFeatureTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-event-driven-rrm-configuration-feature-template
notes:
  - SDK Method used are
    wireless.Wireless.delete_event_driven_r_r_m_configuration_feature_template,
    wireless.Wireless.update_event_driven_r_r_m_configuration_feature_template,
  - Paths used are
    delete /dna/intent/api/v1/featureTemplates/wireless/eventDrivenRRMConfigurations/{id},
    put /dna/intent/api/v1/featureTemplates/wireless/eventDrivenRRMConfigurations/{id},
"""

EXAMPLES = r"""
---
- name: Delete by id
  cisco.dnac.feature_templates_wireless_event_driven_rrmconfigurations_id:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    id: string
- name: Update by id
  cisco.dnac.feature_templates_wireless_event_driven_rrmconfigurations_id:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    designName: string
    featureAttributes:
      eventDrivenRrmCustomThresholdVal: 0
      eventDrivenRrmEnable: true
      eventDrivenRrmThresholdLevel: string
      radioBand: string
    id: string
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
