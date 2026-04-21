#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: feature_templates_wireless_rrm_fra_configurations_id
short_description: Resource module for Feature Templates
  Wireless Rrm Fra Configurations Id
description:
  - Manage operations update and delete of the resource
    Feature Templates Wireless Rrm Fra Configurations
    Id.
  - This API allows users to delete a specific RRM FRA
    configuration feature template by Id.
  - This API allows users to update the details of a
    specific RRM FRA configuration feature template
    by ID.
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
    description: Feature Templates Wireless Rrm Fra
      Configurations Id's featureAttributes.
    suboptions:
      fraFreeze:
        description: Flexible Radio Assignment Freeze
          is supported only on Cisco IOS-XE based Wireless
          Controllers running version >= 17.6 for 2_4GHZ_5GHZ
          radioband and version >= 17.9 for 5GHZ_6GHZ
          radioband.
        type: bool
      fraInterval:
        description: Flexible Radio Assignment Interval.
        type: int
      fraSensitivity:
        description: Flexible Radio Assignment Sensitivity
          values HIGHER,EVEN_HIGHER and SUPER_HIGH are
          supported only on Cisco IOS-XE based Wireless
          Controllers running 17.5 and above and FRA
          Sensitivity is only supported for 2_4GHZ_5GHZ
          radio band.
        type: str
      fraStatus:
        description: Flexible Radio Assignment Status.
        type: bool
      radioBand:
        description: Radio Band 5GHZ_6GHZ is supported
          only on Cisco IOS-XE based Wireless Controllers
          running 17.9.1 and above.
        type: str
    type: dict
  id:
    description: Id path parameter. RRM FRA Configuration
      Feature Template Id.
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
      DeleteRRMFRAConfigurationFeatureTemplate
    description: Complete reference of the DeleteRRMFRAConfigurationFeatureTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-rrmfra-configuration-feature-template
  - name: Cisco DNA Center documentation for Wireless
      UpdateRRMFRAConfigurationFeatureTemplate
    description: Complete reference of the UpdateRRMFRAConfigurationFeatureTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-rrmfra-configuration-feature-template
notes:
  - SDK Method used are
    wireless.Wireless.delete_r_r_m_f_r_a_configuration_feature_template,
    wireless.Wireless.update_r_r_m_f_r_a_configuration_feature_template,
  - Paths used are
    delete /dna/intent/api/v1/featureTemplates/wireless/rrmFraConfigurations/{id},
    put /dna/intent/api/v1/featureTemplates/wireless/rrmFraConfigurations/{id},
"""

EXAMPLES = r"""
---
- name: Update by id
  cisco.dnac.feature_templates_wireless_rrm_fra_configurations_id:
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
      fraFreeze: true
      fraInterval: 0
      fraSensitivity: string
      fraStatus: true
      radioBand: string
    id: string
    unlockedAttributes:
      - string
- name: Delete by id
  cisco.dnac.feature_templates_wireless_rrm_fra_configurations_id:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    id: string
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
