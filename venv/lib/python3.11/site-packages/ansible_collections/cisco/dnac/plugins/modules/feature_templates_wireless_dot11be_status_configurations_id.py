#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: feature_templates_wireless_dot11be_status_configurations_id
short_description: Resource module for Feature Templates
  Wireless Dot11be Status Configurations Id
description:
  - Manage operations update and delete of the resource
    Feature Templates Wireless Dot11be Status Configurations
    Id.
  - This API allows users to delete a specific Dot11be
    status configuration feature template by ID.
  - This API allows users to update the details of a
    specific Dot11be status configuration feature template
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
    description: Feature Templates Wireless Dot11be
      Status Configurations Id's featureAttributes.
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
  id:
    description: Id path parameter. Dot11be Status Configuration
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
      DeleteDot11beStatusConfigurationFeatureTemplate
    description: Complete reference of the DeleteDot11beStatusConfigurationFeatureTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-dot-11be-status-configuration-feature-template
  - name: Cisco DNA Center documentation for Wireless
      UpdateDot11beStatusConfigurationFeatureTemplate
    description: Complete reference of the UpdateDot11beStatusConfigurationFeatureTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-dot-11be-status-configuration-feature-template
notes:
  - SDK Method used are
    wireless.Wireless.delete_dot11be_status_configuration_feature_template,
    wireless.Wireless.update_dot11be_status_configuration_feature_template,
  - Paths used are
    delete /dna/intent/api/v1/featureTemplates/wireless/dot11beStatusConfigurations/{id},
    put /dna/intent/api/v1/featureTemplates/wireless/dot11beStatusConfigurations/{id},
"""

EXAMPLES = r"""
---
- name: Delete by id
  cisco.dnac.feature_templates_wireless_dot11be_status_configurations_id:
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
  cisco.dnac.feature_templates_wireless_dot11be_status_configurations_id:
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
      dot11beStatus: true
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
