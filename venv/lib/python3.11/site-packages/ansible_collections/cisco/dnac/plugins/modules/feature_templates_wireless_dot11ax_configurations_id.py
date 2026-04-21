#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: feature_templates_wireless_dot11ax_configurations_id
short_description: Resource module for Feature Templates
  Wireless Dot11ax Configurations Id
description:
  - Manage operations update and delete of the resource
    Feature Templates Wireless Dot11ax Configurations
    Id.
  - This API allows users to delete a specific Dot11ax
    configuration feature template by ID.
  - This API allows users to update the details of a
    specific Dot11ax configuration feature template
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
    description: Feature Templates Wireless Dot11ax
      Configurations Id's featureAttributes.
    suboptions:
      bssColor:
        description: BSS (Basic Service Set) Color is
          supported on Cisco IOS-XE based Wireless Controllers
          running 17.1 and above.
        type: bool
      multipleBssid:
        description: Multiple Basic service set identifiers
          (BSSID) is supported only on Cisco IOS-XE
          based Wireless Controllers running 17.7.1
          and above. `Note ` Multiple Bssid is only
          supported for radioBand 6GHZ.
        type: bool
      nonSRGObssPdMaxThreshold:
        description: Non SRG Obss Pd Max Threshold is
          supported only on Cisco IOS-XE based Wireless
          Controllers running 17.4 and above. `Note
          ` Non SRG Obss Pd Max Threshold is only supported
          for radioBand 2_4GHZ and 5GHZ.
        type: int
      obssPd:
        description: Overlapping BSS Packet Detect (obssPd)
          is supported only on Cisco IOS-XE based Wireless
          Controllers running 17.4 and above. `Note
          ` Obss Pd is only supported for radioBand
          2_4GHZ and 5GHZ.
        type: bool
      radioBand:
        description: 6 GHz radioBand is supported only
          on Cisco IOS-XE based Wireless Controllers
          running 17.7.1 and above.
        type: str
      targetWakeUpTime11ax:
        description: Target Wake Up Time 11ax is supported
          on Cisco IOS-XE based Wireless Controllers
          running 17.1 and above.
        type: bool
      targetWaketimeBroadcast:
        description: Target Wake Time Broadcast is supported
          on Cisco IOS-XE based Wireless Controllers
          running 17.3.1 and above.
        type: bool
    type: dict
  id:
    description: Id path parameter. Dot11ax Configuration
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
      DeleteDot11axConfigurationFeatureTemplate
    description: Complete reference of the DeleteDot11axConfigurationFeatureTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-dot-11ax-configuration-feature-template
  - name: Cisco DNA Center documentation for Wireless
      UpdateDot11axConfigurationFeatureTemplate
    description: Complete reference of the UpdateDot11axConfigurationFeatureTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-dot-11ax-configuration-feature-template
notes:
  - SDK Method used are
    wireless.Wireless.delete_dot11ax_configuration_feature_template,
    wireless.Wireless.update_dot11ax_configuration_feature_template,
  - Paths used are
    delete /dna/intent/api/v1/featureTemplates/wireless/dot11axConfigurations/{id},
    put /dna/intent/api/v1/featureTemplates/wireless/dot11axConfigurations/{id},
"""

EXAMPLES = r"""
---
- name: Delete by id
  cisco.dnac.feature_templates_wireless_dot11ax_configurations_id:
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
  cisco.dnac.feature_templates_wireless_dot11ax_configurations_id:
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
      bssColor: true
      multipleBssid: true
      nonSRGObssPdMaxThreshold: 0
      obssPd: true
      radioBand: string
      targetWakeUpTime11ax: true
      targetWaketimeBroadcast: true
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
