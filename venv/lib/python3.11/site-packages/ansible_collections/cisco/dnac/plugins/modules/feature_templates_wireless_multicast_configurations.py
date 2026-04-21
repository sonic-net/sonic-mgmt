#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: feature_templates_wireless_multicast_configurations
short_description: Resource module for Feature Templates
  Wireless Multicast Configurations
description:
  - Manage operation create of the resource Feature
    Templates Wireless Multicast Configurations.
  - This API allows users to create a Multicast configuration
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
    description: Feature Templates Wireless Multicast
      Configurations's featureAttributes.
    suboptions:
      globalMulticastEnabled:
        description: Global Multicast Enabled.
        type: bool
      multicastIpv4Address:
        description: Multicast Ipv4 address must be
          between 224.0.0.0 and 239.255.255.255. Note
          This is only supported when multicastIpv4Mode
          is set to MULTICAST.
        type: str
      multicastIpv4Mode:
        description: Multicast Ipv4 Mode.
        type: str
      multicastIpv6Address:
        description: Multicast Ipv6 Address must start
          with FF0 or 11,2,3,4,5,8, or E. Note This
          is only supported when multicastIpv6Mode is
          set to MULTICAST.
        type: str
      multicastIpv6Mode:
        description: Multicast Ipv6 Mode.
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
      CreateMulticastConfigurationFeatureTemplate
    description: Complete reference of the CreateMulticastConfigurationFeatureTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-multicast-configuration-feature-template
notes:
  - SDK Method used are
    wireless.Wireless.create_multicast_configuration_feature_template,
  - Paths used are
    post /dna/intent/api/v1/featureTemplates/wireless/multicastConfigurations,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.feature_templates_wireless_multicast_configurations:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    designName: string
    featureAttributes:
      globalMulticastEnabled: true
      multicastIpv4Address: string
      multicastIpv4Mode: string
      multicastIpv6Address: string
      multicastIpv6Mode: string
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
