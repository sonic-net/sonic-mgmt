#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: feature_templates_wireless_clean_air_configurations
short_description: Resource module for Feature Templates
  Wireless Clean Air Configurations
description:
  - Manage operation create of the resource Feature
    Templates Wireless Clean Air Configurations.
  - This API allows users to create a CleanAir configuration
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
    description: Feature Templates Wireless Clean Air
      Configurations's featureAttributes.
    suboptions:
      cleanAir:
        description: Clean Air.
        type: bool
      cleanAirDeviceReporting:
        description: CleanAir Device Reporting.
        type: bool
      description:
        description: CleanAir Description.
        type: str
      interferersFeatures:
        description: Feature Templates Wireless Clean
          Air Configurations's interferersFeatures.
        suboptions:
          bleBeacon:
            description: BLE Beacon is only applicable
              for Radio Band 2_4GHZ.
            type: bool
          bluetoothPagingInquiry:
            description: Bluetooth Paging Inquiry is
              only applicable for Radio Band 2_4GHZ.
            type: bool
          bluetoothScoAcl:
            description: Bluetooth SCO ACL is only applicable
              for Radio Band 2_4GHZ.
            type: bool
          continuousTransmitter:
            description: Continuous Transmitter is applicable
              for Radio Bands 2_4GHZ, 5GHZ, 6GHZ.
            type: bool
          genericDect:
            description: Generic DECT is only applicable
              for Radio Bands 2_4GHZ, 5GHZ.
            type: bool
          genericTdd:
            description: Generic TDD is only applicable
              for Radio Band 2_4GHZ, 5GHZ.
            type: bool
          jammer:
            description: Jammer is only applicable for
              Radio Band 2_4GHZ, 5GHZ.
            type: bool
          microwaveOven:
            description: Microwave Oven is only applicable
              for Radio Band 2_4GHZ.
            type: bool
          motorolaCanopy:
            description: Motorola Canopy is only applicable
              for Radio Band 2_4GHZ, 5GHZ.
            type: bool
          siFhss:
            description: SI FHSS is only applicable
              for Radio Band 2_4GHZ, 5GHZ.
            type: bool
          spectrum80211Fh:
            description: Spectrum 802.11 FH is only
              applicable for Radio Band 2_4GHZ.
            type: bool
          spectrum80211NonStandardChannel:
            description: Spectrum 802.11 Non STD Channel
              is only applicable for Radio Band 2_4GHZ
              and 5GHZ.
            type: bool
          spectrum802154:
            description: Spectrum 802.15.4 is only applicable
              for Radio Band 2_4GHZ.
            type: bool
          spectrumInverted:
            description: Spectrum Inverted is only applicable
              for Radio Band 2_4GHZ and 5GHZ.
            type: bool
          superAg:
            description: Super AG is only applicable
              for Radio Band 2_4GHZ and 5GHZ.
            type: bool
          videoCamera:
            description: Video Camera is only applicable
              for Radio Band 2_4GHZ and 5GHZ.
            type: bool
          wimaxFixed:
            description: WiMAX Fixed is only applicable
              for Radio Band 2_4GHZ and 5GHZ.
            type: bool
          wimaxMobile:
            description: WiMAX Mobile is only applicable
              for Radio Band 2_4GHZ and 5GHZ.
            type: bool
          xbox:
            description: Xbox is only applicable for
              Radio Band 2_4GHZ.
            type: bool
        type: dict
      persistentDevicePropagation:
        description: Persistent Device Propagation.
        type: bool
      radioBand:
        description: Radio Band.
        type: str
    type: dict
  unlockedAttributes:
    description: Attributes unlocked in design can be
      changed at device provision time. `Note ` unlockedAttributes
      can only contain the first level attributes defined
      under featureAttributes.
    elements: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      CreateCleanAirConfigurationFeatureTemplate
    description: Complete reference of the CreateCleanAirConfigurationFeatureTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-clean-air-configuration-feature-template
notes:
  - SDK Method used are
    wireless.Wireless.create_clean_air_configuration_feature_template,
  - Paths used are
    post /dna/intent/api/v1/featureTemplates/wireless/cleanAirConfigurations,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.feature_templates_wireless_clean_air_configurations:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    designName: string
    featureAttributes:
      cleanAir: true
      cleanAirDeviceReporting: true
      description: string
      interferersFeatures:
        bleBeacon: true
        bluetoothPagingInquiry: true
        bluetoothScoAcl: true
        continuousTransmitter: true
        genericDect: true
        genericTdd: true
        jammer: true
        microwaveOven: true
        motorolaCanopy: true
        siFhss: true
        spectrum80211Fh: true
        spectrum80211NonStandardChannel: true
        spectrum802154: true
        spectrumInverted: true
        superAg: true
        videoCamera: true
        wimaxFixed: true
        wimaxMobile: true
        xbox: true
      persistentDevicePropagation: true
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
