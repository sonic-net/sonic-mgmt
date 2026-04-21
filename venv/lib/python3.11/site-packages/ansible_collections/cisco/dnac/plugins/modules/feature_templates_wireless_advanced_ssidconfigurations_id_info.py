#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: feature_templates_wireless_advanced_ssidconfigurations_id_info
short_description: Information module for Feature Templates
  Wireless Advanced Ssidconfigurations Id
description:
  - Get Feature Templates Wireless Advanced Ssidconfigurations
    Id by id.
  - This API allows users to retrieve a specific Advanced
    SSID configuration feature template by ID.
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
      - Id path parameter. Advanced SSID Configuration
        Feature Template Id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      GetAdvancedSSIDConfigurationFeatureTemplate
    description: Complete reference of the GetAdvancedSSIDConfigurationFeatureTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-advanced-ssid-configuration-feature-template
notes:
  - SDK Method used are
    wireless.Wireless.get_advanced_ssid_configuration_feature_template,
  - Paths used are
    get /dna/intent/api/v1/featureTemplates/wireless/advancedSSIDConfigurations/{id},
"""

EXAMPLES = r"""
---
- name: Get Feature Templates Wireless Advanced Ssidconfigurations
    Id by id
  cisco.dnac.feature_templates_wireless_advanced_ssidconfigurations_id_info:
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
        "featureAttributes": {
          "peer2peerblocking": "string",
          "passiveClient": true,
          "predictionOptimization": true,
          "dualBandNeighborList": true,
          "radiusNacState": true,
          "dhcpRequired": true,
          "dhcpServer": "string",
          "flexLocalAuth": true,
          "targetWakeupTime": true,
          "downlinkOfdma": true,
          "uplinkOfdma": true,
          "downlinkMuMimo": true,
          "uplinkMuMimo": true,
          "dot11ax": true,
          "aironetIESupport": true,
          "loadBalancing": true,
          "dtimPeriod5GHz": 0,
          "dtimPeriod24GHz": 0,
          "scanDeferTime": 0,
          "maxClients": 0,
          "maxClientsPerRadio": 0,
          "maxClientsPerAp": 0,
          "wmmPolicy": "string",
          "multicastBuffer": true,
          "multicastBufferValue": 0,
          "mediaStreamMulticastDirect": true,
          "muMimo11ac": true,
          "wifiToCellularSteering": true,
          "wifiAllianceAgileMultiband": true,
          "fastlaneASR": true,
          "dot11vBSSMaxIdleProtected": true,
          "universalAPAdmin": true,
          "opportunisticKeyCaching": true,
          "ipSourceGuard": true,
          "dhcpOpt82RemoteIDSubOption": true,
          "vlanCentralSwitching": true,
          "callSnooping": true,
          "sendDisassociate": true,
          "sent486Busy": true,
          "ipMacBinding": true,
          "idleThreshold": 0,
          "deferPriority0": true,
          "deferPriority1": true,
          "deferPriority2": true,
          "deferPriority3": true,
          "deferPriority4": true,
          "deferPriority5": true,
          "deferPriority6": true,
          "deferPriority7": true,
          "shareDataWithClient": true,
          "advertiseSupport": true,
          "advertisePCAnalyticsSupport": true,
          "sendBeaconOnAssociation": true,
          "sendBeaconOnRoam": true,
          "fastTransitionReassociationTimeout": 0,
          "mDNSMode": "string"
        },
        "unlockedAttributes": [
          "string"
        ]
      },
      "version": "string"
    }
"""
