#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: feature_templates_wireless_advanced_ssidconfigurations
short_description: Resource module for Feature Templates
  Wireless Advanced Ssidconfigurations
description:
  - Manage operation create of the resource Feature
    Templates Wireless Advanced Ssidconfigurations.
  - This API allows users to create a Advanced SSID
    configuration feature template.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  designName:
    description: Design Name.
    type: str
  featureAttributes:
    description: Feature Templates Wireless Advanced
      Ssidconfigurations's featureAttributes.
    suboptions:
      advertisePCAnalyticsSupport:
        description: Advertise PC Analytics Support.
        type: bool
      advertiseSupport:
        description: Advertise Support.
        type: bool
      aironetIESupport:
        description: Aironet IE Enable.
        type: bool
      callSnooping:
        description: Call Snooping.
        type: bool
      deferPriority0:
        description: Defer Priority0.
        type: bool
      deferPriority1:
        description: Defer Priority1.
        type: bool
      deferPriority2:
        description: Defer Priority2.
        type: bool
      deferPriority3:
        description: Defer Priority3.
        type: bool
      deferPriority4:
        description: Defer Priority4.
        type: bool
      deferPriority5:
        description: Defer Priority5.
        type: bool
      deferPriority6:
        description: Defer Priority6.
        type: bool
      deferPriority7:
        description: Defer Priority7.
        type: bool
      dhcpOpt82RemoteIDSubOption:
        description: DHCP Option82 Remote ID suboption.
        type: bool
      dhcpRequired:
        description: Dynamic Host Configuration Protocol
          (DHCP) Required.
        type: bool
      dhcpServer:
        description: Dynamic Host Configuration Protocol
          (DHCP) Server.
        type: str
      dot11ax:
        description: 802.11ax Status.
        type: bool
      dot11vBSSMaxIdleProtected:
        description: Dot11v Basic Service Set (Bss)
          Max Idle Protected.
        type: bool
      downlinkMuMimo:
        description: Downlink multi-user, multiple input,
          multiple output (MU-MIMO).
        type: bool
      downlinkOfdma:
        description: Downlink orthogonal frequency-division
          multiple access (OFDMA).
        type: bool
      dtimPeriod24GHz:
        description: Delivery Traffic Indication Map
          (DTIM) Period 2.4GhZ Band (1-255).
        type: int
      dtimPeriod5GHz:
        description: Delivery Traffic Indication Map
          (DTIM) Period 5GhZ Band (1-255).
        type: int
      dualBandNeighborList:
        description: Neighbor List Dual Band.
        type: bool
      fastTransitionReassociationTimeout:
        description: Reassociation Timeout time.
        type: int
      fastlaneASR:
        description: Fastlane Advanced Scheduling Request
          (ASR).
        type: bool
      flexLocalAuth:
        description: FlexConnect Local Authentication.
        type: bool
      idleThreshold:
        description: Idle threshold.
        type: int
      ipMacBinding:
        description: IP Mac Binding.
        type: bool
      ipSourceGuard:
        description: IP Source Guard.
        type: bool
      loadBalancing:
        description: Load Balance Enable.
        type: bool
      mDNSMode:
        description: Multicast Domain Name Services
          (mDNS) Mode.
        type: str
      maxClients:
        description: For physical 9800 series controllers,
          valid ranges are - 0-5000 for 9800-L series
          - 0-32000 for 9800-40 series - 0-64000 for
          9800-80 series For 9800-CL series controllers,
          valid ranges are - 0-10000 for Small (S) VM
          - 0-32000 for Medium (M) VM - 0-64000 for
          Large (L) VM For Embedded Wireless Controller
          and Mobility Express, the valid range is 0-2000.
          For the 9300 platform, the valid range is
          0-4000. For the AireOS platform, valid ranges
          are - 0-3000 for 3500 series - 0-20000 for
          5500 series - 0-64000 for 8500 series.
        type: int
      maxClientsPerAp:
        description: Max client Per AP Per WLAN.
        type: int
      maxClientsPerRadio:
        description: Max client Per AP radio Per WLAN.
        type: int
      mediaStreamMulticastDirect:
        description: Media Stream Multicast Direct.
        type: bool
      muMimo11ac:
        description: Multi-user, multiple input, multiple
          output (Mu Mimo) 11ac.
        type: bool
      multicastBuffer:
        description: Multicast Buffer Enabled.
        type: bool
      multicastBufferValue:
        description: Multicast Buffer Value.
        type: int
      opportunisticKeyCaching:
        description: Opportunistic Key Caching.
        type: bool
      passiveClient:
        description: Passive Client.
        type: bool
      peer2peerblocking:
        description: Peer-to-Peer Blocking.
        type: str
      predictionOptimization:
        description: Assisted Roaming Prediction Optimization.
        type: bool
      radiusNacState:
        description: Network Admission Control(NAC-Radius).
        type: bool
      scanDeferTime:
        description: Scan Defer Time.
        type: int
      sendBeaconOnAssociation:
        description: Client Scan Report On Association.
        type: bool
      sendBeaconOnRoam:
        description: Client Scan Report On Roam.
        type: bool
      sendDisassociate:
        description: Send Disassociate.
        type: bool
      sent486Busy:
        description: Send 486 Busy.
        type: bool
      shareDataWithClient:
        description: Share Data with Client.
        type: bool
      targetWakeupTime:
        description: BSS Target Wake Up Time.
        type: bool
      universalAPAdmin:
        description: Universal Admin.
        type: bool
      uplinkMuMimo:
        description: Uplink multi-user, multiple input,
          multiple output (MU-MIMO).
        type: bool
      uplinkOfdma:
        description: Uplink orthogonal frequency-division
          multiple access (OFDMA).
        type: bool
      vlanCentralSwitching:
        description: VLAN Central Switching.
        type: bool
      wifiAllianceAgileMultiband:
        description: Wi-Fi Alliance Agile Multiband.
        type: bool
      wifiToCellularSteering:
        description: Wifi To Cellular Steering.
        type: bool
      wmmPolicy:
        description: Wi-Fi Multimedia (WMM) Policy.
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
      CreateAdvancedSSIDConfigurationFeatureTemplate
    description: Complete reference of the CreateAdvancedSSIDConfigurationFeatureTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-advanced-ssid-configuration-feature-template
notes:
  - SDK Method used are
    wireless.Wireless.create_advanced_ssid_configuration_feature_template,
  - Paths used are
    post /dna/intent/api/v1/featureTemplates/wireless/advancedSSIDConfigurations,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.feature_templates_wireless_advanced_ssidconfigurations:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    designName: string
    featureAttributes:
      advertisePCAnalyticsSupport: true
      advertiseSupport: true
      aironetIESupport: true
      callSnooping: true
      deferPriority0: true
      deferPriority1: true
      deferPriority2: true
      deferPriority3: true
      deferPriority4: true
      deferPriority5: true
      deferPriority6: true
      deferPriority7: true
      dhcpOpt82RemoteIDSubOption: true
      dhcpRequired: true
      dhcpServer: string
      dot11ax: true
      dot11vBSSMaxIdleProtected: true
      downlinkMuMimo: true
      downlinkOfdma: true
      dtimPeriod24GHz: 0
      dtimPeriod5GHz: 0
      dualBandNeighborList: true
      fastTransitionReassociationTimeout: 0
      fastlaneASR: true
      flexLocalAuth: true
      idleThreshold: 0
      ipMacBinding: true
      ipSourceGuard: true
      loadBalancing: true
      mDNSMode: string
      maxClients: 0
      maxClientsPerAp: 0
      maxClientsPerRadio: 0
      mediaStreamMulticastDirect: true
      muMimo11ac: true
      multicastBuffer: true
      multicastBufferValue: 0
      opportunisticKeyCaching: true
      passiveClient: true
      peer2peerblocking: string
      predictionOptimization: true
      radiusNacState: true
      scanDeferTime: 0
      sendBeaconOnAssociation: true
      sendBeaconOnRoam: true
      sendDisassociate: true
      sent486Busy: true
      shareDataWithClient: true
      targetWakeupTime: true
      universalAPAdmin: true
      uplinkMuMimo: true
      uplinkOfdma: true
      vlanCentralSwitching: true
      wifiAllianceAgileMultiband: true
      wifiToCellularSteering: true
      wmmPolicy: string
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
