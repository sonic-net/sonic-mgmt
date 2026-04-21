#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_fabric_devices_layer2handoffs_sda_transits
short_description: Resource module for Sda Fabric Devices
  Layer2handoffs Sda Transits
description:
  - Manage operations create, update and delete of the
    resource Sda Fabric Devices Layer2handoffs Sda Transits.
  - Adds layer 3 handoffs with sda transit in fabric
    devices based on user input.
  - Deletes layer 3 handoffs with sda transit of a fabric
    device based on user input.
  - Updates layer 3 handoffs with sda transit of fabric
    devices based on user input.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  fabricId:
    description: FabricId query parameter. ID of the
      fabric this device belongs to.
    type: str
  networkDeviceId:
    description: NetworkDeviceId query parameter. Network
      device ID of the fabric device.
    type: str
  payload:
    description: Sda Fabric Devices Layer2handoffs Sda
      Transits's payload.
    elements: dict
    suboptions:
      affinityIdDecider:
        description: Affinity id decider value of the
          border node. When the affinity id prime value
          is the same on multiple devices, the affinity
          id decider value is used as a tiebreaker.
          Allowed range is 0-2147483647. The lower the
          relative value of affinity id decider, the
          higher the preference for a destination border
          node.
        type: int
      affinityIdPrime:
        description: Affinity id prime value of the
          border node. It supersedes the border priority
          to determine border node preference. Allowed
          range is 0-2147483647. The lower the relative
          value of affinity id prime, the higher the
          preference for a destination border node.
        type: int
      connectedToInternet:
        description: Set this true to allow associated
          site to provide internet access to other sites
          through sd-access.
        type: bool
      fabricId:
        description: ID of the fabric this device is
          assigned to. (updating this field is not allowed).
        type: str
      isMulticastOverTransitEnabled:
        description: Set this true to configure native
          multicast over multiple sites that are connected
          to an sd-access transit.
        type: bool
      networkDeviceId:
        description: Network device ID of the fabric
          device. (updating this field is not allowed).
        type: str
      transitNetworkId:
        description: ID of the transit network of the
          layer 3 handoff sda transit. (updating this
          field is not allowed).
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA AddFabricDevicesLayer3HandoffsWithSdaTransit
    description: Complete reference of the AddFabricDevicesLayer3HandoffsWithSdaTransit
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-fabric-devices-layer-3-handoffs-with-sda-transit
  - name: Cisco DNA Center documentation for SDA DeleteFabricDeviceLayer3HandoffsWithSdaTransit
    description: Complete reference of the DeleteFabricDeviceLayer3HandoffsWithSdaTransit
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-fabric-device-layer-3-handoffs-with-sda-transit
  - name: Cisco DNA Center documentation for SDA UpdateFabricDevicesLayer3HandoffsWithSdaTransit
    description: Complete reference of the UpdateFabricDevicesLayer3HandoffsWithSdaTransit
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-fabric-devices-layer-3-handoffs-with-sda-transit
notes:
  - SDK Method used are
    sda.Sda.add_fabric_devices_layer3_handoffs_with_sda_transit,
    sda.Sda.delete_fabric_device_layer3_handoffs_with_sda_transit,
    sda.Sda.update_fabric_devices_layer3_handoffs_with_sda_transit,
  - Paths used are
    post /dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/sdaTransits,
    delete /dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/sdaTransits,
    put /dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/sdaTransits,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.sda_fabric_devices_layer2handoffs_sda_transits:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - affinityIdDecider: 0
        affinityIdPrime: 0
        connectedToInternet: true
        fabricId: string
        isMulticastOverTransitEnabled: true
        networkDeviceId: string
        transitNetworkId: string
- name: Delete all
  cisco.dnac.sda_fabric_devices_layer2handoffs_sda_transits:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    fabricId: string
    networkDeviceId: string
- name: Create
  cisco.dnac.sda_fabric_devices_layer2handoffs_sda_transits:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - affinityIdDecider: 0
        affinityIdPrime: 0
        connectedToInternet: true
        fabricId: string
        isMulticastOverTransitEnabled: true
        networkDeviceId: string
        transitNetworkId: string
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
