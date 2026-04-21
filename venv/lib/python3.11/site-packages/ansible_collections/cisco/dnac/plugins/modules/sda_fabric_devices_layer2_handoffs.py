#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_fabric_devices_layer2_handoffs
short_description: Resource module for Sda Fabricdevices
  Layer2handoffs
description:
  - Manage operations create, update and delete of the
    resource Sda Fabricdevices Layer2handoffs.
  - Adds layer 2 handoffs in fabric devices based on
    user input.
  - Deletes a layer 2 handoff of a fabric device based
    on id.
  - Deletes layer 2 handoffs of a fabric device based
    on user input.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  fabricId:
    description: FabricId query parameter. ID of the
      fabric this device belongs to.
    type: str
  id:
    description: Id path parameter. ID of the layer
      2 handoff of a fabric device.
    type: str
  networkDeviceId:
    description: NetworkDeviceId query parameter. Network
      device ID of the fabric device.
    type: str
  payload:
    description: Sda Fabric Devices Layer2 Handoffs's
      payload.
    elements: dict
    suboptions:
      externalVlanId:
        description: External VLAN number into which
          the fabric must be extended. Allowed VLAN
          range is 2-4094 except for reserved vlans
          (1, 1002-1005, 2046, 4094).
        type: int
      fabricId:
        description: ID of the fabric this device is
          assigned to.
        type: str
      interfaceName:
        description: Interface name of the layer 2 handoff.
          E.g., GigabitEthernet1/0/4.
        type: str
      internalVlanId:
        description: VLAN number associated with this
          fabric. Allowed VLAN range is 2-4094 except
          for reserved vlans (1, 1002-1005, 2046, 4094).
        type: int
      networkDeviceId:
        description: Network device ID of the fabric
          device.
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA AddFabricDevicesLayer2Handoffs
    description: Complete reference of the AddFabricDevicesLayer2Handoffs
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-fabric-devices-layer-2-handoffs
  - name: Cisco DNA Center documentation for SDA DeleteFabricDeviceLayer2HandoffById
    description: Complete reference of the DeleteFabricDeviceLayer2HandoffById
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-fabric-device-layer-2-handoff-by-id
  - name: Cisco DNA Center documentation for SDA DeleteFabricDeviceLayer2Handoffs
    description: Complete reference of the DeleteFabricDeviceLayer2Handoffs
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-fabric-device-layer-2-handoffs
notes:
  - SDK Method used are
    sda.Sda.add_fabric_devices_layer2_handoffs,
    sda.Sda.delete_fabric_device_layer2_handoff_by_id,
  - Paths used are
    post /dna/intent/api/v1/sda/fabricDevices/layer2Handoffs,
    delete /dna/intent/api/v1/sda/fabricDevices/layer2Handoffs,
    delete /dna/intent/api/v1/sda/fabricDevices/layer2Handoffs/{id},
"""

EXAMPLES = r"""
---
- name: Delete all
  cisco.dnac.sda_fabricDevices_layer2Handoffs:
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
  cisco.dnac.sda_fabricDevices_layer2Handoffs:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - externalVlanId: 0
        fabricId: string
        interfaceName: string
        internalVlanId: 0
        networkDeviceId: string
- name: Delete by id
  cisco.dnac.sda_fabricDevices_layer2Handoffs:
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
