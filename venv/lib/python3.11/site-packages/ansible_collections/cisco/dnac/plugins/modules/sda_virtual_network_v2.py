#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_virtual_network_v2
short_description: Resource module for Sda Virtual Network
  V2
description:
  - Manage operations create, update and delete of the
    resource Sda Virtual Network V2.
  - Add virtual network with scalable groups at global
    level.
  - Delete virtual network with scalable groups.
  - Update virtual network with scalable groups.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  isGuestVirtualNetwork:
    description: Guest Virtual Network enablement flag,
      default value is False.
    type: bool
  scalableGroupNames:
    description: Scalable Group to be associated to
      virtual network.
    elements: str
    type: list
  vManageVpnId:
    description: VManage vpn id for SD-WAN.
    type: str
  virtualNetworkName:
    description: Virtual Network Name to be assigned
      at global level.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA AddVirtualNetworkWithScalableGroups
    description: Complete reference of the AddVirtualNetworkWithScalableGroups
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-virtual-network-with-scalable-groups
  - name: Cisco DNA Center documentation for SDA DeleteVirtualNetworkWithScalableGroups
    description: Complete reference of the DeleteVirtualNetworkWithScalableGroups
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-virtual-network-with-scalable-groups
  - name: Cisco DNA Center documentation for SDA UpdateVirtualNetworkWithScalableGroups
    description: Complete reference of the UpdateVirtualNetworkWithScalableGroups
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-virtual-network-with-scalable-groups
notes:
  - SDK Method used are
    sda.Sda.add_virtual_network_with_scalable_groups,
    sda.Sda.delete_virtual_network_with_scalable_groups,
    sda.Sda.update_virtual_network_with_scalable_groups,
  - Paths used are
    post /dna/intent/api/v1/virtual-network,
    delete /dna/intent/api/v1/virtual-network,
    put /dna/intent/api/v1/virtual-network,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.sda_virtual_network_v2:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    isGuestVirtualNetwork: true
    scalableGroupNames:
      - string
    vManageVpnId: string
    virtualNetworkName: string
- name: Delete all
  cisco.dnac.sda_virtual_network_v2:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    virtualNetworkName: string
- name: Update all
  cisco.dnac.sda_virtual_network_v2:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    isGuestVirtualNetwork: true
    scalableGroupNames:
      - string
    vManageVpnId: string
    virtualNetworkName: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "status": "string",
      "description": "string",
      "taskId": "string",
      "taskStatusUrl": "string",
      "executionStatusUrl": "string",
      "executionId": "string"
    }
"""
