#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_layer2virtual_networks
short_description: Resource module for Sda Layer2virtual
  Networks
description:
  - Manage operations create, update and delete of the
    resource Sda Layer2virtual Networks.
  - Adds layer 2 virtual networks based on user input.
  - Deletes a layer 2 virtual network based on id.
  - Deletes layer 2 virtual networks based on user input.
  - Updates layer 2 virtual networks based on user input.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  associatedLayer3VirtualNetworkName:
    description: AssociatedLayer3VirtualNetworkName
      query parameter. Name of the associated layer
      3 virtual network.
    type: str
  fabricId:
    description: FabricId query parameter. ID of the
      fabric the layer 2 virtual network is assigned
      to.
    type: str
  id:
    description: Id path parameter. ID of the layer
      2 virtual network.
    type: str
  payload:
    description: Sda Layer2virtual Networks's payload.
    elements: dict
    suboptions:
      associatedLayer3VirtualNetworkName:
        description: Name of the layer 3 virtual network
          associated with the layer 2 virtual network.
          This field is provided to support requests
          related to virtual network anchoring. The
          layer 3 virtual network must have already
          been added to the fabric before association.
          This field must either be present in all payload
          elements or none.
        type: str
      fabricId:
        description: ID of the fabric this layer 2 virtual
          network is to be assigned to.
        type: str
      isFabricEnabledWireless:
        description: Set to true to enable wireless.
          Default is false.
        type: bool
      isMultipleIpToMacAddresses:
        description: Set to true to enable multiple
          IP-to-MAC addresses (Wireless Bridged-Network
          Virtual Machine). This field defaults to false
          when associated with a layer 3 virtual network
          and cannot be used when not associated with
          a layer 3 virtual network.
        type: bool
      isResourceGuardEnabled:
        description: Set to true to enable Resource
          Guard.
        type: bool
      isWirelessFloodingEnabled:
        description: Set to true to enable wireless
          flooding. If there is an associated layer
          3 virtual network, wireless flooding will
          default to false and can only be true when
          fabric-enabled wireless is also true. If there
          is no associated layer 3 virtual network,
          wireless flooding will match fabric-enabled
          wireless.
        type: bool
      layer2FloodingAddress:
        description: The flooding address to use for
          layer 2 flooding. The IP address must be in
          the 239.0.0.0/8 range. This property is applicable
          only when the flooding address source is set
          to "CUSTOM".
        type: str
      layer2FloodingAddressAssignment:
        description: The source of the flooding address
          for layer 2 flooding. "SHARED" means that
          the layer 2 virtual network will inherit the
          flooding address from the fabric. "CUSTOM"
          allows the layer 2 virtual network to use
          a different flooding address (defaults to
          "SHARED").
        type: str
      trafficType:
        description: The type of traffic that is served.
        type: str
      vlanId:
        description: ID of the VLAN of the layer 2 virtual
          network. Allowed VLAN range is 2-4093 except
          for reserved VLANs 1002-1005, and 2046. If
          deploying on a fabric zone, this vlanId must
          match the vlanId of the corresponding layer
          2 virtual network on the fabric site.
        type: int
      vlanName:
        description: Name of the VLAN of the layer 2
          virtual network. Must contain only alphanumeric
          characters, underscores, and hyphens.
        type: str
    type: list
  trafficType:
    description: TrafficType query parameter. The traffic
      type of the layer 2 virtual network.
    type: str
  vlanId:
    description: VlanId query parameter. The vlan ID
      of the layer 2 virtual network.
    type: float
  vlanName:
    description: VlanName query parameter. The vlan
      name of the layer 2 virtual network.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA AddLayer2VirtualNetworks
    description: Complete reference of the AddLayer2VirtualNetworks
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-layer-2-virtual-networks
  - name: Cisco DNA Center documentation for SDA DeleteLayer2VirtualNetworkById
    description: Complete reference of the DeleteLayer2VirtualNetworkById
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-layer-2-virtual-network-by-id
  - name: Cisco DNA Center documentation for SDA DeleteLayer2VirtualNetworks
    description: Complete reference of the DeleteLayer2VirtualNetworks
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-layer-2-virtual-networks
  - name: Cisco DNA Center documentation for SDA UpdateLayer2VirtualNetworks
    description: Complete reference of the UpdateLayer2VirtualNetworks
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-layer-2-virtual-networks
notes:
  - SDK Method used are
    sda.Sda.add_layer2_virtual_networks,
    sda.Sda.delete_layer2_virtual_network_by_id,
    sda.Sda.update_layer2_virtual_networks,
  - Paths used are
    post /dna/intent/api/v1/sda/layer2VirtualNetworks,
    delete /dna/intent/api/v1/sda/layer2VirtualNetworks,
    delete /dna/intent/api/v1/sda/layer2VirtualNetworks/{id},
    put /dna/intent/api/v1/sda/layer2VirtualNetworks,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.sda_layer2virtual_networks:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - associatedLayer3VirtualNetworkName: string
        fabricId: string
        isFabricEnabledWireless: true
        isMultipleIpToMacAddresses: true
        isResourceGuardEnabled: true
        isWirelessFloodingEnabled: true
        layer2FloodingAddress: string
        layer2FloodingAddressAssignment: string
        trafficType: string
        vlanId: 0
        vlanName: string
- name: Delete all
  cisco.dnac.sda_layer2virtual_networks:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    associatedLayer3VirtualNetworkName: string
    fabricId: string
    trafficType: string
    vlanId: 0
    vlanName: string
- name: Update all
  cisco.dnac.sda_layer2virtual_networks:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - associatedLayer3VirtualNetworkName: string
        fabricId: string
        id: string
        isFabricEnabledWireless: true
        isMultipleIpToMacAddresses: true
        isResourceGuardEnabled: true
        isWirelessFloodingEnabled: true
        layer2FloodingAddress: string
        layer2FloodingAddressAssignment: string
        trafficType: string
        vlanId: 0
        vlanName: string
- name: Delete by id
  cisco.dnac.sda_layer2virtual_networks:
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
