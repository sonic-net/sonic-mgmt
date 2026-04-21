#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_fabric_devices_layer2_handoffs_ip_transits
short_description: Resource module for Sda Fabricdevices
  Layer2handoffs Iptransits
description:
  - Manage operations create, update and delete of the
    resource Sda Fabricdevices Layer2handoffs Iptransits.
  - Adds layer 3 handoffs with ip transit in fabric
    devices based on user input.
  - Deletes a layer 3 handoff with ip transit of a fabric
    device by id.
  - Deletes layer 3 handoffs with ip transit of a fabric
    device based on user input.
  - Updates layer 3 handoffs with ip transit of fabric
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
  id:
    description: Id path parameter. ID of the layer
      3 handoff with ip transit of a fabric device.
    type: str
  networkDeviceId:
    description: NetworkDeviceId query parameter. Network
      device ID of the fabric device.
    type: str
  payload:
    description: Sda Fabric Devices Layer2 Handoffs
      Ip Transits's payload.
    elements: dict
    suboptions:
      externalConnectivityIpPoolName:
        description: External connectivity ip pool will
          be used by Catalyst Center to allocate IP
          address for the connection between the border
          node and peer.
        type: str
      fabricId:
        description: ID of the fabric this device is
          assigned to.
        type: str
      interfaceName:
        description: Interface name of the layer 3 handoff
          ip transit.
        type: str
      localIpAddress:
        description: Local ipv4 address for the selected
          virtual network. Enter the IP addresses and
          subnet mask in the CIDR notation (IP address/prefix-length).
          Not applicable if you have already provided
          an external connectivity ip pool name.
        type: str
      localIpv6Address:
        description: Local ipv6 address for the selected
          virtual network. Enter the IP addresses and
          subnet mask in the CIDR notation (IP address/prefix-length).
          Not applicable if you have already provided
          an external connectivity ip pool name.
        type: str
      networkDeviceId:
        description: Network device ID of the fabric
          device.
        type: str
      remoteIpAddress:
        description: Remote ipv4 address for the selected
          virtual network. Enter the IP addresses and
          subnet mask in the CIDR notation (IP address/prefix-length).
          Not applicable if you have already provided
          an external connectivity ip pool name.
        type: str
      remoteIpv6Address:
        description: Remote ipv6 address for the selected
          virtual network. Enter the IP addresses and
          subnet mask in the CIDR notation (IP address/prefix-length).
          Not applicable if you have already provided
          an external connectivity ip pool name.
        type: str
      tcpMssAdjustment:
        description: TCP maximum segment size (mss)
          value for the layer 3 handoff. Allowed range
          is 500-1440. TCP MSS Adjustment value is applicable
          for the TCP sessions over both IPv4 and IPv6.
        type: int
      transitNetworkId:
        description: ID of the transit network of the
          layer 3 handoff ip transit.
        type: str
      virtualNetworkName:
        description: Name of the virtual network associated
          with this fabric site.
        type: str
      vlanId:
        description: VLAN number for the Switch Virtual
          Interface (SVI) used to establish BGP peering
          with the external domain for the virtual network.
          Allowed VLAN range is 2-4094 except for reserved
          vlans (1, 1002-1005, 2046, 4094).
        type: int
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA AddFabricDevicesLayer3HandoffsWithIpTransit
    description: Complete reference of the AddFabricDevicesLayer3HandoffsWithIpTransit
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-fabric-devices-layer-3-handoffs-with-ip-transit
  - name: Cisco DNA Center documentation for SDA DeleteFabricDeviceLayer3HandoffWithIpTransitById
    description: Complete reference of the DeleteFabricDeviceLayer3HandoffWithIpTransitById
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-fabric-device-layer-3-handoff-with-ip-transit-by-id
  - name: Cisco DNA Center documentation for SDA DeleteFabricDeviceLayer3HandoffsWithIpTransit
    description: Complete reference of the DeleteFabricDeviceLayer3HandoffsWithIpTransit
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-fabric-device-layer-3-handoffs-with-ip-transit
  - name: Cisco DNA Center documentation for SDA UpdateFabricDevicesLayer3HandoffsWithIpTransit
    description: Complete reference of the UpdateFabricDevicesLayer3HandoffsWithIpTransit
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-fabric-devices-layer-3-handoffs-with-ip-transit
notes:
  - SDK Method used are
    sda.Sda.add_fabric_devices_layer3_handoffs_with_ip_transit,
    sda.Sda.delete_fabric_device_layer3_handoff_with_ip_transit_by_id,
    sda.Sda.update_fabric_devices_layer3_handoffs_with_ip_transit,
  - Paths used are
    post /dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/ipTransits,
    delete /dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/ipTransits,
    delete /dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/ipTransits/{id},
    put /dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/ipTransits,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.sda_fabricDevices_layer2Handoffs_ipTransits:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - externalConnectivityIpPoolName: string
        fabricId: string
        interfaceName: string
        localIpAddress: string
        localIpv6Address: string
        networkDeviceId: string
        remoteIpAddress: string
        remoteIpv6Address: string
        tcpMssAdjustment: 0
        transitNetworkId: string
        virtualNetworkName: string
        vlanId: 0
- name: Update all
  cisco.dnac.sda_fabricDevices_layer2Handoffs_ipTransits:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - externalConnectivityIpPoolName: string
        fabricId: string
        id: string
        interfaceName: string
        localIpAddress: string
        localIpv6Address: string
        networkDeviceId: string
        remoteIpAddress: string
        remoteIpv6Address: string
        tcpMssAdjustment: 0
        transitNetworkId: string
        virtualNetworkName: string
        vlanId: 0
- name: Delete all
  cisco.dnac.sda_fabricDevices_layer2Handoffs_ipTransits:
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
- name: Delete by id
  cisco.dnac.sda_fabricDevices_layer2Handoffs_ipTransits:
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
