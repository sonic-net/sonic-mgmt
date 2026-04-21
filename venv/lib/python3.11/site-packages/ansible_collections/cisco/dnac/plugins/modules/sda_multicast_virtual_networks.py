#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_multicast_virtual_networks
short_description: Resource module for Sda Multicast
  Virtual Networks
description:
  - Manage operations create, update and delete of the
    resource Sda Multicast Virtual Networks.
  - Adds multicast for virtual networks based on user
    input.
  - Deletes a multicast configuration for a virtual
    network based on id.
  - Updates multicast configurations for virtual networks
    based on user input.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. ID of the multicast
      configuration.
    type: str
  payload:
    description: Sda Multicast Virtual Networks's payload.
    elements: dict
    suboptions:
      fabricId:
        description: ID of the fabric site this multicast
          configuration is associated with.
        type: str
      ipPoolName:
        description: Name of the IP Pool associated
          with the fabric site.
        type: str
      ipv4SsmRanges:
        description: IPv4 Source Specific Multicast
          (SSM) ranges. Allowed ranges are from 225.0.0.0/8
          to 239.0.0.0/8. SSM ranges should not conflict
          with ranges provided for ASM multicast.
        elements: str
        type: list
      multicastRPs:
        description: Sda Multicast Virtual Networks's
          multicastRPs.
        elements: dict
        suboptions:
          ipv4Address:
            description: IPv4 address of the RP. For
              external RP configuration, exactly one
              of ipv4Address or ipv6Address must be
              provided. For fabric RP, this address
              is allocated by SDA and should not be
              provided during RP creation request and
              SDA allocated address should be retained
              in subsequent requests.
            type: str
          ipv4AsmRanges:
            description: IPv4 Any Source Multicast ranges.
              Comma seperated list of IPv4 multicast
              group ranges that will be served by a
              given Multicast RP. Only IPv4 ranges can
              be provided. For fabric RP, both IPv4
              and IPv6 ranges can be provided together.
              For external RP, IPv4 ranges should be
              provided for IPv4 external RP and IPv6
              ranges should be provided for IPv6 external
              RP.
            elements: str
            type: list
          ipv6Address:
            description: IPv6 address of the RP. For
              external RP configuration, exactly one
              of ipv4Address or ipv6Address must be
              provided. For fabric RP, this address
              is allocated by SDA and should not be
              provided during RP creation request and
              SDA allocated address should be retained
              in subsequent requests. Ipv6Address can
              only be provided for virtual networks
              with dual stack (IPv4 + IPv6) multicast
              pool.
            type: str
          ipv6AsmRanges:
            description: IPv6 Any Source Multicast ranges.
              Comma seperated list of IPv6 multicast
              group ranges that will be served by a
              given Multicast RP. Only IPv6 ranges can
              be provided. IPv6 ranges can only be provided
              for dual stack multicast pool. For fabric
              RP, both IPv4 and IPv6 ranges can be provided
              together. For external RP, IPv4 ranges
              should be provided for IPv4 external RP
              and IPv6 ranges should be provided for
              IPv6 external RP.
            elements: str
            type: list
          isDefaultV4RP:
            description: Specifies whether it is a default
              IPv4 RP.
            type: bool
          isDefaultV6RP:
            description: Specifies whether it is a default
              IPv6 RP.
            type: bool
          networkDeviceIds:
            description: IDs of the network devices.
              This is a required field for fabric RPs.
              There can be maximum of two fabric RPs
              for a fabric site and these are shared
              across all multicast virtual networks.
              For configuring two fabric RPs in a fabric
              site both devices must have border roles.
              Only one RP can be configured in scenarios
              where a fabric edge device is used as
              RP or a dual stack multicast pool is used.
            elements: str
            type: list
          rpDeviceLocation:
            description: Device location of the RP.
            type: str
        type: list
      virtualNetworkName:
        description: Name of the virtual network associated
          with the fabric site.
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA AddMulticastVirtualNetworks
    description: Complete reference of the AddMulticastVirtualNetworks
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-multicast-virtual-networks
  - name: Cisco DNA Center documentation for SDA DeleteMulticastVirtualNetworkById
    description: Complete reference of the DeleteMulticastVirtualNetworkById
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-multicast-virtual-network-by-id
  - name: Cisco DNA Center documentation for SDA UpdateMulticastVirtualNetworks
    description: Complete reference of the UpdateMulticastVirtualNetworks
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-multicast-virtual-networks
notes:
  - SDK Method used are
    sda.Sda.add_multicast_virtual_networks,
    sda.Sda.delete_multicast_virtual_network_by_id,
    sda.Sda.update_multicast_virtual_networks,
  - Paths used are
    post /dna/intent/api/v1/sda/multicast/virtualNetworks,
    delete /dna/intent/api/v1/sda/multicast/virtualNetworks/{id},
    put /dna/intent/api/v1/sda/multicast/virtualNetworks,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.sda_multicast_virtual_networks:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - fabricId: string
        ipPoolName: string
        ipv4SsmRanges:
          - string
        multicastRPs:
          - ipv4Address: string
            ipv4AsmRanges:
              - string
            ipv6Address: string
            ipv6AsmRanges:
              - string
            isDefaultV4RP: true
            isDefaultV6RP: true
            networkDeviceIds:
              - string
            rpDeviceLocation: string
        virtualNetworkName: string
- name: Update all
  cisco.dnac.sda_multicast_virtual_networks:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - fabricId: string
        id: string
        ipPoolName: string
        ipv4SsmRanges:
          - string
        multicastRPs:
          - ipv4Address: string
            ipv4AsmRanges:
              - string
            ipv6Address: string
            ipv6AsmRanges:
              - string
            isDefaultV4RP: true
            isDefaultV6RP: true
            networkDeviceIds:
              - string
            rpDeviceLocation: string
        virtualNetworkName: string
- name: Delete by id
  cisco.dnac.sda_multicast_virtual_networks:
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
