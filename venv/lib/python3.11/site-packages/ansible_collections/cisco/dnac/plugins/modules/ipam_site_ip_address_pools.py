#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: ipam_site_ip_address_pools
short_description: Resource module for Ipam Site Ip
  Address Pools
description:
  - Manage operation create of the resource Ipam Site
    Ip Address Pools. - > Reserves creates an IP address
    subpool, which reserves address space from a global
    pool or global pools for a particular site and it's
    child sites. A subpool must be either an IPv4 or
    dual-stack pool, with `ipV4AddressSpace` and optionally
    `ipV6AddressSpace` properties specified.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  ipV4AddressSpace:
    description: Ipam Site Ip Address Pools's ipV4AddressSpace.
    suboptions:
      assignedAddresses:
        description: The number of addresses assigned
          from the pool. This is a numeric string; since
          IPv6 address spaces are 128 bits in size,
          presume this string has a value up to 128
          bits for IPv6 address spaces and 32 bits for
          IPv4 address spaces.
        type: str
      defaultAssignedAddresses:
        description: The number of addresses that are
          assigned from the pool by default. This is
          a numeric string; since IPv6 address spaces
          are 128 bits in size, presume this string
          has a value up to 128 bits for IPv6 address
          spaces and 32 bits for IPv4 address spaces.
        type: str
      dhcpServers:
        description: The DHCP server(s) for this subnet.
        elements: str
        type: list
      dnsServers:
        description: The DNS server(s) for this subnet.
        elements: str
        type: list
      gatewayIpAddress:
        description: The gateway IP address for this
          subnet.
        type: str
      globalPoolId:
        description: The non-tunnel global pool for
          this reserve pool (which matches this IP address
          type). Once added this value cannot be changed.
        type: str
      prefixLength:
        description: The network mask component, as
          a decimal, for the CIDR notation of this subnet.
        type: float
      slaacSupport:
        description: If the prefixLength is 64, this
          option may be enabled. Stateless Address Auto-configuration
          (SLAAC) allows network devices to select their
          IP address without the use of DHCP servers.
        type: bool
      subnet:
        description: The IP address component of the
          CIDR notation for this subnet.
        type: str
      totalAddresses:
        description: The total number of addresses in
          the pool. This is a numeric string; since
          IPv6 address spaces are 128 bits in size,
          presume this string has a value up to 128
          bits for IPv6 address spaces and 32 bits for
          IPv4 address spaces.
        type: str
      unassignableAddresses:
        description: The number of addresses in the
          pool that cannot be assigned. This is a numeric
          string; since IPv6 address spaces are 128
          bits in size, presume this string has a value
          up to 128 bits for IPv6 address spaces and
          32 bits for IPv4 address spaces.
        type: str
    type: dict
  ipV6AddressSpace:
    description: Ipam Site Ip Address Pools's ipV6AddressSpace.
    suboptions:
      assignedAddresses:
        description: The number of addresses assigned
          from the pool. This is a numeric string; since
          IPv6 address spaces are 128 bits in size,
          presume this string has a value up to 128
          bits for IPv6 address spaces and 32 bits for
          IPv4 address spaces.
        type: str
      defaultAssignedAddresses:
        description: The number of addresses that are
          assigned from the pool by default. This is
          a numeric string; since IPv6 address spaces
          are 128 bits in size, presume this string
          has a value up to 128 bits for IPv6 address
          spaces and 32 bits for IPv4 address spaces.
        type: str
      dhcpServers:
        description: The DHCP server(s) for this subnet.
        elements: str
        type: list
      dnsServers:
        description: The DNS server(s) for this subnet.
        elements: str
        type: list
      gatewayIpAddress:
        description: The gateway IP address for this
          subnet.
        type: str
      globalPoolId:
        description: The non-tunnel global pool for
          this reserve pool (which matches this IP address
          type). Once added this value cannot be changed.
        type: str
      prefixLength:
        description: The network mask component, as
          a decimal, for the CIDR notation of this subnet.
        type: float
      slaacSupport:
        description: If the prefixLength is 64, this
          option may be enabled. Stateless Address Auto-configuration
          (SLAAC) allows network devices to select their
          IP address without the use of DHCP servers.
        type: bool
      subnet:
        description: The IP address component of the
          CIDR notation for this subnet.
        type: str
      totalAddresses:
        description: The total number of addresses in
          the pool. This is a numeric string; since
          IPv6 address spaces are 128 bits in size,
          presume this string has a value up to 128
          bits for IPv6 address spaces and 32 bits for
          IPv4 address spaces.
        type: str
      unassignableAddresses:
        description: The number of addresses in the
          pool that cannot be assigned. This is a numeric
          string; since IPv6 address spaces are 128
          bits in size, presume this string has a value
          up to 128 bits for IPv6 address spaces and
          32 bits for IPv4 address spaces.
        type: str
    type: dict
  name:
    description: The name for this reserve IP pool.
      Only letters, numbers, '-' (hyphen), '_' (underscore),
      '.' (period), and '/' (forward slash) are allowed.
    type: str
  poolType:
    description: Once created, a subpool type cannot
      be changed. LAN Assigns IP addresses to LAN interfaces
      of applicable VNFs and underlay LAN automation.
      Management Assigns IP addresses to management
      interfaces. A management network is a dedicated
      network connected to VNFs for VNF management.
      Service Assigns IP addresses to service interfaces.
      Service networks are used for communication within
      VNFs. WAN Assigns IP addresses to NFVIS for UCS-E
      provisioning. Generic used for all other network
      types.
    type: str
  siteId:
    description: The `id` of the site that this subpool
      belongs to. This must be the `id` of a non-Global
      site.
    type: str
  siteName:
    description: The name of the site that this subpool
      belongs to.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings ReservecreateIPAddressSubpools
    description: Complete reference of the ReservecreateIPAddressSubpools
      API.
    link: https://developer.cisco.com/docs/dna-center/#!reservecreate-ip-address-subpools
notes:
  - SDK Method used are
    network_settings.NetworkSettings.reservecreate_ip_address_subpools,
  - Paths used are
    post /dna/intent/api/v1/ipam/siteIpAddressPools,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.ipam_site_ip_address_pools:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    ipV4AddressSpace:
      assignedAddresses: string
      defaultAssignedAddresses: string
      dhcpServers:
        - string
      dnsServers:
        - string
      gatewayIpAddress: string
      globalPoolId: string
      prefixLength: 0
      slaacSupport: true
      subnet: string
      totalAddresses: string
      unassignableAddresses: string
    ipV6AddressSpace:
      assignedAddresses: string
      defaultAssignedAddresses: string
      dhcpServers:
        - string
      dnsServers:
        - string
      gatewayIpAddress: string
      globalPoolId: string
      prefixLength: 0
      slaacSupport: true
      subnet: string
      totalAddresses: string
      unassignableAddresses: string
    name: string
    poolType: string
    siteId: string
    siteName: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "version": "string",
      "response": {
        "url": "string",
        "taskId": "string"
      }
    }
"""
