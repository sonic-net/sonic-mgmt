#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: reserve_ip_subpool_create
short_description: Resource module for Reserve Ip Subpool
  Create
description:
  - Manage operation create of the resource Reserve
    Ip Subpool Create.
  - API to reserve an ip subpool from the global pool.
version_added: '4.0.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  ipv4DhcpServers:
    description: IPv4 input for dhcp server ip example
      "1.1.1.1".
    elements: str
    type: list
  ipv4DnsServers:
    description: IPv4 input for dns server ip example
      "4.4.4.4".
    elements: str
    type: list
  ipv4GateWay:
    description: Gateway ip address details, example
      175.175.0.1.
    type: str
  ipv4GlobalPool:
    description: IP v4 Global pool address with cidr,
      example 175.175.0.0/16.
    type: str
  ipv4Prefix:
    description: IPv4 prefix value is true, the ip4
      prefix length input field is enabled , if it is
      false ipv4 total Host input is enable.
    type: bool
  ipv4PrefixLength:
    description: The ipv4 prefix length is required
      when ipv4prefix value is true.
    type: int
  ipv4Subnet:
    description: IPv4 Subnet address, example 175.175.0.0.
      Either ipv4Subnet or ipv4TotalHost needs to be
      passed if creating IPv4 subpool.
    type: str
  ipv4TotalHost:
    description: IPv4 total host is required when ipv4prefix
      value is false.
    type: int
  ipv6AddressSpace:
    description: If the value is omitted or false only
      ipv4 input are required, otherwise both ipv6 and
      ipv4 are required.
    type: bool
  ipv6DhcpServers:
    description: IPv6 format dhcp server as input example
      "2001 db8 1234".
    elements: str
    type: list
  ipv6DnsServers:
    description: IPv6 format dns server input example
      "2001 db8 1234".
    elements: str
    type: list
  ipv6GateWay:
    description: Gateway ip address details, example
      2001 db8 85a3 0 100 1.
    type: str
  ipv6GlobalPool:
    description: IPv6 Global pool address with cidr
      this is required when Ipv6AddressSpace value is
      true, example 2001 db8 85a3 /64.
    type: str
  ipv6Prefix:
    description: Ipv6 prefix value is true, the ip6
      prefix length input field is enabled , if it is
      false ipv6 total Host input is enable.
    type: bool
  ipv6PrefixLength:
    description: IPv6 prefix length is required when
      the ipv6prefix value is true.
    type: int
  ipv6Subnet:
    description: IPv6 Subnet address, example 2001 db8
      85a3 0 100. Either ipv6Subnet or ipv6TotalHost
      needs to be passed if creating IPv6 subpool.
    type: str
  ipv6TotalHost:
    description: IPv6 total host is required when ipv6prefix
      value is false.
    type: int
  name:
    description: Name of the reserve ip sub pool.
    type: str
  siteId:
    description: SiteId path parameter. Site id to reserve
      the ip sub pool.
    type: str
  slaacSupport:
    description: Slaac Support.
    type: bool
  type:
    description: Type of the reserve ip sub pool.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings ReserveIPSubpool
    description: Complete reference of the ReserveIPSubpool
      API.
    link: https://developer.cisco.com/docs/dna-center/#!reserve-ip-subpool
notes:
  - SDK Method used are
    network_settings.NetworkSettings.reserve_ip_subpool,
  - Paths used are
    post /dna/intent/api/v1/reserve-ip-subpool/{siteId},
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.reserve_ip_subpool_create:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    ipv4DhcpServers:
      - string
    ipv4DnsServers:
      - string
    ipv4GateWay: string
    ipv4GlobalPool: string
    ipv4Prefix: true
    ipv4PrefixLength: 0
    ipv4Subnet: string
    ipv4TotalHost: 0
    ipv6AddressSpace: true
    ipv6DhcpServers:
      - string
    ipv6DnsServers:
      - string
    ipv6GateWay: string
    ipv6GlobalPool: string
    ipv6Prefix: true
    ipv6PrefixLength: 0
    ipv6Subnet: string
    ipv6TotalHost: 0
    name: string
    siteId: string
    slaacSupport: true
    type: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "executionId": "string",
      "executionStatusUrl": "string",
      "message": "string"
    }
"""
