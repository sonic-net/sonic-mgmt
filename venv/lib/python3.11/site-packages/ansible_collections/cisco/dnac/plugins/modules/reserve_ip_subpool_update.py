#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: reserve_ip_subpool_update
short_description: Resource module for Reserve Ip Subpool
  Update
description:
  - Manage operation update of the resource Reserve
    Ip Subpool Update.
  - API to update ip subpool from the global pool.
version_added: '4.0.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id query parameter. Id of subpool group.
    type: str
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
  ipv6AddressSpace:
    description: If the value is false only ipv4 input
      are required. NOTE if value is false then any
      existing ipv6 subpool in the group will be removed.
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
      prefix length input field is enabled, if it is
      false ipv6 total Host input is enable.
    type: bool
  ipv6PrefixLength:
    description: IPv6 prefix length is required when
      the ipv6prefix value is true.
    type: int
  ipv6Subnet:
    description: IPv6 Subnet address, example 2001 db8
      85a3 0 100 .
    type: str
  ipv6TotalHost:
    description: Size of pool in terms of number of
      IPs. IPv6 total host is required when ipv6prefix
      value is false.
    type: int
  name:
    description: Name of the reserve ip sub pool.
    type: str
  siteId:
    description: SiteId path parameter. Site id of site
      to update sub pool.
    type: str
  slaacSupport:
    description: Slaac Support.
    type: bool
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings UpdateReserveIPSubpool
    description: Complete reference of the UpdateReserveIPSubpool
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-reserve-ip-subpool
notes:
  - SDK Method used are
    network_settings.NetworkSettings.update_reserve_ip_subpool,
    - |- Paths used are put /dna/intent/api/v1/reserve-ip-subpool/{siteId},
    - > Removed 'type',
    'ipv4GlobalPool',
    'ipv4Prefix',
    'ipv4PrefixLength',
    'ipv4Subnet' and 'ipv4TotalHost'
    options in v4.3.0.
"""

EXAMPLES = r"""
---
- name: Update by id
  cisco.dnac.reserve_ip_subpool_update:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    id: string
    ipv4DhcpServers:
      - string
    ipv4DnsServers:
      - string
    ipv4GateWay: string
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
