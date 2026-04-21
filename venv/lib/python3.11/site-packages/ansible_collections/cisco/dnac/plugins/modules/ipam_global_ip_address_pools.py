#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: ipam_global_ip_address_pools
short_description: Resource module for Ipam Global Ip
  Address Pools
description:
  - Manage operation create of the resource Ipam Global
    Ip Address Pools. - > Creates a global IP address
    pool, which is not bound to a particular site. A
    global pool must be either an IPv4 or IPv6 pool.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  addressSpace:
    description: Ipam Global Ip Address Pools's addressSpace.
    suboptions:
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
      prefixLength:
        description: The network mask component, as
          a decimal, for the CIDR notation of this subnet.
        type: float
      subnet:
        description: The IP address component of the
          CIDR notation for this subnet.
        type: str
    type: dict
  name:
    description: The name for this reserve IP pool.
      Only letters, numbers, '-' (hyphen), '_' (underscore),
      '.' (period), and '/' (forward slash) are allowed.
    type: str
  poolType:
    description: Once created, a global pool type cannot
      be changed. Tunnel Assigns IP addresses to site-to-site
      VPN for IPSec tunneling. Generic used for all
      other network types.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings CreateAGlobalIPAddressPool
    description: Complete reference of the CreateAGlobalIPAddressPool
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-a-global-ip-address-pool
notes:
  - SDK Method used are
    network_settings.NetworkSettings.create_a_global_ip_address_pool,
  - Paths used are
    post /dna/intent/api/v1/ipam/globalIpAddressPools,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.ipam_global_ip_address_pools:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    addressSpace:
      dhcpServers:
        - string
      dnsServers:
        - string
      gatewayIpAddress: string
      prefixLength: 0
      subnet: string
    name: string
    poolType: string
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
