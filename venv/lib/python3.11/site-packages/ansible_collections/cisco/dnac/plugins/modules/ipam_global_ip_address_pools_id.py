#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: ipam_global_ip_address_pools_id
short_description: Resource module for Ipam Global Ip
  Address Pools Id
description:
  - Manage operations update and delete of the resource
    Ipam Global Ip Address Pools Id. - > Deletes a global
    IP address pool. A global IP address pool can only
    be deleted if there are no subpools reserving address
    space from it.
  - Updates a global IP address pool.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  addressSpace:
    description: Ipam Global Ip Address Pools Id's addressSpace.
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
  id:
    description: Id path parameter. The `id` of the
      global IP address pool to update.
    type: str
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
      Settings DeleteAGlobalIPAddressPool
    description: Complete reference of the DeleteAGlobalIPAddressPool
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-a-global-ip-address-pool
  - name: Cisco DNA Center documentation for Network
      Settings UpdatesAGlobalIPAddressPool
    description: Complete reference of the UpdatesAGlobalIPAddressPool
      API.
    link: https://developer.cisco.com/docs/dna-center/#!updates-a-global-ip-address-pool
notes:
  - SDK Method used are
    network_settings.NetworkSettings.delete_a_global_ip_address_pool,
    network_settings.NetworkSettings.updates_a_global_ip_address_pool,
  - Paths used are
    delete /dna/intent/api/v1/ipam/globalIpAddressPools/{id},
    put /dna/intent/api/v1/ipam/globalIpAddressPools/{id},
"""

EXAMPLES = r"""
---
- name: Update by id
  cisco.dnac.ipam_global_ip_address_pools_id:
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
    id: string
    name: string
    poolType: string
- name: Delete by id
  cisco.dnac.ipam_global_ip_address_pools_id:
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
      "version": "string",
      "response": {
        "url": "string",
        "taskId": "string"
      }
    }
"""
