#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: ipam_site_ip_address_pools_id
short_description: Resource module for Ipam Site Ip
  Address Pools Id
description:
  - Manage operations update and delete of the resource
    Ipam Site Ip Address Pools Id.
  - Releases an IP address subpool.
  - Updates an IP address subpool, which reserves address
    space from a global pool or global pools for a particular
    site.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. The `id` of the
      IP address subpool to delete.
    type: str
  ipV4AddressSpace:
    description: Ipam Site Ip Address Pools Id's ipV4AddressSpace.
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
    type: dict
  ipV6AddressSpace:
    description: Ipam Site Ip Address Pools Id's ipV6AddressSpace.
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
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings ReleaseAnIPAddressSubpool
    description: Complete reference of the ReleaseAnIPAddressSubpool
      API.
    link: https://developer.cisco.com/docs/dna-center/#!release-an-ip-address-subpool
  - name: Cisco DNA Center documentation for Network
      Settings UpdatesAnIPAddressSubpool
    description: Complete reference of the UpdatesAnIPAddressSubpool
      API.
    link: https://developer.cisco.com/docs/dna-center/#!updates-an-ip-address-subpool
notes:
  - SDK Method used are
    network_settings.NetworkSettings.release_an_ip_address_subpool,
    network_settings.NetworkSettings.updates_an_ip_address_subpool,
  - Paths used are
    delete /dna/intent/api/v1/ipam/siteIpAddressPools/{id},
    put /dna/intent/api/v1/ipam/siteIpAddressPools/{id},
"""

EXAMPLES = r"""
---
- name: Delete by id
  cisco.dnac.ipam_site_ip_address_pools_id:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    id: string
- name: Update by id
  cisco.dnac.ipam_site_ip_address_pools_id:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    id: string
    ipV4AddressSpace:
      dhcpServers:
        - string
      dnsServers:
        - string
      gatewayIpAddress: string
      globalPoolId: string
      prefixLength: 0
      slaacSupport: true
      subnet: string
    ipV6AddressSpace:
      dhcpServers:
        - string
      dnsServers:
        - string
      gatewayIpAddress: string
      globalPoolId: string
      prefixLength: 0
      slaacSupport: true
      subnet: string
    name: string
    poolType: string
    siteId: string
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
