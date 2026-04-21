#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: ipam_global_ip_address_pools_count_info
short_description: Information module for Ipam Global
  Ip Address Pools Count
description:
  - Get all Ipam Global Ip Address Pools Count. - >
    Counts global IP address pools. Global pools are
    not associated with any particular site, but may
    have portions of their address space reserved by
    site-specific subpools.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings CountsGlobalIPAddressPools
    description: Complete reference of the CountsGlobalIPAddressPools
      API.
    link: https://developer.cisco.com/docs/dna-center/#!counts-global-ip-address-pools
notes:
  - SDK Method used are
    network_settings.NetworkSettings.counts_global_ip_address_pools,
  - Paths used are
    get /dna/intent/api/v1/ipam/globalIpAddressPools/count,
"""

EXAMPLES = r"""
---
- name: Get all Ipam Global Ip Address Pools Count
  cisco.dnac.ipam_global_ip_address_pools_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "count": 0
      },
      "version": "string"
    }
"""
