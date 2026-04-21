#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: ipam_site_ip_address_pools_count_info
short_description: Information module for Ipam Site
  Ip Address Pools Count
description:
  - Get all Ipam Site Ip Address Pools Count.
  - Counts IP address subpools, which reserve address
    space from a global pool or global pools .
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  siteId:
    description:
      - >
        SiteId query parameter. The `id` of the site
        for which to retrieve IP address subpools. Only
        subpools whose `siteId` matches will be counted.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings CountsIPAddressSubpools
    description: Complete reference of the CountsIPAddressSubpools
      API.
    link: https://developer.cisco.com/docs/dna-center/#!counts-ip-address-subpools
notes:
  - SDK Method used are
    network_settings.NetworkSettings.counts_ip_address_subpools,
  - Paths used are
    get /dna/intent/api/v1/ipam/siteIpAddressPools/count,
"""

EXAMPLES = r"""
---
- name: Get all Ipam Site Ip Address Pools Count
  cisco.dnac.ipam_site_ip_address_pools_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    siteId: string
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
