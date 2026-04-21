#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: ipam_global_ip_address_pools_info
short_description: Information module for Ipam Global
  Ip Address Pools
description:
  - Get all Ipam Global Ip Address Pools. - > Retrieves
    global IP address pools. Global pools are not associated
    with any particular site, but may have portions
    of their address space reserved by site-specific
    subpools.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  offset:
    description:
      - Offset query parameter. The first record to
        show for this page; the first record is numbered
        1.
    type: int
  limit:
    description:
      - Limit query parameter. The number of records
        to show for this page; the minimum is 1, and
        the maximum is 500.
    type: int
  sortBy:
    description:
      - SortBy query parameter. A property within the
        response to sort by.
    type: str
  order:
    description:
      - Order query parameter. Whether ascending or
        descending order should be used to sort the
        response.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings RetrievesGlobalIPAddressPools
    description: Complete reference of the RetrievesGlobalIPAddressPools
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-global-ip-address-pools
notes:
  - SDK Method used are
    network_settings.NetworkSettings.retrieves_global_ip_address_pools,
  - Paths used are
    get /dna/intent/api/v1/ipam/globalIpAddressPools,
"""

EXAMPLES = r"""
---
- name: Get all Ipam Global Ip Address Pools
  cisco.dnac.ipam_global_ip_address_pools_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    offset: 0
    limit: 0
    sortBy: string
    order: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": [
        {
          "addressSpace": {
            "subnet": "string",
            "prefixLength": 0,
            "gatewayIpAddress": "string",
            "dhcpServers": [
              "string"
            ],
            "dnsServers": [
              "string"
            ],
            "totalAddresses": "string",
            "unassignableAddresses": "string",
            "assignedAddresses": "string",
            "defaultAssignedAddresses": "string"
          },
          "id": "string",
          "name": "string",
          "poolType": "string"
        }
      ],
      "version": "string"
    }
"""
