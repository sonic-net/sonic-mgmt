#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: ipam_site_ip_address_pools_info
short_description: Information module for Ipam Site
  Ip Address Pools
description:
  - Get all Ipam Site Ip Address Pools.
  - Retrieves IP address subpools, which reserve address
    space from a global pool or global pools .
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
  siteId:
    description:
      - >
        SiteId query parameter. The `id` of the site
        for which to retrieve IP address subpools. Only
        subpools whose `siteId` exactly matches will
        be fetched, parent or child site matches will
        not be included.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings RetrievesIPAddressSubpools
    description: Complete reference of the RetrievesIPAddressSubpools
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-ip-address-subpools
notes:
  - SDK Method used are
    network_settings.NetworkSettings.retrieves_ip_address_subpools,
  - Paths used are
    get /dna/intent/api/v1/ipam/siteIpAddressPools,
"""

EXAMPLES = r"""
---
- name: Get all Ipam Site Ip Address Pools
  cisco.dnac.ipam_site_ip_address_pools_info:
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
      "response": [
        {
          "id": "string",
          "ipV4AddressSpace": {
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
            "defaultAssignedAddresses": "string",
            "slaacSupport": true,
            "globalPoolId": "string"
          },
          "ipV6AddressSpace": {
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
            "defaultAssignedAddresses": "string",
            "slaacSupport": true,
            "globalPoolId": "string"
          },
          "name": "string",
          "poolType": "string",
          "siteId": "string",
          "siteName": "string"
        }
      ],
      "version": "string"
    }
"""
