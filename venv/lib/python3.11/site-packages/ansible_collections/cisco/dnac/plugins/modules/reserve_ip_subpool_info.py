#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: reserve_ip_subpool_info
short_description: Information module for Reserve Ip
  Subpool
description:
  - Get all Reserve Ip Subpool.
  - API to get the ip subpool info.
version_added: '3.1.0'
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
        SiteId query parameter. Site id of site from
        which to retrieve associated reserve pools.
        Either siteId (per site queries) or ignoreInheritedGroups
        must be used. They can also be used together.
    type: str
  offset:
    description:
      - Offset query parameter. Offset/starting row.
        Indexed from 1.
    type: int
  limit:
    description:
      - >
        Limit query parameter. Number of reserve pools
        to be retrieved. Default is 25 if not specified.
        Maximum allowed limit is 500.
    type: int
  ignoreInheritedGroups:
    description:
      - >
        IgnoreInheritedGroups query parameter. Ignores
        pools inherited from parent site. Either siteId
        or ignoreInheritedGroups must be passed. They
        can also be used together.
    type: bool
  poolUsage:
    description:
      - PoolUsage query parameter. Can take values empty,
        partially-full or empty-partially-full.
    type: str
  groupName:
    description:
      - GroupName query parameter. Name of the group.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings GetReserveIPSubpool
    description: Complete reference of the GetReserveIPSubpool
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-reserve-ip-subpool
notes:
  - SDK Method used are
    network_settings.NetworkSettings.get_reserve_ip_subpool,
  - Paths used are
    get /dna/intent/api/v1/reserve-ip-subpool,
"""

EXAMPLES = r"""
---
- name: Get all Reserve Ip Subpool
  cisco.dnac.reserve_ip_subpool_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    siteId: string
    offset: 1      # Must be >= 1
    limit: 25     # Must be >= 1
    ignoreInheritedGroups: true
    poolUsage: string
    groupName: string
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
          "groupName": "string",
          "ipPools": [
            {
              "ipPoolName": "string",
              "dhcpServerIps": [
                {}
              ],
              "gateways": [
                "string"
              ],
              "createTime": 0,
              "lastUpdateTime": 0,
              "totalIpAddressCount": 0,
              "usedIpAddressCount": 0,
              "parentUuid": "string",
              "owner": "string",
              "shared": true,
              "overlapping": true,
              "configureExternalDhcp": true,
              "usedPercentage": "string",
              "clientOptions": {},
              "groupUuid": "string",
              "dnsServerIps": [
                {}
              ],
              "context": [
                {
                  "owner": "string",
                  "contextKey": "string",
                  "contextValue": "string"
                }
              ],
              "ipv6": true,
              "id": "string",
              "ipPoolCidr": "string"
            }
          ],
          "siteId": "string",
          "siteHierarchy": "string",
          "type": "string",
          "groupOwner": "string"
        }
      ],
      "version": "string"
    }
"""
