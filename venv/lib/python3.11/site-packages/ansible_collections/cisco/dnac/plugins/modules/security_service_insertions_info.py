#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: security_service_insertions_info
short_description: Information module for Security Service
  Insertions
description:
  - Get all Security Service Insertions.
  - Retrieves a list of all Security Service Insertions
    SSIs configured across fabric sites.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  limit:
    description:
      - >
        Limit query parameter. Maximum number of records
        to return. Default value is 100, minimum value
        is 1 and maximum value is 100.
    type: str
  offset:
    description:
      - Offset query parameter. Starting record for
        pagination. The first record is numbered 1.
    type: float
  order:
    description:
      - >
        Order query parameter. The sorting order for
        the response can be specified as either ascending
        (asc) or descending (desc). The default order
        is ascending (asc).
    type: str
  fabricSiteName:
    description:
      - >
        FabricSiteName query parameter. Filter by fabric
        site name (supports partial search). For example,
        searching for "London" will match "London fabric
        site", etc.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA SecurityServiceInsertions
    description: Complete reference of the SecurityServiceInsertions
      API.
    link: https://developer.cisco.com/docs/dna-center/#!security-service-insertions
notes:
  - SDK Method used are
    sda.Sda.security_service_insertions,
  - Paths used are
    get /dna/intent/api/v1/securityServiceInsertions,
"""

EXAMPLES = r"""
---
- name: Get all Security Service Insertions
  cisco.dnac.security_service_insertions_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    limit: string
    offset: 0
    order: string
    fabricSiteName: string
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
          "siteId": "string",
          "fabricSiteName": "string",
          "virtualNetworks": [
            {
              "id": "string",
              "name": "string",
              "devices": [
                {
                  "id": "string",
                  "hostName": "string",
                  "layer3Handoffs": [
                    {
                      "id": "string",
                      "firewallIpV4AddressWithMask": "string"
                    }
                  ]
                }
              ]
            }
          ]
        }
      ],
      "version": "string"
    }
"""
