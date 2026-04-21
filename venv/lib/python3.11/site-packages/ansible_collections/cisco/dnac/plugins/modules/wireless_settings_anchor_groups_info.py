#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_settings_anchor_groups_info
short_description: Information module for Wireless Settings
  Anchor Groups
description:
  - Get all Wireless Settings Anchor Groups.
  - This API allows the user to get AnchorGroups that
    captured in wireless settings design.
version_added: '6.17.0'
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
        Limit query parameter. The number of records
        to show for this page. Default is 500 if not
        specified. Maximum allowed limit is 500.
    type: str
  offset:
    description:
      - Offset query parameter. The first record to
        show for this page, the first record is numbered
        1.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      GetAnchorGroups
    description: Complete reference of the GetAnchorGroups
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-anchor-groups
notes:
  - SDK Method used are
    wireless.Wireless.get_anchor_groups,
  - Paths used are
    get /dna/intent/api/v1/wirelessSettings/anchorGroups,
"""

EXAMPLES = r"""
---
- name: Get all Wireless Settings Anchor Groups
  cisco.dnac.wireless_settings_anchor_groups_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    limit: string
    offset: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "id": "string",
      "anchorGroupName": "string",
      "mobilityAnchors": [
        {
          "deviceName": "string",
          "ipAddress": "string",
          "anchorPriority": "string",
          "managedAnchorWlc": true,
          "peerDeviceType": "string",
          "macAddress": "string",
          "mobilityGroupName": "string",
          "privateIp": "string"
        }
      ]
    }
"""
