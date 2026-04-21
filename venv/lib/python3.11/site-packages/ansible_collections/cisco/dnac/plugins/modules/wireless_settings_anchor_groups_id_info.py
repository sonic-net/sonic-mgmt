#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_settings_anchor_groups_id_info
short_description: Information module for Wireless Settings
  Anchor Groups Id
description:
  - Get Wireless Settings Anchor Groups Id by id.
  - This API allows the user to get an AnchorGroup by
    AnchorGroup ID.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. AnchorGroup ID.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      GetAnchorGroupByID
    description: Complete reference of the GetAnchorGroupByID
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-anchor-group-by-id
notes:
  - SDK Method used are
    wireless.Wireless.get_anchor_group_by_id,
  - Paths used are
    get /dna/intent/api/v1/wirelessSettings/anchorGroups/{id},
"""

EXAMPLES = r"""
---
- name: Get Wireless Settings Anchor Groups Id by id
  cisco.dnac.wireless_settings_anchor_groups_id_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
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
