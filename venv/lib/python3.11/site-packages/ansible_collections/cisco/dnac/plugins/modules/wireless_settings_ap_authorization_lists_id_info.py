#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_settings_ap_authorization_lists_id_info
short_description: Information module for Wireless Settings
  Ap Authorization Lists Id
description:
  - Get Wireless Settings Ap Authorization Lists Id
    by id. - > This API allows the user to get an AP
    Authorization List by AP Authorization List ID that
    captured in wireless settings design.
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
      - Id path parameter. AP Authorization List ID.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      GetAPAuthorizationListByID
    description: Complete reference of the GetAPAuthorizationListByID
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-ap-authorization-list-by-id
notes:
  - SDK Method used are
    wireless.Wireless.get_ap_authorization_list_by_id,
  - Paths used are
    get /dna/intent/api/v1/wirelessSettings/apAuthorizationLists/{id},
"""

EXAMPLES = r"""
---
- name: Get Wireless Settings Ap Authorization Lists
    Id by id
  cisco.dnac.wireless_settings_ap_authorization_lists_id_info:
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
      "response": {
        "id": "string",
        "apAuthorizationListName": "string",
        "localAuthorization": {
          "apMacEntries": [
            "string"
          ],
          "apSerialNumberEntries": [
            "string"
          ]
        },
        "remoteAuthorization": {
          "aaaServers": [
            "string"
          ],
          "authorizeApWithMac": true,
          "authorizeApWithSerialNumber": true
        }
      },
      "version": "string"
    }
"""
