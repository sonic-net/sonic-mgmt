#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_settings_ssids_override_at_sites_info
short_description: Information module for Wireless Settings
  Ssids Override At Sites
description:
  - Get all Wireless Settings Ssids Override At Sites.
  - Retrieve list of siteIds with information of SSIDs
    which are overridden.
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
      - SiteId query parameter. Site UUID.
    type: str
  offset:
    description:
      - Offset query parameter. The first record to
        show for this page; the first record is numbered
        1.
    type: float
  limit:
    description:
      - >
        Limit query parameter. The number of records
        to show for this page. Default is 500 if not
        specified. Maximum allowed limit is 500.
    type: float
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      RetrieveSitesWithOverriddenSSIDs
    description: Complete reference of the RetrieveSitesWithOverriddenSSIDs
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieve-sites-with-overridden-ssi-ds
notes:
  - SDK Method used are
    wireless.Wireless.retrieve_sites_with_overridden_ssids,
  - Paths used are
    get /dna/intent/api/v1/wirelessSettings/ssids/overrideAtSites,
"""

EXAMPLES = r"""
---
- name: Get all Wireless Settings Ssids Override At
    Sites
  cisco.dnac.wireless_settings_ssids_override_at_sites_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    siteId: string
    offset: 0
    limit: 0
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
          "siteId": "string",
          "siteNameHierarchy": "string",
          "ssids": [
            {
              "id": "string",
              "ssid": "string"
            }
          ]
        }
      ],
      "version": "string"
    }
"""
