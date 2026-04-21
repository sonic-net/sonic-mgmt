#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sites_site_id_wireless_settings_flex_connect_aaa_override_info
short_description: Information module for Sites Site
  Id Wireless Settings Flex Connect Aaa Override
description:
  - Get all Sites Site Id Wireless Settings Flex Connect
    Aaa Override.
  - This API allows the user to get all Flex Connect
    AAA Override VLAN settings at the given site.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  siteId:
    description:
      - SiteId path parameter. Site Id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      GetAAAOverrideVlanSettingsBySite
    description: Complete reference of the GetAAAOverrideVlanSettingsBySite
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-aaa-override-vlan-settings-by-site
notes:
  - SDK Method used are
    wireless.Wireless.get_aaa_override_vlan_settings_by_site,
  - Paths used are
    get /dna/intent/api/v1/sites/{siteId}/wirelessSettings/flexConnectAaaOverride,
"""

EXAMPLES = r"""
---
- name: Get all Sites Site Id Wireless Settings Flex
    Connect Aaa Override
  cisco.dnac.sites_site_id_wireless_settings_flex_connect_aaa_override_info:
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
      "response": [
        {
          "vlanId": 0,
          "vlanName": "string",
          "inheritedSiteUUID": "string",
          "inheritedSiteNameHierarchy": "string"
        }
      ],
      "version": "string"
    }
"""
