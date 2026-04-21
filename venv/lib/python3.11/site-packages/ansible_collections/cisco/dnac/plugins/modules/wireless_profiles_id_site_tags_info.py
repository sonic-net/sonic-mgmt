#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_profiles_id_site_tags_info
short_description: Information module for Wireless Profiles
  Id Site Tags
description:
  - Get all Wireless Profiles Id Site Tags. - > This
    endpoint retrieves a list of all `Site Tags` associated
    with a specific `Wireless Profile`. This API requires
    the `id` of the `Wireless Profile` to be provided
    as a path parameter.
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
      - Id path parameter. Wireless profile id.
    type: str
  limit:
    description:
      - >
        Limit query parameter. The number of records
        to show for this page. Default is 500 if not
        specified. Maximum allowed limit is 500.
    type: float
  offset:
    description:
      - Offset query parameter.
    type: float
  siteTagName:
    description:
      - SiteTagName query parameter.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      RetrieveAllSiteTagsForAWirelessProfile
    description: Complete reference of the RetrieveAllSiteTagsForAWirelessProfile
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieve-all-site-tags-for-a-wireless-profile
notes:
  - SDK Method used are
    wireless.Wireless.retrieve_all_site_tags_for_a_wireless_profile,
  - Paths used are
    get /dna/intent/api/v1/wirelessProfiles/{id}/siteTags,
"""

EXAMPLES = r"""
---
- name: Get all Wireless Profiles Id Site Tags
  cisco.dnac.wireless_profiles_id_site_tags_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    limit: 0
    offset: 0
    siteTagName: string
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
      "response": [
        {
          "siteIds": [
            "string"
          ],
          "siteTagName": "string",
          "flexProfileName": "string",
          "apProfileName": "string",
          "siteTagId": "string"
        }
      ],
      "version": "string"
    }
"""
