#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_profiles_id_site_tags_bulk
short_description: Resource module for Wireless Profiles
  Id Site Tags Bulk
description:
  - Manage operation create of the resource Wireless
    Profiles Id Site Tags Bulk. - > This endpoint allows
    the creation of multiple `Site Tags` associated
    with a specific `Wireless Profile` in a single request.
    The `id` of the `Wireless Profile` must be provided
    as a path parameter, and a list of `Site Tags` should
    be included in the request body. Note Only one Site
    Tag siteTag can be created per siteId. If multiple
    siteTags are specified for the same siteId within
    a request, only the last one will be saved, overriding
    any previously configured tags. When creating a
    Site Tag under a Flex-enabled Wireless Profile i.e.,
    a Wireless Profile with one or more Flex SSIDs ,
    a non-default Flex Profile Name flexProfileName
    will be used. If no custom flexProfileName is defined,
    the System will automatically generate one and configure
    it in the controller.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. Network profile
      id.
    type: str
  items:
    description: Wireless Profiles Id Site Tags Bulk's
      items.
    elements: list
    suboptions:
      apProfileName:
        description: Ap Profile Name.
        type: str
      flexProfileName:
        description: Flex Profile Name.
        type: str
      siteIds:
        description: Site Ids.
        elements: str
        type: list
      siteTagName:
        description: Use English letters, numbers, special characters except <, /, '.*', ? and leading/trailing space.
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      CreateMultipleSiteTagsForAWirelessProfileInBulk
    description: Complete reference of the CreateMultipleSiteTagsForAWirelessProfileInBulk
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-multiple-site-tags-for-a-wireless-profile-in-bulk
notes:
  - SDK Method used are
    wireless.Wireless.create_multiple_site_tags_for_a_wireless_profile_in_bulk,
  - Paths used are
    post /dna/intent/api/v1/wirelessProfiles/{id}/siteTags/bulk,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.wireless_profiles_id_site_tags_bulk:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    id: string
    items:
      - - apProfileName: string
          flexProfileName: string
          siteIds:
            - string
          siteTagName: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""
