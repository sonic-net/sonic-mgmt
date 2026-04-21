#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_profiles_id_policy_tags_bulk
short_description: Resource module for Wireless Profiles
  Id Policy Tags Bulk
description:
  - Manage operation create of the resource Wireless
    Profiles Id Policy Tags Bulk. - > This endpoint
    allows the creation of multiple `Policy Tags` associated
    with a specific `Wireless Profile` in a single request.
    The `id` of the Wireless Profile must be provided
    as a path parameter, and a list of `Policy Tags`
    should be included in the request body. Note Multiple
    Policy Tags policyTag can be configured for the
    same siteId only if they have different sets of
    AP Zones apZones. If multiple Policy Tags are created
    with the same apZones for the same site or a parent
    site, only the last one will be saved, overriding
    the previous ones.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. Wireless Profile
      Id.
    type: str
  items:
    description: Wireless Profiles Id Policy Tags Bulk's
      items.
    elements: list
    suboptions:
      apZones:
        description: Ap Zones.
        elements: str
        type: list
      policyTagName:
        description: Use English letters, numbers,
          special characters except <, /, '.*',
          ? and leading/trailing space.
        type: str
      siteIds:
        description: Site Ids.
        elements: str
        type: list
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      CreateMultiplePolicyTagsForAWirelessProfileInBulk
    description: Complete reference of the CreateMultiplePolicyTagsForAWirelessProfileInBulk
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-multiple-policy-tags-for-a-wireless-profile-in-bulk
notes:
  - SDK Method used are
    wireless.Wireless.create_multiple_policy_tags_for_a_wireless_profile_in_bulk,
  - Paths used are
    post /dna/intent/api/v1/wirelessProfiles/{id}/policyTags/bulk,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.wireless_profiles_id_policy_tags_bulk:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    id: string
    items:
      - - apZones:
            - string
          policyTagName: string
          siteIds:
            - string
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
