#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_profiles_id_policy_tags_policy_tag_id_info
short_description: Information module for Wireless Profiles
  Id Policy Tags Policy Tag Id
description:
  - Get Wireless Profiles Id Policy Tags Policy Tag
    Id by id. - > This endpoint retrieves the details
    of a specific `Policy Tag` associated with a given
    `Wireless Profile`. This API requires the `id` of
    the `Wireless Profile` and the `policyTagId` of
    the `Policy Tag`.
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
      - Id path parameter. Wireless Profile Id.
    type: str
  policyTagId:
    description:
      - PolicyTagId path parameter. Policy Tag Id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      RetrieveASpecificPolicyTagForAWirelessProfile
    description: Complete reference of the RetrieveASpecificPolicyTagForAWirelessProfile
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieve-a-specific-policy-tag-for-a-wireless-profile
notes:
  - SDK Method used are
    wireless.Wireless.retrieve_a_specific_policy_tag_for_a_wireless_profile,
  - Paths used are
    get /dna/intent/api/v1/wirelessProfiles/{id}/policyTags/{policyTagId},
"""

EXAMPLES = r"""
---
- name: Get Wireless Profiles Id Policy Tags Policy
    Tag Id by id
  cisco.dnac.wireless_profiles_id_policy_tags_policy_tag_id_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
    policyTagId: string
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
        "siteIds": [
          "string"
        ],
        "policyTagName": "string",
        "apZones": [
          "string"
        ],
        "policyTagId": "string"
      },
      "version": "string"
    }
"""
