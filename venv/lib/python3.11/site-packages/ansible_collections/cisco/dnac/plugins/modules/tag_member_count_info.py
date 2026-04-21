#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: tag_member_count_info
short_description: Information module for Tag Member
  Count
description:
  - Get all Tag Member Count.
  - Returns the number of members in a given tag.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. Tag ID.
    type: str
  memberType:
    description:
      - MemberType query parameter.
    type: str
  memberAssociationType:
    description:
      - MemberAssociationType query parameter.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Tag GetTagMemberCount
    description: Complete reference of the GetTagMemberCount
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-tag-member-count
notes:
  - SDK Method used are
    tag.Tag.get_tag_member_count,
  - Paths used are
    get /dna/intent/api/v1/tag/{id}/member/count,
"""

EXAMPLES = r"""
---
- name: Get all Tag Member Count
  cisco.dnac.tag_member_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    memberType: string
    memberAssociationType: string
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
      "version": "string",
      "response": 0
    }
"""
