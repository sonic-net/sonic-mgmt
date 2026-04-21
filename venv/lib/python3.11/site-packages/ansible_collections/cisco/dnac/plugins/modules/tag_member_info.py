#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: tag_member_info
short_description: Information module for Tag Member
description:
  - Get all Tag Member.
  - Returns tag members specified by id.
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
      - >
        MemberType query parameter. Entity type of the
        member. Possible values can be retrieved by
        using /tag/member/type API.
    type: str
  offset:
    description:
      - Offset query parameter. Used for pagination.
        It indicates the starting row number out of
        available member records.
    type: float
  limit:
    description:
      - >
        Limit query parameter. The number of members
        to be retrieved. If not specified, the default
        is 500. The maximum allowed limit is 500.
    type: float
  memberAssociationType:
    description:
      - >
        MemberAssociationType query parameter. Indicates
        how the member is associated with the tag. Possible
        values and description. 1) DYNAMIC The member
        is associated to the tag through rules. 2) STATIC
        – The member is associated to the tag manually.
        3) MIXED – The member is associated manually
        and also satisfies the rule defined for the
        tag.
    type: str
  level:
    description:
      - Level query parameter.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Tag GetTagMembersById
    description: Complete reference of the GetTagMembersById
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-tag-members-by-id
notes:
  - SDK Method used are
    tag.Tag.get_tag_members_by_id,
  - Paths used are
    get /dna/intent/api/v1/tag/{id}/member,
"""

EXAMPLES = r"""
---
- name: Get all Tag Member
  cisco.dnac.tag_member_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    memberType: string
    offset: 0
    limit: 0
    memberAssociationType: string
    level: string
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
      "response": [
        {
          "instanceUuid": "string"
        }
      ]
    }
"""
