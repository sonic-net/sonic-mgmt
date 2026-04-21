#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: tag_info
short_description: Information module for Tag
description:
  - Get all Tag.
  - Get Tag by id.
  - Returns tag specified by Id.
  - Returns the tags for given filter criteria.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  name:
    description:
      - Name query parameter. Tag name is mandatory
        when filter operation is used.
    type: str
  additionalInfo_nameSpace:
    description:
      - AdditionalInfo.nameSpace query parameter.
    type: str
  additionalInfo_attributes:
    description:
      - AdditionalInfo.attributes query parameter.
    type: str
  level:
    description:
      - Level query parameter.
    type: str
  offset:
    description:
      - Offset query parameter.
    type: float
  limit:
    description:
      - >
        Limit query parameter. The number of tags to
        be retrieved. If not specified, the default
        is 500. The maximum allowed limit is 500.
    type: float
  size:
    description:
      - Size query parameter. Size in kilobytes(KB).
    type: str
  field:
    description:
      - >
        Field query parameter. Available field names
        are 'name,id,parentId,type,additionalInfo.nameSpace,additionalInfo.attributes'.
    type: str
  sortBy:
    description:
      - SortBy query parameter. Only supported attribute
        is name. SortyBy is mandatory when order is
        used.
    type: str
  order:
    description:
      - Order query parameter. Available values are
        asc and des.
    type: str
  systemTag:
    description:
      - SystemTag query parameter.
    type: str
  id:
    description:
      - Id path parameter. Tag ID.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Tag GetTag
    description: Complete reference of the GetTag API.
    link: https://developer.cisco.com/docs/dna-center/#!get-tag
  - name: Cisco DNA Center documentation for Tag GetTagById
    description: Complete reference of the GetTagById
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-tag-by-id
notes:
  - SDK Method used are
    tag.Tag.get_tag,
    tag.Tag.get_tag_by_id,
  - Paths used are
    get /dna/intent/api/v1/tag,
    get /dna/intent/api/v1/tag/{id},
"""

EXAMPLES = r"""
---
- name: Get all Tag
  cisco.dnac.tag_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    name: string
    additionalInfo_nameSpace: string
    additionalInfo_attributes: string
    level: string
    offset: 0
    limit: 0
    size: string
    field: string
    sortBy: string
    order: string
    systemTag: string
  register: result
- name: Get Tag by id
  cisco.dnac.tag_info:
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
      "version": "string",
      "response": {
        "systemTag": true,
        "description": "string",
        "dynamicRules": [
          {
            "memberType": "string",
            "rules": {
              "values": [
                "string"
              ],
              "items": [
                {}
              ],
              "operation": "string",
              "name": "string",
              "value": "string"
            }
          }
        ],
        "name": "string",
        "id": "string",
        "instanceTenantId": "string"
      }
    }
"""
