#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: tag_member_type_info
short_description: Information module for Tag Member
  Type
description:
  - Get all Tag Member Type.
  - Returns list of supported resource types.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Tag GetTagResourceTypes
    description: Complete reference of the GetTagResourceTypes
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-tag-resource-types
notes:
  - SDK Method used are
    tag.Tag.get_tag_resource_types,
  - Paths used are
    get /dna/intent/api/v1/tag/member/type,
"""

EXAMPLES = r"""
---
- name: Get all Tag Member Type
  cisco.dnac.tag_member_type_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
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
        "string"
      ]
    }
"""
