#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: tag_count_info
short_description: Information module for Tag Count
description:
  - Get all Tag Count.
  - Returns tag count.
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
      - Name query parameter.
    type: str
  nameSpace:
    description:
      - NameSpace query parameter.
    type: str
  attributeName:
    description:
      - AttributeName query parameter.
    type: str
  size:
    description:
      - Size query parameter. Size in kilobytes(KB).
    type: str
  systemTag:
    description:
      - SystemTag query parameter.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Tag GetTagCount
    description: Complete reference of the GetTagCount
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-tag-count
notes:
  - SDK Method used are
    tag.Tag.get_tag_count,
  - Paths used are
    get /dna/intent/api/v1/tag/count,
"""

EXAMPLES = r"""
---
- name: Get all Tag Count
  cisco.dnac.tag_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    name: string
    nameSpace: string
    attributeName: string
    size: string
    systemTag: string
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
