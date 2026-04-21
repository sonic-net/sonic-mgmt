#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: application_policy_application_set_count_info
short_description: Information module for Application
  Policy Application Set Count
description:
  - Get all Application Policy Application Set Count.
  - Get the number of all existing application sets.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  scalableGroupType:
    description:
      - ScalableGroupType query parameter. Scalable
        group type to retrieve, valid value APPLICATION_GROUP.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Application
      Policy GetApplicationSetCountV2
    description: Complete reference of the GetApplicationSetCountV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-application-set-count-v-2
notes:
  - SDK Method used are
    application_policy.ApplicationPolicy.get_application_set_count_v2,
  - Paths used are
    get /dna/intent/api/v2/application-policy-application-set-count,
"""

EXAMPLES = r"""
---
- name: Get all Application Policy Application Set Count
  cisco.dnac.application_policy_application_set_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    scalableGroupType: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": 0,
      "version": "string"
    }
"""
