#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: application_policy_application_set_info
short_description: Information module for Application
  Policy Application Set
description:
  - Get all Application Policy Application Set.
  - Get application set/s by offset/limit or by name.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  attributes:
    description:
      - Attributes query parameter. Attributes to retrieve,
        valid value applicationSet.
    type: str
  name:
    description:
      - Name query parameter. Application set name.
    type: str
  offset:
    description:
      - Offset query parameter. The starting point or
        index from where the paginated results should
        begin.
    type: int
  limit:
    description:
      - >
        Limit query parameter. The limit which is the
        maximum number of items to include in a single
        page of results, max value 500.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Application
      Policy GetApplicationSetsV2
    description: Complete reference of the GetApplicationSetsV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-application-sets-v-2
notes:
  - SDK Method used are
    application_policy.ApplicationPolicy.get_application_sets_v2,
  - Paths used are
    get /dna/intent/api/v2/application-policy-application-set,
"""

EXAMPLES = r"""
---
- name: Get all Application Policy Application Set
  cisco.dnac.application_policy_application_set_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    attributes: string
    name: string
    offset: 0
    limit: 0
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
          "id": "string",
          "instanceId": 0,
          "displayName": "string",
          "instanceVersion": 0,
          "defaultBusinessRelevance": "string",
          "identitySource": {
            "id": "string",
            "type": "string"
          },
          "name": "string",
          "namespace": "string",
          "scalableGroupExternalHandle": "string",
          "scalableGroupType": "string",
          "type": "string"
        }
      ],
      "version": "string"
    }
"""
