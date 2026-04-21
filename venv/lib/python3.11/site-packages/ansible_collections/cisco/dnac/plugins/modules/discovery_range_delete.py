#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: discovery_range_delete
short_description: Resource module for Discovery Range
  Delete
description:
  - Manage operation delete of the resource Discovery
    Range Delete.
  - Stops discovery for the given range and removes
    them.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  recordsToDelete:
    description: RecordsToDelete path parameter. Number
      of records to delete from the starting index.
    type: int
  startIndex:
    description: StartIndex path parameter. Starting
      index for the records.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Discovery
      DeleteDiscoveryBySpecifiedRange
    description: Complete reference of the DeleteDiscoveryBySpecifiedRange
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-discovery-by-specified-range
notes:
  - SDK Method used are
    discovery.Discovery.delete_discovery_by_specified_range,
  - Paths used are
    delete /dna/intent/api/v1/discovery/{startIndex}/{recordsToDelete},
"""

EXAMPLES = r"""
---
- name: Delete all
  cisco.dnac.discovery_range_delete:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    recordsToDelete: 0
    startIndex: 0
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
