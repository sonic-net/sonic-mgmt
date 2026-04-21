#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: diagnostic_validation_sets_info
short_description: Information module for Diagnostic
  Validation Sets
description:
  - Get all Diagnostic Validation Sets.
  - Get Diagnostic Validation Sets by id.
  - Retrieves all the validation sets and optionally
    the contained validations.
  - Retrieves validation details for the given validation
    set id.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  view:
    description:
      - >
        View query parameter. When the query parameter
        `view=DETAIL` is passed, all validation sets
        and associated validations will be returned.
        When the query parameter `view=DEFAULT` is passed,
        only validation sets metadata will be returned.
    type: str
  id:
    description:
      - Id path parameter. Validation set id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Health
      and Performance RetrievesAllTheValidationSets
    description: Complete reference of the RetrievesAllTheValidationSets
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-all-the-validation-sets
  - name: Cisco DNA Center documentation for Health
      and Performance RetrievesValidationDetailsForAValidationSet
    description: Complete reference of the RetrievesValidationDetailsForAValidationSet
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-validation-details-for-a-validation-set
notes:
  - SDK Method used are
    health_and_performance.HealthAndPerformance.retrieves_all_the_validation_sets,
    health_and_performance.HealthAndPerformance.retrieves_validation_details_for_a_validation_set,
  - Paths used are
    get /dna/intent/api/v1/diagnosticValidationSets,
    get /dna/intent/api/v1/diagnosticValidationSets/{id},
"""

EXAMPLES = r"""
---
- name: Get all Diagnostic Validation Sets
  cisco.dnac.diagnostic_validation_sets_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    view: string
  register: result
- name: Get Diagnostic Validation Sets by id
  cisco.dnac.diagnostic_validation_sets_info:
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
      "response": {
        "id": "string",
        "name": "string",
        "description": "string",
        "version": "string",
        "validationGroups": [
          {
            "name": "string",
            "id": "string",
            "description": "string",
            "validations": [
              {
                "id": "string",
                "name": "string"
              }
            ]
          }
        ]
      },
      "version": "string"
    }
"""
