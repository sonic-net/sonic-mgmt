#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: diagnostic_validation_workflows_info
short_description: Information module for Diagnostic
  Validation Workflows
description:
  - Get all Diagnostic Validation Workflows.
  - Get Diagnostic Validation Workflows by id. - > Retrieves
    the workflows that have been successfully submitted
    and are currently available. This is sorted by `submitTime`.
  - Retrieves workflow details for a workflow id.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  startTime:
    description:
      - StartTime query parameter. Workflows started
        after the given time (as milliseconds since
        UNIX epoch).
    type: float
  endTime:
    description:
      - EndTime query parameter. Workflows started before
        the given time (as milliseconds since UNIX epoch).
    type: float
  runStatus:
    description:
      - >
        RunStatus query parameter. Execution status
        of the workflow. If the workflow is successfully
        submitted, runStatus is `PENDING`. If the workflow
        execution has started, runStatus is `IN_PROGRESS`.
        If the workflow executed is completed with all
        validations executed, runStatus is `COMPLETED`.
        If the workflow execution fails while running
        validations, runStatus is `FAILED`.
    type: str
  offset:
    description:
      - Offset query parameter. The first record to
        show for this page; the first record is numbered
        1.
    type: int
  limit:
    description:
      - >
        Limit query parameter. Specifies the maximum
        number of workflows to return per page. Must
        be an integer between 1 and 500, inclusive.
    type: int
  id:
    description:
      - Id path parameter. Workflow id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Health
      and Performance RetrievesTheListOfValidationWorkflows
    description: Complete reference of the RetrievesTheListOfValidationWorkflows
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-list-of-validation-workflows
  - name: Cisco DNA Center documentation for Health
      and Performance RetrievesValidationWorkflowDetails
    description: Complete reference of the RetrievesValidationWorkflowDetails
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-validation-workflow-details
notes:
  - SDK Method used are
    health_and_performance.HealthAndPerformance.retrieves_the_list_of_validation_workflows,
    health_and_performance.HealthAndPerformance.retrieves_validation_workflow_details,
  - Paths used are
    get /dna/intent/api/v1/diagnosticValidationWorkflows,
    get /dna/intent/api/v1/diagnosticValidationWorkflows/{id},
"""

EXAMPLES = r"""
---
- name: Get all Diagnostic Validation Workflows
  cisco.dnac.diagnostic_validation_workflows_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    startTime: 0
    endTime: 0
    runStatus: string
    offset: 0
    limit: 0
  register: result
- name: Get Diagnostic Validation Workflows by id
  cisco.dnac.diagnostic_validation_workflows_info:
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
        "runStatus": "string",
        "submitTime": 0,
        "validationSetIds": [
          "string"
        ],
        "releaseVersion": "string",
        "validationSetsRunDetails": [
          {
            "validationSetId": "string",
            "startTime": 0,
            "endTime": 0,
            "validationStatus": "string",
            "version": "string",
            "validationRunDetails": [
              {
                "validationId": "string",
                "validationName": "string",
                "validationMessage": "string",
                "validationStatus": "string"
              }
            ]
          }
        ],
        "validationStatus": "string"
      },
      "version": "string"
    }
"""
