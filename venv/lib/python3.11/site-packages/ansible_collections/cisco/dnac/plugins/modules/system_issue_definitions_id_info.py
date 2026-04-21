#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: system_issue_definitions_id_info
short_description: Information module for System Issue
  Definitions Id
description:
  - Get System Issue Definitions Id by id. - > Get system
    issue defintion for the given id. Definition includes
    all properties from IssueTriggerDefinition schema
    by default. For detailed information about the usage
    of the API, please refer to the Open API specification
    document - https //github.com/cisco-en-programmability/catalyst-center-api-
    specs/blob/main/Assurance/CE_Cat_Center_Org-issueAndHealthDefinitions-1.0.0-resolved.yaml.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. Issue trigger definition
        id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Issues
      GetIssueTriggerDefinitionForGivenId
    description: Complete reference of the GetIssueTriggerDefinitionForGivenId
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-issue-trigger-definition-for-given-id
notes:
  - SDK Method used are
    issues.Issues.get_issue_trigger_definition_for_given_id,
  - Paths used are
    get /dna/intent/api/v1/systemIssueDefinitions/{id},
"""

EXAMPLES = r"""
---
- name: Get System Issue Definitions Id by id
  cisco.dnac.system_issue_definitions_id_info:
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
        "displayName": "string",
        "description": "string",
        "priority": "string",
        "defaultPriority": "string",
        "deviceType": "string",
        "issueEnabled": true,
        "profileId": "string",
        "definitionStatus": "string",
        "categoryName": "string",
        "synchronizeToHealthThreshold": true,
        "thresholdValue": 0,
        "lastModified": "string"
      },
      "version": "string"
    }
"""
