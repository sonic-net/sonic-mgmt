#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: custom_issue_definitions
short_description: Resource module for Custom Issue
  Definitions
description:
  - Manage operations create, update and delete of the
    resource Custom Issue Definitions. - > Create a
    new custom issue definition using the provided input
    request data. The unique identifier for this issue
    definition is id. Please note that the issue names
    cannot be duplicated. The definition is based on
    the syslog. For detailed information about the usage
    of the API, please refer to the Open API specification
    document - https //github.com/cisco-en-programmability/catalyst-center-api-
    specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceUserDefinedIssueAPIs-1.0.0-resolved.yaml.
    - > Deletes an existing custom issue definition
    based on the Id. Only the Global profile issue has
    the access to delete the issue definition, so no
    profile id is required. For detailed information
    about the usage of the API, please refer to the
    Open API specification document - https //github.com/cisco-en-
    programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    AssuranceUserDefinedIssueAPIs-1.0.0-resolved.yaml.
    - > Updates an existing custom issue definition
    based on the provided Id. For detailed information
    about the usage of the API, please refer to the
    Open API specification document - https //github.com/cisco-en-
    programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    AssuranceUserDefinedIssueAPIs-1.0.0-resolved.yaml.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  description:
    description: Description.
    type: str
  headers:
    description: Additional headers.
    type: dict
  id:
    description: Id path parameter. The custom issue
      definition Identifier.
    type: str
  isEnabled:
    description: Is Enabled.
    type: bool
  isNotificationEnabled:
    description: Is Notification Enabled.
    type: bool
  name:
    description: Name.
    type: str
  priority:
    description: Priority.
    type: str
  rules:
    description: Custom Issue Definitions's rules.
    elements: dict
    suboptions:
      durationInMinutes:
        description: Duration In Minutes.
        type: int
      facility:
        description: Facility.
        type: str
      mnemonic:
        description: Mnemonic.
        type: str
      occurrences:
        description: Occurrences.
        type: int
      pattern:
        description: Pattern.
        type: str
      severity:
        description: Severity.
        type: int
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Issues
      CreatesANewUserDefinedIssueDefinitions
    description: Complete reference of the CreatesANewUserDefinedIssueDefinitions
      API.
    link: https://developer.cisco.com/docs/dna-center/#!creates-a-new-user-defined-issue-definitions
  - name: Cisco DNA Center documentation for Issues
      DeletesAnExistingCustomIssueDefinition
    description: Complete reference of the DeletesAnExistingCustomIssueDefinition
      API.
    link: https://developer.cisco.com/docs/dna-center/#!deletes-an-existing-custom-issue-definition
  - name: Cisco DNA Center documentation for Issues
      UpdatesAnExistingCustomIssueDefinitionBasedOnTheProvidedId
    description: Complete reference of the UpdatesAnExistingCustomIssueDefinitionBasedOnTheProvidedId
      API.
    link: https://developer.cisco.com/docs/dna-center/#!updates-an-existing-custom-issue-definition-based-on-the-provided-id
notes:
  - SDK Method used are
    issues.Issues.creates_a_new_user_defined_issue_definitions,
    issues.Issues.deletes_an_existing_custom_issue_definition,
    issues.Issues.updates_an_existing_custom_issue_definition_based_on_the_provided_id,
  - Paths used are
    post /dna/intent/api/v1/customIssueDefinitions,
    delete /dna/intent/api/v1/customIssueDefinitions/{id},
    put /dna/intent/api/v1/customIssueDefinitions/{id},
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.custom_issue_definitions:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    description: string
    headers: '{{my_headers | from_json}}'
    isEnabled: true
    isNotificationEnabled: true
    name: string
    priority: string
    rules:
      - durationInMinutes: 0
        facility: string
        mnemonic: string
        occurrences: 0
        pattern: string
        severity: 0
- name: Update by id
  cisco.dnac.custom_issue_definitions:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    description: string
    id: string
    isEnabled: true
    isNotificationEnabled: true
    name: string
    priority: string
    rules:
      - durationInMinutes: 0
        facility: string
        mnemonic: string
        occurrences: 0
        pattern: string
        severity: 0
- name: Delete by id
  cisco.dnac.custom_issue_definitions:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    id: string
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
        "profileId": "string",
        "triggerId": "string",
        "rules": [
          {
            "type": "string",
            "severity": 0,
            "facility": "string",
            "mnemonic": "string",
            "pattern": "string",
            "occurrences": 0,
            "durationInMinutes": 0
          }
        ],
        "isEnabled": true,
        "priority": "string",
        "isDeletable": true,
        "isNotificationEnabled": true,
        "createdTime": 0,
        "lastUpdatedTime": 0
      }
    }
"""
