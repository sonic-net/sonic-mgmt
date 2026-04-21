#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: assurance_issues_update
short_description: Resource module for Assurance Issues
  Update
description:
  - Manage operation create of the resource Assurance
    Issues Update. - > Updates selected fields in the
    given issue. Currently the only field that can be
    updated is 'notes' field. After this API returns
    success response, it may take few seconds for the
    issue details to be updated if the system is heavily
    loaded. Please use `GET /dna/data/api/v1/assuranceIssues/{id}`
    API to fetch the details of a particular issue and
    verify `updatedTime`. For detailed information about
    the usage of the API, please refer to the Open API
    specification document - https //github.com/cisco-en-programmability/catalyst-center-api-
    specs/blob/main/Assurance/CE_Cat_Center_Org-IssuesLifecycle-1.0.0-resolved.yaml.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description: Id path parameter. The issue Uuid.
    type: str
  notes:
    description: Notes.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Issues
      UpdateTheGivenIssueByUpdatingSelectedFields
    description: Complete reference of the UpdateTheGivenIssueByUpdatingSelectedFields
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-the-given-issue-by-updating-selected-fields
notes:
  - SDK Method used are
    issues.Issues.update_the_given_issue_by_updating_selected_fields,
  - Paths used are
    post /dna/intent/api/v1/assuranceIssues/{id}/update,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.assurance_issues_update:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: '{{my_headers | from_json}}'
    id: string
    notes: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "issueId": "string",
        "name": "string",
        "description": "string",
        "summary": "string",
        "priority": "string",
        "severity": "string",
        "deviceType": "string",
        "category": "string",
        "entityType": "string",
        "entityId": "string",
        "firstOccurredTime": 0,
        "mostRecentOccurredTime": 0,
        "status": "string",
        "isGlobal": true,
        "updatedBy": "string",
        "updatedTime": 0,
        "notes": "string",
        "siteId": "string",
        "siteHierarchyId": "string",
        "siteName": "string",
        "siteHierarchy": "string",
        "suggestedActions": [
          {
            "message": "string"
          }
        ],
        "additionalAttributes": [
          {
            "key": "string",
            "value": "string"
          }
        ]
      },
      "version": "string"
    }
"""
