#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: assurance_issues_ignore
short_description: Resource module for Assurance Issues
  Ignore
description:
  - Manage operation create of the resource Assurance
    Issues Ignore. - > Ignores the given list of issues.
    The response contains the list of issues which were
    successfully ignored as well as the issues which
    are failed to ignore. After this API returns success
    response, it may take few seconds for the issue
    status to be updated if the system is heavily loaded.
    Please use `GET /dna/data/api/v1/assuranceIssues/{id}`
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
  ignoreHours:
    description: Ignore Hours.
    type: int
  issueIds:
    description: Issue Ids.
    elements: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Issues
      IgnoreTheGivenListOfIssues
    description: Complete reference of the IgnoreTheGivenListOfIssues
      API.
    link: https://developer.cisco.com/docs/dna-center/#!ignore-the-given-list-of-issues
notes:
  - SDK Method used are
    issues.Issues.ignore_the_given_list_of_issues,
  - Paths used are
    post /dna/intent/api/v1/assuranceIssues/ignore,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.assurance_issues_ignore:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: '{{my_headers | from_json}}'
    ignoreHours: 0
    issueIds:
      - string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "successfulIssueIds": [
          "string"
        ],
        "failureIssueIds": [
          "string"
        ]
      },
      "version": "string"
    }
"""
