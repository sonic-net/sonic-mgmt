#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: system_issue_definitions_info
short_description: Information module for System Issue
  Definitions
description:
  - Get all System Issue Definitions. - > Get all system
    issue defintions. The supported filters are id,
    name, profileId and definition enable status. An
    issue trigger definition can be different across
    the profile and device type. So, `profileId` and
    `deviceType` in the query param is important and
    default is global profile and all device type. For
    detailed information about the usage of the API,
    please refer to the Open API specification document
    - https //github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    issueAndHealthDefinitions-1.0.0-resolved.yaml.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  deviceType:
    description:
      - >
        DeviceType query parameter. These are the device
        families/types supported for system issue definitions.
        If no input is made on device type, all device
        types are considered.
    type: str
  profileId:
    description:
      - >
        ProfileId query parameter. The profile identier
        to fetch the profile associated issue defintions.
        The default is `global`. Please refer Network
        design profiles documentation for more details.
    type: str
  id:
    description:
      - >
        Id query parameter. The definition identifier.
        Examples id=015d9cba-4f53-4087-8317-7e49e5ffef46
        (single entity id request) id=015d9cba-4f53-4087-8317-7e49e5ffef46&id=015d9cba-4f53-4087-8317-7e49e5ffef47
        (multiple ids in the query param).
    type: str
  name:
    description:
      - >
        Name query parameter. The list of system defined
        issue names. (Ex."BGP_Down") Examples name=BGP_Down
        (single entity uuid requested) name=BGP_Down&name=BGP_Flap
        (multiple issue names separated by & operator).
    type: str
  priority:
    description:
      - >
        Priority query parameter. Issue priority, possible
        values are P1, P2, P3, P4. `P1` A critical issue
        that needs immediate attention and can have
        a wide impact on network operations. `P2` A
        major issue that can potentially impact multiple
        devices or clients. `P3` A minor issue that
        has a localized or minimal impact. `P4` A warning
        issue that may not be an immediate problem but
        addressing it can optimize the network performance.
    type: str
  issueEnabled:
    description:
      - IssueEnabled query parameter. The enablement
        status of the issue definition, either true
        or false.
    type: bool
  attribute:
    description:
      - >
        Attribute query parameter. These are the attributes
        supported in system issue definitions response.
        By default, all properties are sent in response.
    type: str
  offset:
    description:
      - >
        Offset query parameter. Specifies the starting
        point within all records returned by the API.
        It's one based offset. The starting value is
        1.
    type: float
  limit:
    description:
      - Limit query parameter. Maximum number of records
        to return.
    type: float
  sortBy:
    description:
      - SortBy query parameter. A field within the response
        to sort by.
    type: str
  order:
    description:
      - Order query parameter. The sort order of the
        field ascending or descending.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Issues
      ReturnsAllIssueTriggerDefinitionsForGivenFilters
    description: Complete reference of the ReturnsAllIssueTriggerDefinitionsForGivenFilters
      API.
    link: https://developer.cisco.com/docs/dna-center/#!returns-all-issue-trigger-definitions-for-given-filters
notes:
  - SDK Method used are
    issues.Issues.returns_all_issue_trigger_definitions_for_given_filters,
  - Paths used are
    get /dna/intent/api/v1/systemIssueDefinitions,
"""

EXAMPLES = r"""
---
- name: Get all System Issue Definitions
  cisco.dnac.system_issue_definitions_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    deviceType: string
    profileId: string
    id: string
    name: string
    priority: string
    issueEnabled: true
    attribute: string
    offset: 0
    limit: 0
    sortBy: string
    order: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
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
      }
    ]
"""
