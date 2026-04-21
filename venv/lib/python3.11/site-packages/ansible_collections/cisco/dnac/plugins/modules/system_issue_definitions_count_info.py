#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: system_issue_definitions_count_info
short_description: Information module for System Issue
  Definitions Count
description:
  - Get all System Issue Definitions Count. - > Get
    the count of system defined issue definitions based
    on provided filters. Supported filters are id, name,
    profileId and definition enable status. For detailed
    information about the usage of the API, please refer
    to the Open API specification document - https //github.com/cisco-en-programmability/catalyst-center-api-
    specs/blob/main/Assurance/CE_Cat_Center_Org-issueAndHealthDefinitions-1.0.0-resolved.yaml.
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
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Issues
      GetTheCountOfSystemDefinedIssueDefinitionsBasedOnProvidedFilters
    description: Complete reference of the GetTheCountOfSystemDefinedIssueDefinitionsBasedOnProvidedFilters
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-the-count-of-system-defined-issue-definitions-based-on-provided-filters
notes:
  - SDK Method used are
    issues.Issues.get_the_count_of_system_defined_issue_definitions_based_on_provided_filters,
  - Paths used are
    get /dna/intent/api/v1/systemIssueDefinitions/count,
"""

EXAMPLES = r"""
---
- name: Get all System Issue Definitions Count
  cisco.dnac.system_issue_definitions_count_info:
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
        "count": 0
      },
      "version": "string"
    }
"""
