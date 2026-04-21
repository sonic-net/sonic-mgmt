#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: thousand_eyes_test_results_count_info
short_description: Information module for Thousand Eyes
  Test Results Count
description:
  - Get all Thousand Eyes Test Results Count. - > Retrieves
    the total count of ThousandEyes test results for
    the given filters. If `startTime` and `endTime`
    are not provided, the API defaults to the last 24
    hours. For detailed information about the usage
    of the API, please refer to the Open API specification
    document - https //github.com/cisco-en-programmability/catalyst-
    center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-thousandEyesTestResults-1.0.0-resolved.yaml.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  siteId:
    description:
      - >
        SiteId query parameter. The site UUID without
        the top level hierarchy. `siteId` must be a
        site UUID of a building. The list of buildings
        can be fetched using API `GET /dna/intent/api/v1/sites?type=building`.
        Examples `siteId=buildingUuid` (single siteId
        requested) `siteId=buildingUuid1&siteId=buildingUuid2`
        (multiple siteId requested).
    type: str
  startTime:
    description:
      - >
        StartTime query parameter. Start time from which
        API queries the data set related to the resource.
        It must be specified in UNIX epochtime in milliseconds.
        Value is inclusive.
    type: float
  endTime:
    description:
      - >
        EndTime query parameter. End time to which API
        queries the data set related to the resource.
        It must be specified in UNIX epochtime in milliseconds.
        Value is inclusive.
    type: float
  testId:
    description:
      - >
        TestId query parameter. Unique identifier of
        the ThousandEyes test. Examples `testId=2043918`
        (filter for single testId) `testId=2043918&testId=129440`
        (filter for multiple testIds).
    type: str
  testName:
    description:
      - >
        TestName query parameter. Name of the ThousandEyes
        test. This supports `*` wildcard, and filtering
        is case-insensitve. Examples `testName=Cisco
        Webex` (exact match) `testName=Microsoft*` (starts
        with given string).
    type: str
  testType:
    description:
      - >
        TestType query parameter. Type of the ThousandEyes
        test. Please note that Catalyst Center supports
        only a subset of all possible ThousandEyes test
        types.
    type: str
  agentId:
    description:
      - >
        AgentId query parameter. Unique identifier of
        the ThousandEyes agent. Examples `agentId=199345`
        (filter for single agentId) `agentId=1993458&agentId=499387`
        (filter for multiple agentIds).
    type: str
  networkDeviceName:
    description:
      - >
        NetworkDeviceName query parameter. Name of the
        network device as per the inventory. This supports
        `*` wildcard, and filtering is case-insensitve.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Applications
      RetrievesTheTotalCountOfThousandEyesTestResults
    description: Complete reference of the RetrievesTheTotalCountOfThousandEyesTestResults
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-total-count-of-thousand-eyes-test-results
notes:
  - SDK Method used are
    applications.Applications.retrieves_the_total_count_of_thousand_eyes_test_results,
  - Paths used are
    get /dna/data/api/v1/thousandEyesTestResults/count,
"""

EXAMPLES = r"""
---
- name: Get all Thousand Eyes Test Results Count
  cisco.dnac.thousand_eyes_test_results_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    siteId: string
    startTime: 0
    endTime: 0
    testId: string
    testName: string
    testType: string
    agentId: string
    networkDeviceName: string
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
