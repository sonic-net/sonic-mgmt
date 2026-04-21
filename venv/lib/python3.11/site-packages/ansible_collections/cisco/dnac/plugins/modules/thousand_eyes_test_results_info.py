#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: thousand_eyes_test_results_info
short_description: Information module for Thousand Eyes
  Test Results
description:
  - Get all Thousand Eyes Test Results. - > Retrieves
    the list of ThousandEyes test results along with
    related metrics. If `startTime` and `endTime` are
    not provided, the API defaults to the last 24 hours.
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
  attribute:
    description:
      - >
        Attribute query parameter. List of attributes
        related to resource that can be requested to
        only be part of the response along with the
        required attributes. Examples `attribute=testName`
        (single attribute requested) `attribute=testId&attribute=testName&attribute=averageLatency`
        (multiple attributes requested). For valid attributes,
        verify the documentation.
    type: str
  limit:
    description:
      - Limit query parameter. Maximum number of records
        to return.
    type: float
  offset:
    description:
      - >
        Offset query parameter. Specifies the starting
        point within all records returned by the API.
        It's one based offset. The starting value is
        1.
    type: float
  sortBy:
    description:
      - SortBy query parameter. Attribute name by which
        the results should be sorted.
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
  - name: Cisco DNA Center documentation for Applications
      RetrievesTheListOfThousandEyesTestResultsAlongWithRelatedMetrics
    description: Complete reference of the RetrievesTheListOfThousandEyesTestResultsAlongWithRelatedMetrics
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-list-of-thousand-eyes-test-results-along-with-related-metrics
notes:
  - SDK Method used are
    applications.Applications.retrieves_the_list_of_thousand_eyes_test_results_along_with_related_metrics,
  - Paths used are
    get /dna/data/api/v1/thousandEyesTestResults,
"""

EXAMPLES = r"""
---
- name: Get all Thousand Eyes Test Results
  cisco.dnac.thousand_eyes_test_results_info:
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
    attribute: string
    limit: 0
    offset: 0
    sortBy: string
    order: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": [
        {
          "id": "string",
          "testId": "string",
          "testName": "string",
          "testType": "string",
          "agentId": "string",
          "agentName": "string",
          "networkDeviceName": "string",
          "networkDeviceType": "string",
          "siteId": "string",
          "siteName": "string",
          "testInterval": 0,
          "testTarget": "string",
          "sampleTime": 0,
          "averagePacketLoss": 0,
          "latestPacketLoss": 0,
          "maxPacketLoss": 0,
          "averageJitter": {},
          "latestJitter": {},
          "maxJitter": {},
          "averageLatency": 0,
          "latestLatency": 0,
          "maxLatency": 0,
          "averageResponseTime": 0,
          "latestResponseTime": 0,
          "maxResponseTime": 0,
          "averageMos": {},
          "latestMos": {},
          "minMos": {},
          "averagePdv": {},
          "latestPdv": {},
          "maxPdv": {},
          "totalAlerts": 0,
          "totalActiveAlerts": 0,
          "totalSamplingTests": 0,
          "totalFailureSamplingTests": 0,
          "totalErrorsSamplingTests": 0
        }
      ],
      "page": {
        "limit": 0,
        "offset": 0,
        "count": 0,
        "sortBy": [
          {
            "name": "string",
            "order": "string"
          }
        ]
      },
      "version": "string"
    }
"""
