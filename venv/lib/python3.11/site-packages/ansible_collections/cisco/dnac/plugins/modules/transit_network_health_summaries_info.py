#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: transit_network_health_summaries_info
short_description: Information module for Transit Network
  Health Summaries
description:
  - Get all Transit Network Health Summaries.
  - Get a paginated list of Transit Networks with health
    summary.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
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
      - SortBy query parameter. A field within the response
        to sort by.
    type: str
  order:
    description:
      - Order query parameter. The sort order of the
        field ascending or descending.
    type: str
  id:
    description:
      - >
        Id query parameter. The list of transit entity
        ids. (Ex "1551156a-bc97-3c63-aeda-8a6d3765b5b9")
        Examples id=1551156a-bc97-3c63-aeda-8a6d3765b5b9
        (single entity uuid requested) id=1551156a-bc97-3c63-aeda-8a6d3765b5b9&id=4aa20652-237c-4625-b2b4-fd7e82b6a81e
        (multiple entity uuids with '&' separator).
    type: str
  attribute:
    description:
      - Attribute query parameter. The interested fields
        in the request. For valid attributes, verify
        the documentation.
    type: str
  view:
    description:
      - >
        View query parameter. The specific summary view
        being requested. This is an optional parameter
        which can be passed to get one or more of the
        specific health data summaries associated with
        sites.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA ReadListOfTransitNetworksWithTheirHealthSummary
    description: Complete reference of the ReadListOfTransitNetworksWithTheirHealthSummary
      API.
    link: https://developer.cisco.com/docs/dna-center/#!read-list-of-transit-networks-with-their-health-summary
notes:
  - SDK Method used are
    sda.Sda.read_list_of_transit_networks_with_their_health_summary,
  - Paths used are
    get /dna/data/api/v1/transitNetworkHealthSummaries,
"""

EXAMPLES = r"""
---
- name: Get all Transit Network Health Summaries
  cisco.dnac.transit_network_health_summaries_info:
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
    limit: 0
    offset: 0
    sortBy: string
    order: string
    id: string
    attribute: string
    view: string
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
          "name": "string",
          "controlPlaneCount": 0,
          "transitType": [
            "string"
          ],
          "networkProtocol": "string",
          "fabricSitesCount": 0,
          "goodHealthPercentage": 0,
          "goodHealthDeviceCount": 0,
          "totalHealthDeviceCount": 0,
          "poorHealthDeviceCount": 0,
          "fairHealthDeviceCount": 0,
          "transitControlPlaneHealthPercentage": 0,
          "transitControlPlaneTotalDeviceCount": 0,
          "transitControlPlaneGoodHealthDeviceCount": 0,
          "transitControlPlanePoorHealthDeviceCount": 0,
          "transitControlPlaneFairHealthDeviceCount": 0,
          "transitServicesHealthPercentage": 0,
          "transitServicesTotalDeviceCount": 0,
          "transitServicesGoodHealthDeviceCount": 0,
          "transitServicesPoorHealthDeviceCount": 0,
          "transitServicesFairHealthDeviceCount": 0,
          "pubsubTransitHealthPercentage": 0,
          "pubsubTransitTotalDeviceCount": 0,
          "pubsubTransitGoodHealthDeviceCount": 0,
          "pubsubTransitPoorHealthDeviceCount": 0,
          "pubsubTransitFairHealthDeviceCount": 0,
          "lispTransitHealthPercentage": 0,
          "lispTransitTotalDeviceCount": 0,
          "lispTransitGoodHealthDeviceCount": 0,
          "lispTransitPoorHealthDeviceCount": 0,
          "lispTransitFairHealthDeviceCount": 0,
          "internetAvailTransitHealthPercentage": 0,
          "internetAvailTransitTotalDeviceCount": 0,
          "internetAvailTransitGoodHealthDeviceCount": 0,
          "internetAvailTransitPoorHealthDeviceCount": 0,
          "internetAvailTransitFairHealthDeviceCount": 0,
          "bgpTcpHealthPercentage": 0,
          "bgpTcpTotalDeviceCount": 0,
          "bgpTcpGoodHealthDeviceCount": 0,
          "bgpTcpPoorHealthDeviceCount": 0,
          "bgpTcpFairHealthDeviceCount": 0,
          "siteHierarchy": "string",
          "siteHierarchyId": "string"
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
