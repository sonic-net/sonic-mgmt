#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_applications_info
short_description: Information module for Network Applications
description:
  - Get all Network Applications. - > Retrieves the
    list of network applications along with experience
    and health metrics. If startTime and endTime are
    not provided, the API defaults to the last 24 hours.
    `siteId` is mandatory. `siteId` must be a site UUID
    of a building. For detailed information about the
    usage of the API, please refer to the Open API specification
    document - https //github.com/cisco-en-programmability/catalyst-center-api-
    specs/blob/main/Assurance/CE_Cat_Center_Org-NetworkApplications-1.0.0-resolved.yaml.
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
    type: int
  offset:
    description:
      - >
        Offset query parameter. Specifies the starting
        point within all records returned by the API.
        It's one based offset. The starting value is
        1.
    type: int
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
  siteId:
    description:
      - >
        SiteId query parameter. The site UUID without
        the top level hierarchy. `siteId` is mandatory.
        `siteId` must be a site UUID of a building.
        (Ex."buildingUuid") Examples `siteId=buildingUuid`
        (single siteId requested) `siteId=buildingUuid1&siteId=buildingUuid2`
        (multiple siteId requested).
    type: str
  ssid:
    description:
      - >
        Ssid query parameter. In the context of a network
        application, SSID refers to the name of the
        wireless network to which the client connects.
        Examples `ssid=Alpha` (single ssid requested)
        `ssid=Alpha&ssid=Guest` (multiple ssid requested).
    type: str
  applicationName:
    description:
      - >
        ApplicationName query parameter. Name of the
        application for which the experience data is
        intended. Examples `applicationName=webex` (single
        applicationName requested) `applicationName=webex&applicationName=teams`
        (multiple applicationName requested).
    type: str
  businessRelevance:
    description:
      - >
        BusinessRelevance query parameter. The application
        can be chosen to be categorized as business-relevant,
        irrelevant, or default (neutral). By doing so,
        the assurance application prioritizes the monitoring
        and analysis of business-relevant data, ensuring
        critical insights are captured. Applications
        marked as irrelevant or default are selectively
        excluded from certain data sets, streamlining
        focus on what's most important for business
        outcomes.
    type: str
  attribute:
    description:
      - >
        Attribute query parameter. List of attributes
        related to resource that can be requested to
        only be part of the response along with the
        required attributes. Supported attributes are
        applicationName, siteId, exporterIpAddress,
        exporterNetworkDeviceId, healthScore, businessRelevance,
        usage, throughput, packetLossPercent, networkLatency,
        applicationServerLatency, clientNetworkLatency,
        serverNetworkLatency, trafficClass, jitter,
        ssid Examples `attribute=healthScore` (single
        attribute requested) `attribute=healthScore&attribute=ssid&attribute=jitter`
        (multiple attribute requested).
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Applications
      RetrievesTheListOfNetworkApplicationsAlongWithExperienceAndHealthMetrics
    description: Complete reference of the RetrievesTheListOfNetworkApplicationsAlongWithExperienceAndHealthMetrics
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-list-of-network-applications-along-with-experience-and-health-metrics
notes:
  - SDK Method used are
    applications.Applications.retrieves_the_list_of_network_applications_along_with_experience_and_health_metrics,
  - Paths used are
    get /dna/data/api/v1/networkApplications,
"""

EXAMPLES = r"""
---
- name: Get all Network Applications
  cisco.dnac.network_applications_info:
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
    siteId: string
    ssid: string
    applicationName: string
    businessRelevance: string
    attribute: string
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
          "applicationName": "string",
          "businessRelevance": "string",
          "siteId": "string",
          "exporterIpAddress": "string",
          "exporterNetworkDeviceId": "string",
          "healthScore": 0,
          "usage": 0,
          "throughput": 0,
          "packetLossPercent": 0,
          "networkLatency": 0,
          "applicationServerLatency": 0,
          "clientNetworkLatency": 0,
          "serverNetworkLatency": 0,
          "trafficClass": "string",
          "jitter": 0,
          "ssid": "string"
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
