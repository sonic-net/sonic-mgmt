#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_applications_summary_analytics
short_description: Resource module for Network Applications
  Summary Analytics
description:
  - Manage operation create of the resource Network
    Applications Summary Analytics. - > Retrieves summary
    analytics data related to network applications while
    applying complex filtering, aggregate functions,
    and grouping. This API facilitates obtaining consolidated
    insights into the performance and status of the
    network applications. If startTime and endTime are
    not provided, the API defaults to the last 24 hours.
    For detailed information about the usage of the
    API, please refer to the Open API specification
    document - https //github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    NetworkApplications-1.0.1-resolved.yaml.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  aggregateAttributes:
    description: Network Applications Summary Analytics's
      aggregateAttributes.
    elements: dict
    suboptions:
      function:
        description: Function.
        type: str
      name:
        description: Name.
        type: str
    type: list
  attributes:
    description: Attributes.
    elements: str
    type: list
  endTime:
    description: End Time.
    type: int
  filters:
    description: Network Applications Summary Analytics's
      filters.
    elements: dict
    suboptions:
      key:
        description: Key.
        type: str
      operator:
        description: Operator.
        type: str
      value:
        description: Value.
        type: int
    type: list
  headers:
    description: Additional headers.
    type: dict
  page:
    description: Network Applications Summary Analytics's
      page.
    suboptions:
      cursor:
        description: Cursor.
        type: str
      limit:
        description: Limit.
        type: int
      offset:
        description: Offset.
        type: int
      sortBy:
        description: Network Applications Summary Analytics's
          sortBy.
        elements: dict
        suboptions:
          function:
            description: Function.
            type: str
          name:
            description: Name.
            type: str
          order:
            description: Order.
            type: str
        type: list
    type: dict
  siteIds:
    description: Site Ids.
    elements: str
    type: list
  startTime:
    description: Start Time.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Applications
      RetrievesSummaryAnalyticsDataRelatedToNetworkApplicationsAlongWithHealthMetrics
    description: Complete reference of the RetrievesSummaryAnalyticsDataRelatedToNetworkApplicationsAlongWithHealthMetrics
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-summary-analytics-data-related-to-network-applications-along-with-health-metrics
notes:
  - SDK Method used are
    applications.Applications.retrieves_summary_analytics_data_related_to_network_applications_along_with_health_metrics,
  - Paths used are
    post /dna/data/api/v1/networkApplications/summaryAnalytics,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.network_applications_summary_analytics:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    aggregateAttributes:
      - function: string
        name: string
    attributes:
      - string
    endTime: 0
    filters:
      - key: string
        operator: string
        value: 0
    headers: '{{my_headers | from_json}}'
    page:
      cursor: string
      limit: 0
      offset: 0
      sortBy:
        - function: string
          name: string
          order: string
    siteIds:
      - string
    startTime: 0
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "attributes": [
          {
            "name": "string",
            "value": "string"
          }
        ],
        "aggregateAttributes": [
          {
            "name": "string",
            "function": "string",
            "value": 0
          }
        ]
      },
      "page": {
        "limit": 0,
        "offset": 0,
        "cursor": "string",
        "sortBy": [
          {
            "name": "string",
            "function": "string",
            "order": "string"
          }
        ]
      },
      "version": "string"
    }
"""
