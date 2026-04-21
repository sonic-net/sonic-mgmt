#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: virtual_network_health_summaries_id_trend_analytics_info
short_description: Information module for Virtual Network
  Health Summaries Id Trend Analytics
description:
  - Get all Virtual Network Health Summaries Id Trend
    Analytics. - > Get health time series for a specific
    Virtual Network by providing the unique Virtual
    Network id in the url path. Layer 2 Virtual Networks
    are only included in health reporting for EVPN protocol
    deployments. The special Layer 3 VN called "INFRA_VN"
    is also not included for user access through Assurance
    virtualNetworkHealthSummaries APIS.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. Unique virtual network id.
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
  trendInterval:
    description:
      - >
        TrendInterval query parameter. The time window
        to aggregate the metrics. Interval can be 5
        minutes or 10 minutes or 1 hour or 1 day or
        7 days.
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
  order:
    description:
      - Order query parameter. The sort order of the
        field ascending or descending.
    type: str
  attribute:
    description:
      - Attribute query parameter. The interested fields
        in the request. For valid attributes, verify
        the documentation.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA TheTrendAnalyticsDataForAVirtualNetworkInTheSpecifiedTimeRange
    description: Complete reference of the TheTrendAnalyticsDataForAVirtualNetworkInTheSpecifiedTimeRange
      API.
    link: https://developer.cisco.com/docs/dna-center/#!the-trend-analytics-data-for-a-virtual-network-in-the-specified-time-range
notes:
  - SDK Method used are
    sda.Sda.the_trend_analytics_data_for_a_virtual_network_in_the_specified_time_range,
  - Paths used are
    get /dna/data/api/v1/virtualNetworkHealthSummaries/{id}/trendAnalytics,
"""

EXAMPLES = r"""
---
- name: Get all Virtual Network Health Summaries Id
    Trend Analytics
  cisco.dnac.virtual_network_health_summaries_id_trend_analytics_info:
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
    trendInterval: string
    limit: 0
    offset: 0
    order: string
    attribute: string
    id: string
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
          "timestamp": 0,
          "attributes": [
            {
              "name": "string",
              "value": 0
            }
          ]
        }
      ],
      "page": {
        "limit": 0,
        "offset": 0,
        "count": 0,
        "timeSortOrder": "string"
      },
      "version": "string"
    }
"""
