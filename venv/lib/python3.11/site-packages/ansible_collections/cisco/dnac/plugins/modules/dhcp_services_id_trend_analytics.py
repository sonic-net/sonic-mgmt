#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: dhcp_services_id_trend_analytics
short_description: Resource module for Dhcp Services
  Id Trend Analytics
description:
  - Manage operation create of the resource Dhcp Services
    Id Trend Analytics. - > Gets the trend analytics
    data related to a particular DHCP Service matching
    the id. For detailed information about the usage
    of the API, please refer to the Open API specification
    document - https //github.com/cisco-en- programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    DHCPServices-1.0.0-resolved.yaml.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  aggregateAttributes:
    description: Dhcp Services Id Trend Analytics's
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
    description: Dhcp Services Id Trend Analytics's
      filters.
    elements: dict
    suboptions:
      filters:
        description: Filters.
        elements: str
        type: list
      key:
        description: Key.
        type: str
      logicalOperator:
        description: Logical Operator.
        type: str
      operator:
        description: Operator.
        type: str
      value:
        description: Value.
        type: dict
    type: list
  groupBy:
    description: Group By.
    elements: str
    type: list
  headers:
    description: Additional headers.
    type: dict
  id:
    description: Id path parameter. Unique id of the
      DHCP Service. It is the combination of DHCP Server
      IP (`serverIp`) and Device UUID (`deviceId`) separated
      by underscore (`_`). Example If `serverIp` is
      `10.76.81.33` and `deviceId` is `6bef213c-19ca-4170-8375-b694e251101c`,
      then the `id` would be `10.76.81.33_6bef213c-19ca-4170-8375-b694e251101c`.
    type: str
  page:
    description: Dhcp Services Id Trend Analytics's
      page.
    suboptions:
      limit:
        description: Limit.
        type: int
      offset:
        description: Offset.
        type: int
      timestampOrder:
        description: Timestamp Order.
        type: str
    type: dict
  startTime:
    description: Start Time.
    type: int
  trendInterval:
    description: Trend Interval.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      GetTrendAnalyticsDataForAGivenDHCPServiceMatchingTheIdOfTheService
    description: Complete reference of the GetTrendAnalyticsDataForAGivenDHCPServiceMatchingTheIdOfTheService
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-trend-analytics-data-for-a-given-dhcp-service-matching-the-id-of-the-service
notes:
  - SDK Method used are
    devices.Devices.get_trend_analytics_data_for_a_given_d_h_c_p_service_matching_the_id_of_the_service,
  - Paths used are
    post /dna/data/api/v1/dhcpServices/{id}/trendAnalytics,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.dhcp_services_id_trend_analytics:
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
      - filters:
          - string
        key: string
        logicalOperator: string
        operator: string
        value: {}
    groupBy:
      - string
    headers: '{{my_headers | from_json}}'
    id: string
    page:
      limit: 0
      offset: 0
      timestampOrder: string
    startTime: 0
    trendInterval: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "version": "string",
      "response": [
        {
          "timestamp": 0,
          "groups": [
            {
              "id": "string",
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
            }
          ],
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
        }
      ],
      "page": {
        "limit": 0,
        "offset": 0,
        "count": 0,
        "timestampOrder": "string"
      }
    }
"""
