#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: interfaces_id_trend_analytics
short_description: Resource module for Interfaces Id
  Trend Analytics
description:
  - Manage operation create of the resource Interfaces
    Id Trend Analytics. - > The Trend analytcis data
    for the interface, identified by its instanceUuid,
    in the specified time range. The data is grouped
    based on the trend time Interval, other input parameters
    like attributes and aggregate attributes. The default
    time interval range is 3 hours when start and endTime
    is not provided.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  aggregateAttributes:
    description: Interfaces Id Trend Analytics's aggregateAttributes.
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
    description: Interfaces Id Trend Analytics's filters.
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
        type: str
    type: list
  id:
    description: Id path parameter. The interface instance
      Uuid.
    type: str
  startTime:
    description: Start Time.
    type: int
  timestampOrder:
    description: Timestamp Order.
    type: str
  trendIntervalInMinutes:
    description: Trend Interval In Minutes.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      TheTrendAnalytcisDataForTheInterfacesInTheSpecifiedTimeRange
    description: Complete reference of the TheTrendAnalytcisDataForTheInterfacesInTheSpecifiedTimeRange
      API.
    link: https://developer.cisco.com/docs/dna-center/#!the-trend-analytcis-data-for-the-interfaces-in-the-specified-time-range
notes:
  - SDK Method used are
    devices.Devices.the_trend_analytcis_data_for_the_interfaces_in_the_specified_time_range,
  - Paths used are
    post /dna/data/api/v1/interfaces/{id}/trendAnalytics,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.interfaces_id_trend_analytics:
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
        value: string
    id: string
    startTime: 0
    timestampOrder: string
    trendIntervalInMinutes: 0
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
              "value": "string"
            }
          ],
          "aggregateAttributes": [
            {
              "name": "string"
            }
          ]
        }
      ],
      "timestampOrder": "string"
    }
"""
