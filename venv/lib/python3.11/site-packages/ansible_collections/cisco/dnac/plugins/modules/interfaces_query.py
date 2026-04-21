#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: interfaces_query
short_description: Resource module for Interfaces Query
description:
  - Manage operation create of the resource Interfaces
    Query. - > Gets the list of interfaces across the
    Network Devices based on the provided complex filters
    and aggregation functions.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  aggregateAttributes:
    description: Interfaces Query's aggregateAttributes.
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
    description: Interfaces Query's filters.
    elements: dict
    suboptions:
      filters:
        description: Interfaces Query's filters.
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
  page:
    description: Interfaces Query's page.
    suboptions:
      limit:
        description: Limit.
        type: int
      offset:
        description: Offset.
        type: int
      sortBy:
        description: Interfaces Query's sortBy.
        elements: dict
        suboptions:
          name:
            description: Name.
            type: str
          order:
            description: Order.
            type: str
        type: list
    type: dict
  startTime:
    description: Start Time.
    type: int
  views:
    description: Views.
    elements: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
          GetsTheListOfInterfacesAcrossTheNetworkDevicesBasedOnTheProvidedComplexFiltersAndAggregationFunctions
    description:
      >
      Complete reference of the GetsTheListOfInterfacesAcrossThe
      NetworkDevicesBasedOnTheProvidedComplexFiltersAndAggregationFunctions
      API.
    link:
      https://developer.cisco.com/docs/dna-center/#!gets-the-list-
      of-interfaces-across-the-network-devices-based-on-the-provided-complex-filters-and-aggregation-functions
notes:
  - SDK Method used are
    devices.Devices.gets_the_list_of_interfaces_across_the_network_devices_based_on_the_provided_complex_filters_and_aggregation_functions,
  - Paths used are
    post /dna/data/api/v1/interfaces/query,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.interfaces_query:
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
          - filters:
              - string
            key: string
            logicalOperator: string
            operator: string
            value: {}
        key: string
        logicalOperator: string
        operator: string
        value: {}
    page:
      limit: 0
      offset: 0
      sortBy:
        - name: string
          order: string
    startTime: 0
    views:
      - string
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
          "adminStatus": "string",
          "description": "string",
          "duplexConfig": "string",
          "duplexOper": "string",
          "interfaceIfIndex": 0,
          "interfaceType": "string",
          "ipv4Address": "string",
          "ipv6AddressList": [
            "string"
          ],
          "isL3Interface": true,
          "isWan": true,
          "macAddr": "string",
          "mediaType": "string",
          "name": "string",
          "operStatus": "string",
          "peerStackMember": 0,
          "peerStackPort": "string",
          "portChannelId": "string",
          "portMode": "string",
          "portType": "string",
          "rxDiscards": 0,
          "rxError": 0,
          "rxRate": 0,
          "rxUtilization": 0,
          "speed": "string",
          "stackPortType": "string",
          "timestamp": 0,
          "txDiscards": 0,
          "txError": 0,
          "txRate": 0,
          "txUtilization": 0,
          "vlanId": "string",
          "networkDeviceId": "string",
          "networkDeviceIpAddress": "string",
          "networkDeviceMacAddress": "string",
          "siteName": "string",
          "siteHierarchy": "string",
          "siteHierarchyId": "string",
          "aggregateAttributes": [
            {
              "name": "string",
              "values": [
                {
                  "key": "string",
                  "value": 0
                }
              ]
            }
          ]
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
