#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: energy_network_devices_query
short_description: Resource module for Energy Network
  Devices Query
description:
  - Manage operation create of the resource Energy Network
    Devices Query. - > Retrieves a list of network devices
    along with their energy data for a specified time
    range, based on the filters provided in the request
    body. For detailed information about the usage of
    the API, please refer to the Open API specification
    document - https //github.com/cisco-en-programmability/catalyst-center-api-
    specs/blob/main/Assurance/CE_Cat_Center_Org-deviceEnergy_1.0-1.0.1-resolved.yaml.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  aggregateAttributes:
    description: Energy Network Devices Query's aggregateAttributes.
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
    description: Energy Network Devices Query's filters.
    elements: dict
    suboptions:
      filters:
        description: Energy Network Devices Query's
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
            elements: str
            type: list
        type: list
      logicalOperator:
        description: Logical Operator.
        type: str
    type: list
  headers:
    description: Additional headers.
    type: dict
  page:
    description: Energy Network Devices Query's page.
    suboptions:
      cursor:
        description: Cursor.
        type: str
      limit:
        description: Limit.
        type: int
      sortBy:
        description: Energy Network Devices Query's
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
      QueryDevicesEnergy
    description: Complete reference of the QueryDevicesEnergy
      API.
    link: https://developer.cisco.com/docs/dna-center/#!query-devices-energy
notes:
  - SDK Method used are
    devices.Devices.query_devices_energy,
  - Paths used are
    post /dna/data/api/v1/energy/networkDevices/query,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.energy_network_devices_query:
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
          - key: string
            operator: string
            value:
              - string
        logicalOperator: string
    headers: '{{my_headers | from_json}}'
    page:
      cursor: string
      limit: 0
      sortBy:
        - function: string
          name: string
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
          "deviceName": "string",
          "deviceCategory": "string",
          "deviceSubCategory": "string",
          "siteId": "string",
          "siteHierarchy": "string",
          "siteHierarchyId": "string",
          "energyConsumed": 0,
          "estimatedCost": 0,
          "estimatedEmission": 0,
          "carbonIntensity": 0,
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
        "cursor": "string",
        "count": 0,
        "sortBy": [
          {
            "name": "string",
            "order": "string",
            "function": "string"
          }
        ]
      },
      "version": "string"
    }
"""
