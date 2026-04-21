#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: intent_network_devices_query
short_description: Resource module for Intent Network
  Devices Query
description:
  - Manage operation create of the resource Intent Network
    Devices Query. - > Returns the list of network devices,
    determined by the filters. It is possible to filter
    the network devices based on various parameters,
    such as device type, device role, software version,
    etc. The API returns a paginated response based
    on 'limit' and 'offset' parameters, allowing up
    to 500 records per page. 'limit' specifies the number
    of records, and 'offset' sets the starting point
    using 1-based indexing. Use '/dna/intent/api/v1/networkDevices/query/count'
    API to get the total record count. For data sets
    over 500 records, make multiple calls, adjusting
    'limit' and 'offset' to retrieve all records incrementally.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  filter:
    description: Intent Network Devices Query's filter.
    suboptions:
      filters:
        description: Intent Network Devices Query's
          filters.
        elements: dict
        suboptions:
          key:
            description: The key to filter by.
            type: str
          operator:
            description: The operator to use for filtering
              the values.
            type: str
          value:
            description: Value to filter by. For `in`
              operator, the value should be a list of
              values.
            type: dict
        type: list
      logicalOperator:
        description: The logical operator to use for
          combining the filter criteria. If not provided,
          the default value is AND.
        type: str
    type: dict
  page:
    description: Intent Network Devices Query's page.
    suboptions:
      limit:
        description: The number of records to show for
          this page. Min 1, Max 500.
        type: int
      offset:
        description: The first record to show for this
          page; the first record is numbered 1.
        type: int
      sortBy:
        description: Intent Network Devices Query's
          sortBy.
        suboptions:
          name:
            description: The field to sort by. Default
              is hostname.
            type: str
          order:
            description: The order to sort by.
            type: str
        type: dict
    type: dict
  views:
    description: The specific views being requested.
      This is an optional parameter which can be passed
      to get one or more of the network device data.
      If this is not provided, then it will default
      to BASIC views. If multiple views are provided,
      the response will contain the union of the views.
    elements: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      QueryNetworkDevicesWithFilters
    description: Complete reference of the QueryNetworkDevicesWithFilters
      API.
    link: https://developer.cisco.com/docs/dna-center/#!query-network-devices-with-filters
notes:
  - SDK Method used are
    devices.Devices.query_network_devices_with_filters,
  - Paths used are
    post /dna/intent/api/v1/networkDevices/query,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.intent_network_devices_query:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    filter:
      filters:
        - key: string
          operator: string
          value: {}
      logicalOperator: string
    page:
      limit: 0
      offset: 0
      sortBy:
        name: string
        order: string
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
          "managementAddress": "string",
          "dnsResolvedManagementIpAddress": "string",
          "hostname": "string",
          "macAddress": "string",
          "serialNumbers": [
            "string"
          ],
          "type": "string",
          "family": "string",
          "series": "string",
          "status": "string",
          "platformIds": [
            "string"
          ],
          "softwareType": "string",
          "softwareVersion": "string",
          "vendor": "string",
          "stackDevice": true,
          "bootTime": 0,
          "role": "string",
          "roleSource": "string",
          "apEthernetMacAddress": "string",
          "apManagerInterfaceIpAddress": "string",
          "apWlcIpAddress": "string",
          "deviceSupportLevel": "string",
          "snmpLocation": "string",
          "snmpContact": "string",
          "reachabilityStatus": "string",
          "reachabilityFailureReason": "string",
          "managementState": "string",
          "lastSuccessfulResyncReasons": [
            "string"
          ],
          "resyncStartTime": 0,
          "resyncEndTime": 0,
          "resyncReasons": [
            "string"
          ],
          "resyncRequestedByApps": [
            "string"
          ],
          "pendingResyncRequestCount": 0,
          "pendingResyncRequestReasons": [
            "string"
          ],
          "resyncIntervalSource": "string",
          "resyncIntervalMinutes": 0,
          "errorCode": "string",
          "errorDescription": "string",
          "userDefinedFields": {}
        }
      ],
      "version": "string"
    }
"""
