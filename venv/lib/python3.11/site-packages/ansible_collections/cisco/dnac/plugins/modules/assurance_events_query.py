#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: assurance_events_query
short_description: Resource module for Assurance Events
  Query
description:
  - Manage operation create of the resource Assurance
    Events Query. - > Returns the list of events discovered
    by Catalyst Center, determined by the complex filters.
    Please refer to the 'API Support Documentation'
    section to understand which fields are supported.
    For detailed information about the usage of the
    API, please refer to the Open API specification
    document - https //github.com/cisco-en- programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    AssuranceEvents-1.0.0-resolved.yaml.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  attributes:
    description: Attributes.
    elements: str
    type: list
  deviceFamily:
    description: Device Family.
    elements: str
    type: list
  endTime:
    description: End Time.
    type: int
  filters:
    description: Assurance Events Query's filters.
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
  headers:
    description: Additional headers.
    type: dict
  page:
    description: Assurance Events Query's page.
    suboptions:
      limit:
        description: Limit.
        type: int
      offset:
        description: Offset.
        type: int
      sortBy:
        description: Assurance Events Query's sortBy.
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
      QueryAssuranceEventsWithFilters
    description: Complete reference of the QueryAssuranceEventsWithFilters
      API.
    link: https://developer.cisco.com/docs/dna-center/#!query-assurance-events-with-filters
notes:
  - SDK Method used are
    devices.Devices.query_assurance_events_with_filters,
  - Paths used are
    post /dna/data/api/v1/assuranceEvents/query,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.assurance_events_query:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    attributes:
      - string
    deviceFamily:
      - string
    endTime: 0
    filters:
      - key: string
        operator: string
        value: string
    headers: '{{my_headers | from_json}}'
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
          "oldRadioChannelWidth": "string",
          "clientMac": "string",
          "switchNumber": "string",
          "assocRssi": 0,
          "affectedClients": [
            "string"
          ],
          "isPrivateMac": true,
          "frequency": "string",
          "apRole": "string",
          "replacingDeviceSerialNumber": "string",
          "messageType": "string",
          "failureCategory": "string",
          "apSwitchName": "string",
          "apSwitchId": "string",
          "radioChannelUtilization": "string",
          "mnemonic": "string",
          "radioChannelSlot": 0,
          "details": "string",
          "id": "string",
          "lastApDisconnectReason": "string",
          "networkDeviceName": "string",
          "identifier": "string",
          "reasonDescription": "string",
          "vlanId": "string",
          "udnId": "string",
          "auditSessionId": "string",
          "apMac": "string",
          "deviceFamily": "string",
          "radioNoise": "string",
          "wlcName": "string",
          "apRadioOperationState": "string",
          "name": "string",
          "failureIpAddress": "string",
          "newRadioChannelList": "string",
          "duid": "string",
          "roamType": "string",
          "candidateAPs": [
            {
              "apId": "string",
              "apName": "string",
              "apMac": "string",
              "bssid": "string",
              "rssi": 0
            }
          ],
          "replacedDeviceSerialNumber": "string",
          "oldRadioChannelList": "string",
          "ssid": "string",
          "subReasonDescription": "string",
          "wirelessClientEventEndTime": 0,
          "ipv4": "string",
          "wlcId": "string",
          "ipv6": "string",
          "missingResponseAPs": [
            {
              "apId": "string",
              "apName": "string",
              "apMac": "string",
              "bssid": "string",
              "type": "string",
              "frameType": "string"
            }
          ],
          "timestamp": 0,
          "severity": 0,
          "currentRadioPowerLevel": 0,
          "newRadioChannelWidth": "string",
          "assocSnr": 0,
          "authServerIp": "string",
          "childEvents": [
            {
              "id": "string",
              "name": "string",
              "timestamp": 0,
              "wirelessEventType": 0,
              "details": "string",
              "reasonCode": "string",
              "reasonDescription": "string",
              "subReasonCode": "string",
              "subReasonDescription": "string",
              "resultStatus": "string",
              "failureCategory": "string"
            }
          ],
          "connectedInterfaceName": "string",
          "dhcpServerIp": "string",
          "managementIpAddress": "string",
          "previousRadioPowerLevel": 0,
          "resultStatus": "string",
          "radioInterference": "string",
          "networkDeviceId": "string",
          "siteHierarchy": "string",
          "eventStatus": "string",
          "wirelessClientEventStartTime": 0,
          "siteHierarchyId": "string",
          "udnName": "string",
          "facility": "string",
          "lastApResetType": "string",
          "invalidIeAPs": [
            {
              "apId": "string",
              "apName": "string",
              "apMac": "string",
              "bssid": "string",
              "type": "string",
              "frameType": "string",
              "ies": "string"
            }
          ],
          "username": "string"
        }
      ],
      "version": "string",
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
      }
    }
"""
