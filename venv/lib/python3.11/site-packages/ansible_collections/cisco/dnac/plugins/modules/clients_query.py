#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: clients_query
short_description: Resource module for Clients Query
description:
  - Manage operation create of the resource Clients
    Query. - > Retrieves the list of clients by applying
    complex filters while also supporting aggregate
    attributes. For detailed information about the usage
    of the API, please refer to the Open API specification
    document - https //github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    clients1-1.0.0-resolved.yaml.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  aggregateAttributes:
    description: Clients Query's aggregateAttributes.
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
    description: Clients Query's filters.
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
    description: Clients Query's page.
    suboptions:
      limit:
        description: Limit.
        type: int
      offset:
        description: Offset.
        type: int
      sortBy:
        description: Clients Query's sortBy.
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
  - name: Cisco DNA Center documentation for Clients
      RetrievesTheListOfClientsByApplyingComplexFiltersWhileAlsoSupportingAggregateAttributes
    description: Complete reference of the RetrievesTheListOfClientsByApplyingComplexFiltersWhileAlsoSupportingAggregateAttributes
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-list-of-clients-by-applying-complex-filters-while-also-supporting-aggregate-attributes
notes:
  - SDK Method used are
    clients.Clients.retrieves_the_list_of_clients_by_applying_complex_filters_while_also_supporting_aggregate_attributes,
  - Paths used are
    post /dna/data/api/v1/clients/query,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.clients_query:
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
          "macAddress": "string",
          "type": "string",
          "name": "string",
          "userId": "string",
          "username": "string",
          "ipv4Address": "string",
          "ipv6Addresses": [
            "string"
          ],
          "vendor": "string",
          "osType": "string",
          "osVersion": "string",
          "formFactor": "string",
          "siteHierarchy": "string",
          "siteHierarchyId": "string",
          "siteId": "string",
          "lastUpdatedTime": 0,
          "connectionStatus": "string",
          "tracked": "string",
          "isPrivateMacAddress": true,
          "health": {
            "overallScore": 0,
            "onboardingScore": 0,
            "connectedScore": 0,
            "linkErrorPercentageThreshold": 0,
            "isLinkErrorIncluded": true,
            "rssiThreshold": 0,
            "snrThreshold": 0,
            "isRssiIncluded": true,
            "isSnrIncluded": true
          },
          "traffic": {
            "txBytes": 0,
            "rxBytes": 0,
            "usage": 0,
            "rxPackets": 0,
            "txPackets": 0,
            "rxRate": 0,
            "txRate": 0,
            "rxLinkErrorPercentage": 0,
            "txLinkErrorPercentage": 0,
            "rxRetries": 0,
            "rxRetryPercentage": 0,
            "txDrops": 0,
            "txDropPercentage": 0,
            "dnsRequestCount": 0,
            "dnsResponseCount": 0
          },
          "connectedNetworkDevice": {
            "connectedNetworkDeviceId": "string",
            "connectedNetworkDeviceName": "string",
            "connectedNetworkDeviceManagementIp": "string",
            "connectedNetworkDeviceMac": "string",
            "connectedNetworkDeviceType": "string",
            "interfaceName": "string",
            "interfaceSpeed": 0,
            "duplexMode": "string"
          },
          "connection": {
            "vlanId": "string",
            "sessionDuration": 0,
            "vnId": "string",
            "l2Vn": "string",
            "l3Vn": "string",
            "securityGroupTag": "string",
            "linkSpeed": 0,
            "bridgeVMMode": "string",
            "band": "string",
            "ssid": "string",
            "authType": "string",
            "wlcName": "string",
            "wlcId": "string",
            "apMac": "string",
            "apEthernetMac": "string",
            "apMode": "string",
            "radioId": 0,
            "channel": "string",
            "channelWidth": "string",
            "protocol": "string",
            "protocolCapability": "string",
            "upnId": "string",
            "upnName": "string",
            "upnOwner": "string",
            "upnDuid": "string",
            "rssi": 0,
            "snr": 0,
            "dataRate": 0,
            "isIosAnalyticsCapable": true
          },
          "onboarding": {
            "avgRunDuration": 0,
            "maxRunDuration": 0,
            "avgAssocDuration": 0,
            "maxAssocDuration": 0,
            "avgAuthDuration": 0,
            "maxAuthDuration": 0,
            "avgDhcpDuration": 0,
            "maxDhcpDuration": 0,
            "maxRoamingDuration": 0,
            "aaaServerIp": "string",
            "dhcpServerIp": "string",
            "onboardingTime": 0,
            "authDoneTime": 0,
            "assocDoneTime": 0,
            "dhcpDoneTime": 0,
            "roamingTime": 0,
            "failedRoamingCount": 0,
            "successfulRoamingCount": 0,
            "totalRoamingAttempts": 0,
            "assocFailureReason": "string",
            "aaaFailureReason": "string",
            "dhcpFailureReason": "string",
            "otherFailureReason": "string",
            "latestFailureReason": "string"
          },
          "latency": {
            "video": 0,
            "voice": 0,
            "bestEffort": 0,
            "background": 0
          },
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
