#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: client_enrichment_details_info
short_description: Information module for Client Enrichment
  Details
description:
  - Get all Client Enrichment Details. - > Enriches
    a given network End User context a network user-id
    or end user's device Mac Address with details about
    the user, the devices that the user is connected
    to and the assurance issues that the user is impacted
    by.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Clients
      GetClientEnrichmentDetails
    description: Complete reference of the GetClientEnrichmentDetails
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-client-enrichment-details
notes:
  - SDK Method used are
    clients.Clients.get_client_enrichment_details,
  - Paths used are
    get /dna/intent/api/v1/client-enrichment-details,
"""

EXAMPLES = r"""
---
- name: Get all Client Enrichment Details
  cisco.dnac.client_enrichment_details_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "userDetails": {
          "id": "string",
          "connectionStatus": "string",
          "hostType": "string",
          "userId": "string",
          "hostName": {},
          "hostOs": {},
          "hostVersion": {},
          "subType": {},
          "lastUpdated": 0,
          "healthScore": [
            {
              "healthType": "string",
              "reason": "string",
              "score": 0
            }
          ],
          "hostMac": "string",
          "hostIpV4": "string",
          "hostIpV6": [
            {}
          ],
          "authType": {},
          "vlanId": "string",
          "ssid": {},
          "location": {},
          "clientConnection": "string",
          "connectedDevice": [
            {}
          ],
          "issueCount": 0,
          "rssi": {},
          "snr": {},
          "dataRate": {},
          "port": {}
        },
        "connectedDevice": [
          {
            "deviceDetails": {
              "family": "string",
              "type": "string",
              "location": {},
              "errorCode": "string",
              "macAddress": "string",
              "role": "string",
              "apManagerInterfaceIp": "string",
              "associatedWlcIp": "string",
              "bootDateTime": {},
              "collectionStatus": "string",
              "interfaceCount": {},
              "lineCardCount": {},
              "lineCardId": {},
              "managementIpAddress": "string",
              "memorySize": "string",
              "platformId": "string",
              "reachabilityFailureReason": "string",
              "reachabilityStatus": "string",
              "snmpContact": "string",
              "snmpLocation": "string",
              "tunnelUdpPort": "string",
              "waasDeviceMode": {},
              "series": "string",
              "inventoryStatusDetail": "string",
              "collectionInterval": "string",
              "serialNumber": "string",
              "softwareVersion": "string",
              "roleSource": "string",
              "hostname": "string",
              "upTime": "string",
              "lastUpdateTime": 0,
              "errorDescription": {},
              "locationName": {},
              "tagCount": "string",
              "lastUpdated": "string",
              "instanceUuid": "string",
              "id": "string",
              "neighborTopology": [
                {
                  "nodes": [
                    {
                      "role": "string",
                      "name": "string",
                      "id": "string",
                      "description": "string",
                      "deviceType": {},
                      "platformId": {},
                      "family": {},
                      "ip": {},
                      "softwareVersion": {},
                      "userId": {},
                      "nodeType": {},
                      "radioFrequency": {},
                      "clients": 0,
                      "count": {},
                      "healthScore": {},
                      "level": 0,
                      "fabricGroup": {}
                    }
                  ],
                  "links": [
                    {
                      "source": "string",
                      "linkStatus": "string",
                      "label": [
                        {}
                      ],
                      "target": "string",
                      "id": {},
                      "portUtilization": {}
                    }
                  ]
                }
              ],
              "cisco360view": "string"
            }
          }
        ],
        "issueDetails": {
          "issue": [
            {
              "issueId": "string",
              "issueSource": "string",
              "issueCategory": "string",
              "issueName": "string",
              "issueDescription": "string",
              "issueEntity": "string",
              "issueEntityValue": "string",
              "issueSeverity": "string",
              "issuePriority": "string",
              "issueSummary": "string",
              "issueTimestamp": 0,
              "suggestedActions": [
                {
                  "message": "string",
                  "steps": [
                    {}
                  ]
                }
              ],
              "impactedHosts": [
                {
                  "hostType": "string",
                  "hostName": "string",
                  "hostOs": "string",
                  "ssid": "string",
                  "connectedInterface": "string",
                  "macAddress": "string",
                  "failedAttempts": 0,
                  "location": {
                    "siteId": "string",
                    "siteType": "string",
                    "area": "string",
                    "building": "string",
                    "floor": {},
                    "apsImpacted": [
                      {}
                    ]
                  },
                  "timestamp": 0
                }
              ]
            }
          ]
        }
      }
    ]
"""
