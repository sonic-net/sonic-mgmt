#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: client_detail_info
short_description: Information module for Client Detail
description:
  - Get all Client Detail.
  - Returns detailed Client information retrieved by
    Mac Address for any given point of time.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  macAddress:
    description:
      - MacAddress query parameter. MAC Address of the
        client.
    type: str
  timestamp:
    description:
      - Timestamp query parameter. Epoch time(in milliseconds)
        when the Client health data is required.
    type: float
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Clients
      GetClientDetail
    description: Complete reference of the GetClientDetail
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-client-detail
notes:
  - SDK Method used are
    clients.Clients.get_client_detail,
  - Paths used are
    get /dna/intent/api/v1/client-detail,
"""

EXAMPLES = r"""
---
- name: Get all Client Detail
  cisco.dnac.client_detail_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    macAddress: string
    timestamp: 0
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "detail": {
        "id": "string",
        "connectionStatus": "string",
        "tracked": "string",
        "hostType": "string",
        "userId": "string",
        "duid": "string",
        "identifier": "string",
        "hostName": "string",
        "hostOs": "string",
        "hostVersion": "string",
        "subType": "string",
        "firmwareVersion": "string",
        "deviceVendor": "string",
        "deviceForm": "string",
        "salesCode": "string",
        "countryCode": "string",
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
          "string"
        ],
        "authType": "string",
        "vlanId": 0,
        "l3VirtualNetwork": "string",
        "l2VirtualNetwork": "string",
        "vnid": 0,
        "upnId": "string",
        "upnName": "string",
        "ssid": "string",
        "frequency": "string",
        "channel": "string",
        "apGroup": "string",
        "sgt": "string",
        "location": "string",
        "clientConnection": "string",
        "connectedDevice": [
          {
            "type": "string",
            "name": "string",
            "mac": "string",
            "id": "string",
            "ip address": "string",
            "mgmtIp": "string",
            "band": "string",
            "mode": "string"
          }
        ],
        "issueCount": 0,
        "rssi": "string",
        "rssiThreshold": "string",
        "rssiIsInclude": "string",
        "avgRssi": "string",
        "snr": "string",
        "snrThreshold": "string",
        "snrIsInclude": "string",
        "avgSnr": "string",
        "dataRate": "string",
        "txBytes": "string",
        "rxBytes": "string",
        "dnsResponse": "string",
        "dnsRequest": "string",
        "onboarding": {
          "averageRunDuration": "string",
          "maxRunDuration": "string",
          "averageAssocDuration": "string",
          "maxAssocDuration": "string",
          "averageAuthDuration": "string",
          "maxAuthDuration": "string",
          "averageDhcpDuration": "string",
          "maxDhcpDuration": "string",
          "aaaServerIp": "string",
          "dhcpServerIp": "string",
          "authDoneTime": 0,
          "assocDoneTime": 0,
          "dhcpDoneTime": 0,
          "assocRootcauseList": [
            "string"
          ],
          "aaaRootcauseList": [
            "string"
          ],
          "dhcpRootcauseList": [
            "string"
          ],
          "otherRootcauseList": [
            "string"
          ],
          "latestRootCauseList": [
            "string"
          ]
        },
        "clientType": "string",
        "onboardingTime": 0,
        "port": "string",
        "iosCapable": true,
        "usage": 0,
        "linkSpeed": 0,
        "linkThreshold": "string",
        "remoteEndDuplexMode": "string",
        "txLinkError": 0,
        "rxLinkError": 0,
        "txRate": 0,
        "rxRate": 0,
        "rxRetryPct": "string",
        "versionTime": 0,
        "dot11Protocol": "string",
        "slotId": 0,
        "dot11ProtocolCapability": "string",
        "privateMac": true,
        "dhcpServerIp": "string",
        "aaaServerIp": "string",
        "aaaServerTransaction": 0,
        "aaaServerFailedTransaction": 0,
        "aaaServerSuccessTransaction": 0,
        "aaaServerLatency": 0,
        "aaaServerMABLatency": 0,
        "aaaServerEAPLatency": 0,
        "dhcpServerTransaction": 0,
        "dhcpServerFailedTransaction": 0,
        "dhcpServerSuccessTransaction": 0,
        "dhcpServerLatency": 0,
        "dhcpServerDOLatency": 0,
        "dhcpServerRALatency": 0,
        "maxRoamingDuration": "string",
        "upnOwner": "string",
        "connectedUpn": "string",
        "connectedUpnOwner": "string",
        "connectedUpnId": "string",
        "isGuestUPNEndpoint": true,
        "wlcName": "string",
        "wlcUuid": "string",
        "sessionDuration": "string",
        "intelCapable": true,
        "hwModel": "string",
        "powerType": "string",
        "modelName": "string",
        "bridgeVMMode": "string",
        "dhcpNakIp": "string",
        "dhcpDeclineIp": "string",
        "portDescription": "string",
        "latencyVoice": 0,
        "latencyVideo": 0,
        "latencyBg": 0,
        "latencyBe": 0,
        "trustScore": "string",
        "trustDetails": "string"
      },
      "connectionInfo": {
        "hostType": "string",
        "nwDeviceName": "string",
        "nwDeviceMac": "string",
        "protocol": "string",
        "band": "string",
        "spatialStream": "string",
        "channel": "string",
        "channelWidth": "string",
        "wmm": "string",
        "uapsd": "string",
        "timestamp": 0
      },
      "topology": {
        "nodes": [
          {
            "role": "string",
            "name": "string",
            "id": "string",
            "description": "string",
            "deviceType": "string",
            "platformId": "string",
            "family": "string",
            "ip": "string",
            "ipv6": [
              "string"
            ],
            "softwareVersion": "string",
            "userId": "string",
            "nodeType": "string",
            "radioFrequency": "string",
            "clients": 0,
            "count": 0,
            "healthScore": 0,
            "level": 0,
            "fabricGroup": "string",
            "fabricRole": [
              "string"
            ],
            "connectedDevice": "string",
            "stackType": "string"
          }
        ],
        "links": [
          {
            "source": "string",
            "linkStatus": "string",
            "sourceLinkStatus": "string",
            "targetLinkStatus": "string",
            "label": [
              "string"
            ],
            "target": "string",
            "id": "string",
            "portUtilization": 0,
            "sourceInterfaceName": "string",
            "targetInterfaceName": "string",
            "sourceDuplexInfo": "string",
            "targetDuplexInfo": "string",
            "sourcePortMode": "string",
            "targetPortMode": "string",
            "sourceAdminStatus": "string",
            "targetAdminStatus": "string",
            "apRadioAdminStatus": "string",
            "apRadioOperStatus": "string",
            "sourcePortVLANInfo": "string",
            "targetPortVLANInfo": "string",
            "interfaceDetails": [
              {
                "clientMacAddress": "string",
                "connectedDeviceIntName": "string",
                "duplex": "string",
                "portMode": "string",
                "adminStatus": "string"
              }
            ]
          }
        ]
      }
    }
"""
