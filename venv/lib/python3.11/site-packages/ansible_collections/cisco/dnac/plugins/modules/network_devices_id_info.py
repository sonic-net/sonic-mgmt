#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_devices_id_info
short_description: Information module for Network Devices
  Id
description:
  - Get Network Devices Id by id. - > API to fetch the
    details of network device using the `id`. Use the
    `/dna/intent/api/v1/networkDevices/query` API for
    advanced filtering. The API supports views to fetch
    only the required fields. Refer features for more
    details.
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
      - Id path parameter. Unique identifier for the
        network device.
    type: str
  views:
    description:
      - >
        Views query parameter. The specific views being
        requested. This is an optional parameter which
        can be passed to get one or more of the network
        device data. If this is not provided, then it
        will default to BASIC views. If multiple views
        are provided, the response will contain the
        union of the views. Available values BASIC,
        RESYNC, USER_DEFINED_FIELDS.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      GetDetailsOfASingleNetworkDevice
    description: Complete reference of the GetDetailsOfASingleNetworkDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-details-of-a-single-network-device
notes:
  - SDK Method used are
    devices.Devices.get_details_of_a_single_network_device,
  - Paths used are
    get /dna/intent/api/v1/networkDevices/{id},
"""

EXAMPLES = r"""
---
- name: Get Network Devices Id by id
  cisco.dnac.network_devices_id_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    views: string
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
      "response": {
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
      },
      "version": "string"
    }
"""
