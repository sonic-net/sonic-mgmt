#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_replacements_info
short_description: Information module for Network Device
  Replacements
description:
  - Get all Network Device Replacements. - > Retrieve
    the list of device replacements with replacement
    details. Filters can be applied based on faulty
    device name, faulty device platform, faulty device
    serial number, replacement device platform, replacement
    device serial number, device replacement status,
    device family.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  family:
    description:
      - Family query parameter. Faulty device family.
    type: str
  faultyDeviceName:
    description:
      - FaultyDeviceName query parameter. Faulty device
        name.
    type: str
  faultyDevicePlatform:
    description:
      - FaultyDevicePlatform query parameter. Faulty
        device platform.
    type: str
  faultyDeviceSerialNumber:
    description:
      - FaultyDeviceSerialNumber query parameter. Faulty
        device serial number.
    type: str
  replacementDevicePlatform:
    description:
      - ReplacementDevicePlatform query parameter. Replacement
        device platform.
    type: str
  replacementDeviceSerialNumber:
    description:
      - ReplacementDeviceSerialNumber query parameter.
        Replacement device serial number.
    type: str
  replacementStatus:
    description:
      - >
        ReplacementStatus query parameter. Device replacement
        status. Available values MARKED_FOR_REPLACEMENT,
        NETWORK_READINESS_REQUESTED, NETWORK_READINESS_FAILED,
        READY_FOR_REPLACEMENT, REPLACEMENT_SCHEDULED,
        REPLACEMENT_IN_PROGRESS, REPLACED, ERROR. Replacement
        status 'MARKED_FOR_REPLACEMENT' - The faulty
        device has been marked for replacement. 'NETWORK_READINESS_REQUESTED'
        - Initiated steps to shut down neighboring device
        interfaces and create a DHCP server on the uplink
        neighbor if the faulty device is part of a fabric
        setup. 'NETWORK_READINESS_FAILED' - Preparation
        of the network failed. Neighboring device interfaces
        were not shut down, and the DHCP server on the
        uplink neighbor was not created. 'READY_FOR_REPLACEMENT'
        - The network is prepared for the faulty device
        replacement. Neighboring device interfaces are
        shut down, and the DHCP server on the uplink
        neighbor is set up. 'REPLACEMENT_SCHEDULED'
        - Device replacement has been scheduled. 'REPLACEMENT_IN_PROGRESS'
        - Device replacement is currently in progress.
        'REPLACED' - Device replacement was successful.
        'ERROR' - Device replacement has failed.
    type: str
  offset:
    description:
      - Offset query parameter. The first record to
        show for this page; the first record is numbered
        1.
    type: int
  limit:
    description:
      - Limit query parameter. The number of records
        to show for this page. Maximum value can be
        500.
    type: int
  sortBy:
    description:
      - >
        SortBy query parameter. A property within the
        response to sort by. Available values id, creationTime,
        family, faultyDeviceId, fautyDeviceName, faultyDevicePlatform,
        faultyDeviceSerialNumber, replacementDevicePlatform,
        replacementDeviceSerialNumber, replacementTime.
    type: str
  sortOrder:
    description:
      - >
        SortOrder query parameter. Whether ascending
        or descending order should be used to sort the
        response. Available values ASC, DESC.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Device
      Replacement RetrieveTheStatusOfAllTheDeviceReplacementWorkflows
    description: Complete reference of the RetrieveTheStatusOfAllTheDeviceReplacementWorkflows
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieve-the-status-of-all-the-device-replacement-workflows
notes:
  - SDK Method used are
    device_replacement.DeviceReplacement.retrieve_the_status_of_all_the_device_replacement_workflows,
  - Paths used are
    get /dna/intent/api/v1/networkDeviceReplacements,
"""

EXAMPLES = r"""
---
- name: Get all Network Device Replacements
  cisco.dnac.network_device_replacements_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    family: string
    faultyDeviceName: string
    faultyDevicePlatform: string
    faultyDeviceSerialNumber: string
    replacementDevicePlatform: string
    replacementDeviceSerialNumber: string
    replacementStatus: string
    offset: 0
    limit: 0
    sortBy: string
    sortOrder: string
  register: result
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
          "creationTime": 0,
          "family": "string",
          "faultyDeviceId": "string",
          "faultyDeviceName": "string",
          "faultyDevicePlatform": "string",
          "faultyDeviceSerialNumber": "string",
          "id": "string",
          "neighborDeviceId": "string",
          "replacementDevicePlatform": "string",
          "replacementDeviceSerialNumber": "string",
          "replacementStatus": "string",
          "replacementTime": 0,
          "workflow": {
            "id": "string",
            "name": "string",
            "workflowStatus": "string",
            "startTime": 0,
            "endTime": 0,
            "steps": [
              {
                "name": "string",
                "status": "string",
                "statusMessage": "string",
                "startTime": 0,
                "endTime": 0
              }
            ]
          }
        }
      ],
      "version": "string"
    }
"""
