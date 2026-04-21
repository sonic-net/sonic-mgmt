#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: eox_status_device_info
short_description: Information module for Eox Status
  Device
description:
  - Get all Eox Status Device.
  - Get Eox Status Device by id.
  - Retrieves EoX details for a device.
  - Retrieves EoX status for all devices in the network.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  limit:
    description:
      - >
        Limit query parameter. The number of records
        to show for this page. Default is 500 if not
        specified. Maximum allowed limit is 500.
    type: int
  offset:
    description:
      - Offset query parameter. The first record to
        show for this page, the first record is numbered
        1.
    type: int
  deviceId:
    description:
      - DeviceId path parameter. Device instance UUID.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for EoX GetEoXDetailsPerDevice
    description: Complete reference of the GetEoXDetailsPerDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-eo-x-details-per-device
  - name: Cisco DNA Center documentation for EoX GetEoXStatusForAllDevices
    description: Complete reference of the GetEoXStatusForAllDevices
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-eo-x-status-for-all-devices
notes:
  - SDK Method used are
    eox.Eox.get_eox_details_per_device,
    eox.Eox.get_eox_status_for_all_devices,
  - Paths used are
    get /dna/intent/api/v1/eox-status/device,
    get /dna/intent/api/v1/eox-status/device/{deviceId},
"""

EXAMPLES = r"""
---
- name: Get all Eox Status Device
  cisco.dnac.eox_status_device_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    limit: 0
    offset: 0
  register: result
- name: Get Eox Status Device by id
  cisco.dnac.eox_status_device_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    deviceId: string
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
        "deviceId": "string",
        "alertCount": 0,
        "eoxDetails": [
          {
            "name": "string",
            "bulletinHeadline": "string",
            "bulletinName": "string",
            "bulletinNumber": "string",
            "bulletinURL": "string",
            "endOfHardwareNewServiceAttachmentDate": "string",
            "endOfHardwareServiceContractRenewalDate": "string",
            "endOfLastHardwareShipDate": "string",
            "endOfLifeExternalAnnouncementDate": "string",
            "endOfSignatureReleasesDate": "string",
            "endOfSoftwareVulnerabilityOrSecuritySupportDate": "string",
            "endOfSoftwareVulnerabilityOrSecuritySupportDateHw": "string",
            "endOfSaleDate": "string",
            "endOfLifeDate": "string",
            "lastDateOfSupport": "string",
            "endOfSoftwareMaintenanceReleasesDate": "string",
            "eoxAlertType": "string",
            "eoXPhysicalType": "string",
            "bulletinPID": "string"
          }
        ],
        "scanStatus": "string",
        "comments": [
          "string"
        ],
        "lastScanTime": 0
      },
      "version": "string"
    }
"""
