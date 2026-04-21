#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: security_advisories_results_network_devices_count_info
short_description: Information module for Security Advisories
  Results Network Devices Count
description:
  - Get all Security Advisories Results Network Devices
    Count.
  - Get count of security advisory network devices.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  networkDeviceId:
    description:
      - NetworkDeviceId query parameter. Id of the network
        device.
    type: str
  scanMode:
    description:
      - >
        ScanMode query parameter. Mode or the criteria
        using which the network device was scanned.
        Available values ESSENTIALS, ADVANTAGE, CX_CLOUD,
        NOT_AVAILABLE.
    type: str
  scanStatus:
    description:
      - >
        ScanStatus query parameter. Status of the scan
        on the network device. Available values NOT_SCANNED,
        IN_PROGRESS, SUCCESS, FAILED, FALL_BACK.
    type: str
  advisoryCount:
    description:
      - AdvisoryCount query parameter. Return network
        devices with advisoryCount greater than this
        advisoryCount.
    type: float
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Compliance
      GetCountOfSecurityAdvisoryNetworkDevices
    description: Complete reference of the GetCountOfSecurityAdvisoryNetworkDevices
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-count-of-security-advisory-network-devices
notes:
  - SDK Method used are
    compliance.Compliance.get_count_of_security_advisory_network_devices,
  - Paths used are
    get /dna/intent/api/v1/securityAdvisories/results/networkDevices/count,
"""

EXAMPLES = r"""
---
- name: Get all Security Advisories Results Network
    Devices Count
  cisco.dnac.security_advisories_results_network_devices_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    networkDeviceId: string
    scanMode: string
    scanStatus: string
    advisoryCount: 0
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "version": "string",
      "response": {
        "count": 0
      }
    }
"""
