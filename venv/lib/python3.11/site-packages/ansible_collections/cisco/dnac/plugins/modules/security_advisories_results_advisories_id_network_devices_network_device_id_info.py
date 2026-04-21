#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: security_advisories_results_advisories_id_network_devices_network_device_id_info
short_description: Information module for Security Advisories
  Results Advisories Id Network Devices Network Device
  Id
description:
  - Get Security Advisories Results Advisories Id Network
    Devices Network Device Id by id.
  - Get security advisory network device for the security
    advisory by network device id.
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
      - Id path parameter. Id of the security advisory.
    type: str
  networkDeviceId:
    description:
      - NetworkDeviceId path parameter. Id of the network
        device.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Compliance
      GetSecurityAdvisoryNetworkDeviceForTheSecurityAdvisoryByNetworkDeviceId
    description: Complete reference of the GetSecurityAdvisoryNetworkDeviceForTheSecurityAdvisoryByNetworkDeviceId
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-security-advisory-network-device-for-the-security-advisory-by-network-device-id
notes:
  - SDK Method used are
    compliance.Compliance.get_security_advisory_network_device_for_the_security_advisory_by_network_device_id,
  - Paths used are
    get /dna/intent/api/v1/securityAdvisories/results/advisories/{id}/networkDevices/{networkDeviceId},
"""

EXAMPLES = r"""
---
- name: Get Security Advisories Results Advisories Id
    Network Devices Network Device Id by id
  cisco.dnac.security_advisories_results_advisories_id_network_devices_network_device_id_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
    networkDeviceId: string
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
        "networkDeviceId": "string",
        "advisoryCount": 0,
        "scanMode": "string",
        "scanStatus": "string",
        "comments": "string",
        "lastScanTime": 0
      },
      "version": "string"
    }
"""
