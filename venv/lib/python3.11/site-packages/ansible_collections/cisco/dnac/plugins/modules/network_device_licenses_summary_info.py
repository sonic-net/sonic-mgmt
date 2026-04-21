#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_licenses_summary_info
short_description: Information module for Network Device
  Licenses Summary
description:
  - Get all Network Device Licenses Summary. - > Retrieves
    the summary of consumed network, DNA, and Cisco
    Networking Subscription CNS licenses, along with
    the counts of unregistered and out-of-compliance
    network devices, and expired and expiring network
    device licenses.
version_added: '6.18.0'
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
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) RetrievesSummaryOfNetworkDeviceLicenses
    description: Complete reference of the RetrievesSummaryOfNetworkDeviceLicenses
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-summary-of-network-device-licenses
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.retrieves_summary_of_network_device_licenses,
  - Paths used are
    get /dna/intent/api/v1/networkDeviceLicenses/summary,
"""

EXAMPLES = r"""
---
- name: Get all Network Device Licenses Summary
  cisco.dnac.network_device_licenses_summary_info:
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
  type: dict
  sample: >
    {
      "response": {
        "networkDeviceLicenseSummary": {
          "networkLicenseSummary": {
            "essentialCount": 0,
            "advantageCount": 0
          },
          "dnaLicenseSummary": {
            "essentialCount": 0,
            "advantageCount": 0
          },
          "cnsLicenseSummary": {
            "essentialCount": 0,
            "advantageCount": 0
          }
        },
        "unregisteredNetworkDeviceCount": 0,
        "outOfComplianceNetworkDeviceCount": 0,
        "expiredNetworkDeviceLicenseCount": 0,
        "expiringNetworkDeviceLicenseCount": 0
      },
      "version": "string"
    }
"""
