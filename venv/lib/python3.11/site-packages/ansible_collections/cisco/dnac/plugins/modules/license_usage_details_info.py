#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: license_usage_details_info
short_description: Information module for License Usage
  Details
description:
  - Get License Usage Details by name.
  - Get count of purchased and in use Cisco DNA and
    Network licenses.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  smart_account_id:
    description:
      - Smart_account_id path parameter. Id of smart
        account.
    type: str
  virtual_account_name:
    description:
      - >
        Virtual_account_name path parameter. Name of
        virtual account. Putting "All" will give license
        term detail for all virtual accounts.
    type: str
  device_type:
    description:
      - Device_type query parameter. Type of device
        like router, switch, wireless or ise.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Licenses
      LicenseUsageDetails
    description: Complete reference of the LicenseUsageDetails
      API.
    link: https://developer.cisco.com/docs/dna-center/#!license-usage-details
notes:
  - SDK Method used are
    licenses.Licenses.license_usage_details,
  - Paths used are
    get /dna/intent/api/v1/licenses/usage/smartAccount/{smart_account_id}/virtualAccount/{virtual_account_name},
"""

EXAMPLES = r"""
---
- name: Get License Usage Details by name
  cisco.dnac.license_usage_details_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    device_type: string
    smart_account_id: string
    virtual_account_name: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "purchased_dna_license": {
        "total_license_count": 0,
        "license_count_by_type": [
          {
            "license_type": "string",
            "license_count": 0
          }
        ]
      },
      "purchased_network_license": {
        "total_license_count": 0,
        "license_count_by_type": [
          {
            "license_type": "string",
            "license_count": 0
          }
        ]
      },
      "used_dna_license": {
        "total_license_count": 0,
        "license_count_by_type": [
          {
            "license_type": "string",
            "license_count": 0
          }
        ]
      },
      "used_network_license": {
        "total_license_count": 0,
        "license_count_by_type": [
          {
            "license_type": "string",
            "license_count": 0
          }
        ]
      }
    }
"""
