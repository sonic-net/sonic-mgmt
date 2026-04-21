#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: license_setting_info
short_description: Information module for License Setting
description:
  - Get all License Setting. - > Retrieves license setting
    - Default smart account id and virtual account id
    for auto registration of devices for smart license
    flow. If default smart account is not configured,
    'defaultSmartAccountId' is 'null'. Similarly, if
    auto registration of devices for smart license flow
    is not enabled, 'autoRegistrationVirtualAccountId'
    is 'null'. For smart proxy connection mode, 'autoRegistrationVirtualAccountId'
    is always 'null'.
version_added: '6.15.0'
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
  - name: Cisco DNA Center documentation for Licenses
      RetrieveLicenseSetting
    description: Complete reference of the RetrieveLicenseSetting
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieve-license-setting
notes:
  - SDK Method used are
    licenses.Licenses.retrieve_license_setting,
  - Paths used are
    get /dna/intent/api/v1/licenseSetting,
"""

EXAMPLES = r"""
---
- name: Get all License Setting
  cisco.dnac.license_setting_info:
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
        "defaultSmartAccountId": "string",
        "autoRegistrationVirtualAccountId": "string"
      },
      "version": "string"
    }
"""
