#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: license_setting
short_description: Resource module for License Setting
description:
  - Manage operation update of the resource License
    Setting. - > Update license setting - Configure
    default smart account id and/or virtual account
    id for auto registration of devices for smart license
    flow. Virtual account should be part of default
    smart account. Default smart account id cannot be
    set to 'null'. Auto registration of devices for
    smart license flow is applicable only for direct
    or on-prem SSM connection mode.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  autoRegistrationVirtualAccountId:
    description: Virtual account id.
    type: str
  defaultSmartAccountId:
    description: Default smart account id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Licenses
      UpdateLicenseSetting
    description: Complete reference of the UpdateLicenseSetting
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-license-setting
notes:
  - SDK Method used are
    licenses.Licenses.update_license_setting,
  - Paths used are
    put /dna/intent/api/v1/licenseSetting,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.license_setting:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    autoRegistrationVirtualAccountId: string
    defaultSmartAccountId: string
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
