#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: license_device_registration
short_description: Resource module for License Device
  Registration
description:
  - Manage operation update of the resource License
    Device Registration.
  - Register devices in CSSM Cisco Smart Software Manager
    .
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  device_uuids:
    description: Comma separated device ids.
    elements: str
    type: list
  virtual_account_name:
    description: Virtual_account_name path parameter.
      Name of virtual account.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Licenses
      DeviceRegistration
    description: Complete reference of the DeviceRegistration
      API.
    link: https://developer.cisco.com/docs/dna-center/#!device-registration
notes:
  - SDK Method used are
    licenses.Licenses.device_registration,
  - Paths used are
    put /dna/intent/api/v1/licenses/smartAccount/virtualAccount/{virtual_account_name}/register,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.license_device_registration:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    device_uuids:
      - string
    virtual_account_name: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "string",
        "url": "string"
      }
    }
"""
