#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: license_virtual_account_change
short_description: Resource module for License Virtual
  Account Change
description:
  - Manage operation create of the resource License
    Virtual Account Change.
  - Transfer devices from one virtual account to another
    within same smart account.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  device_uuids:
    description: Comma separated device ids.
    elements: str
    type: list
  smart_account_id:
    description: Smart_account_id path parameter. Id
      of smart account.
    type: str
  virtual_account_name:
    description: Virtual_account_name path parameter.
      Name of target virtual account.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Licenses
      ChangeVirtualAccount
    description: Complete reference of the ChangeVirtualAccount
      API.
    link: https://developer.cisco.com/docs/dna-center/#!change-virtual-account
notes:
  - SDK Method used are
    licenses.Licenses.change_virtual_account,
  - Paths used are
    post /dna/intent/api/v1/licenses/smartAccount/{smart_account_id}/virtualAccount/{virtual_account_name}/device/transfer,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.license_virtual_account_change:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    device_uuids:
      - string
    smart_account_id: string
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
