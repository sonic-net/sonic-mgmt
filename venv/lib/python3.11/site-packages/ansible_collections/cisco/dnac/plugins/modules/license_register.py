#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: license_register
short_description: Resource module for License Register
description:
  - Manage operation create of the resource License
    Register.
  - Registers the system with Cisco Smart Software Manager
    CSSM .
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  smartAccountId:
    description: The ID of the Smart Account to which
      the system is registered.
    type: str
  virtualAccountId:
    description: The ID of the Virtual Account to which
      the system is registered.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Licenses
      SystemLicensingRegistration
    description: Complete reference of the SystemLicensingRegistration
      API.
    link: https://developer.cisco.com/docs/dna-center/#!system-licensing-registration
notes:
  - SDK Method used are
    licenses.Licenses.system_licensing_registration,
  - Paths used are
    post /dna/system/api/v1/license/register,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.license_register:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    smartAccountId: string
    virtualAccountId: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "url": "string"
      },
      "version": "string"
    }
"""
