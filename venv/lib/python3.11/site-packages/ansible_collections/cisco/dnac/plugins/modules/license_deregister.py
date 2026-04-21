#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: license_deregister
short_description: Resource module for License Deregister
description:
  - Manage operation create of the resource License
    Deregister.
  - Deregisters the system with Cisco Smart Software
    Manager CSSM .
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options: {}
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Licenses
      SmartLicensingDeregistration
    description: Complete reference of the SmartLicensingDeregistration
      API.
    link: https://developer.cisco.com/docs/dna-center/#!smart-licensing-deregistration
notes:
  - SDK Method used are
    licenses.Licenses.smart_licensing_deregistration,
  - Paths used are
    post /dna/system/api/v1/license/deregister,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.license_deregister:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
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
