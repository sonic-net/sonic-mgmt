#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: qos_device_interface_info_count_info
short_description: Information module for Qos Device
  Interface Info Count
description:
  - Get all Qos Device Interface Info Count.
  - Get the number of all existing qos device interface
    infos group by network device id.
version_added: '4.0.0'
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
  - name: Cisco DNA Center documentation for Application
      Policy GetQosDeviceInterfaceInfoCount
    description: Complete reference of the GetQosDeviceInterfaceInfoCount
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-qos-device-interface-info-count
notes:
  - SDK Method used are
    application_policy.ApplicationPolicy.get_qos_device_interface_info_count,
  - Paths used are
    get /dna/intent/api/v1/qos-device-interface-info-count,
"""

EXAMPLES = r"""
---
- name: Get all Qos Device Interface Info Count
  cisco.dnac.qos_device_interface_info_count_info:
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
      "response": 0,
      "version": "string"
    }
"""
