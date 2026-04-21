#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_config_write_memory
short_description: Resource module for Network Device
  Config Write Memory
description:
  - Manage operation create of the resource Network
    Device Config Write Memory.
  - This operation would commit device running configuration
    to startup by issuing "write memory" to device.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  deviceId:
    description: UUID of the device.
    elements: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Configuration
      Archive CommitDeviceConfiguration
    description: Complete reference of the CommitDeviceConfiguration
      API.
    link: https://developer.cisco.com/docs/dna-center/#!commit-device-configuration
notes:
  - SDK Method used are
    configuration_archive.ConfigurationArchive.commit_device_configuration,
  - Paths used are
    post /dna/intent/api/v1/network-device-config/write-memory,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.network_device_config_write_memory:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    deviceId:
      - string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "version": "string",
      "response": {
        "url": "string",
        "taskId": "string"
      }
    }
"""
