#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: interface_operation_create
short_description: Resource module for Interface Operation
  Create
description:
  - Manage operation create of the resource Interface
    Operation Create. - > Clear mac-address on an individual
    port. In request body, operation needs to be specified
    as 'ClearMacAddress'. In the future more possible
    operations will be added to this API.
version_added: '6.0.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  deploymentMode:
    description: DeploymentMode query parameter. Preview/Deploy
      'Preview' means the configuration is not pushed
      to the device. 'Deploy' makes the configuration
      pushed to the device.
    type: str
  interfaceUuid:
    description: InterfaceUuid path parameter. Interface
      Id.
    type: str
  operation:
    description: Operation needs to be specified as
      'ClearMacAddress'.
    type: str
  payload:
    description: Payload is not applicable.
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      ClearMacAddressTable
    description: Complete reference of the ClearMacAddressTable
      API.
    link: https://developer.cisco.com/docs/dna-center/#!clear-mac-address-table
notes:
  - SDK Method used are
    devices.Devices.clear_mac_address_table,
  - Paths used are
    post /dna/intent/api/v1/interface/{interfaceUuid}/operation,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.interface_operation_create:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    deploymentMode: string
    interfaceUuid: string
    operation: string
    payload: {}
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
      },
      "version": "string"
    }
"""
