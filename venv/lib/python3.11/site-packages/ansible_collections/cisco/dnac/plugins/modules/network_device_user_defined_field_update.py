#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_user_defined_field_update
short_description: Resource module for Network Device
  User Defined Field Update
description:
  - Manage operation update of the resource Network
    Device User Defined Field Update. - > Assigns an
    existing Global User-Defined-Field to a device.
    If the UDF is already assigned to the specific device,
    then it updates the device UDF value accordingly.
    Please note that the assigning UDF 'name' must be
    an existing global UDF. Otherwise error shall be
    shown.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  deviceId:
    description: DeviceId path parameter. UUID of device
      to which UDF has to be added.
    type: str
  payload:
    description: Network Device User Defined Field Update's
      payload.
    elements: dict
    suboptions:
      name:
        description: Name of the User Defined Field.
        type: str
      value:
        description: Value of the User Defined Field
          that will be assigned to the device.
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      AddUserDefinedFieldToDevice
    description: Complete reference of the AddUserDefinedFieldToDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-user-defined-field-to-device
notes:
  - SDK Method used are
    devices.Devices.add_user_defined_field_to_device,
  - Paths used are
    put /dna/intent/api/v1/network-device/{deviceId}/user-defined-field,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.network_device_user_defined_field_update:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    deviceId: string
    payload:
      - name: string
        value: string
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
