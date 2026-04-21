#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_user_defined_field
short_description: Resource module for Network Device
  User Defined Field
description:
  - Manage operations create, update and delete of the
    resource Network Device User Defined Field.
  - Creates a new global User Defined Field, which can
    be assigned to devices.
  - Deletes an existing Global User-Defined-Field using
    it's id.
  - Updates an existing global User Defined Field, using
    it's id.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  description:
    description: Description of UDF.
    type: str
  id:
    description: Id path parameter. UDF id.
    type: str
  name:
    description: Name of UDF.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      CreateUserDefinedField
    description: Complete reference of the CreateUserDefinedField
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-user-defined-field
  - name: Cisco DNA Center documentation for Devices
      DeleteUserDefinedField
    description: Complete reference of the DeleteUserDefinedField
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-user-defined-field
  - name: Cisco DNA Center documentation for Devices
      UpdateUserDefinedField
    description: Complete reference of the UpdateUserDefinedField
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-user-defined-field
notes:
  - SDK Method used are
    devices.Devices.create_user_defined_field,
    devices.Devices.delete_user_defined_field,
    devices.Devices.update_user_defined_field,
  - Paths used are
    post /dna/intent/api/v1/network-device/user-defined-field,
    delete /dna/intent/api/v1/network-device/user-defined-field/{id},
    put /dna/intent/api/v1/network-device/user-defined-field/{id},
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.network_device_user_defined_field:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    description: string
    name: string
- name: Update by id
  cisco.dnac.network_device_user_defined_field:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    description: string
    id: string
    name: string
- name: Delete by id
  cisco.dnac.network_device_user_defined_field:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    id: string
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
