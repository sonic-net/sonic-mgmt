#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: device_replacement
short_description: Resource module for Device Replacement
description:
  - Manage operations create and update of the resource
    Device Replacement.
  - Marks device for replacement.
  - UnMarks device for replacement.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  payload:
    description: Device Replacement's payload.
    elements: dict
    suboptions:
      creationTime:
        description: Date and time of marking the device
          for replacement.
        type: int
      family:
        description: Faulty device family.
        type: str
      faultyDeviceId:
        description: Unique identifier of the faulty
          device.
        type: str
      faultyDeviceName:
        description: Faulty device name.
        type: str
      faultyDevicePlatform:
        description: Faulty device platform.
        type: str
      faultyDeviceSerialNumber:
        description: Faulty device serial number.
        type: str
      id:
        description: Unique identifier of the device
          replacement resource.
        type: str
      neighbourDeviceId:
        description: Unique identifier of the neighbor
          device to create the DHCP server.
        type: str
      networkReadinessTaskId:
        description: Unique identifier of network readiness
          task.
        type: str
      replacementDevicePlatform:
        description: Replacement device platform.
        type: str
      replacementDeviceSerialNumber:
        description: Replacement device serial number.
        type: str
      replacementStatus:
        description: Device replacement status. Use
          NON-FAULTY to unmark the device for replacement.
        type: str
      replacementTime:
        description: Date and time of device replacement.
        type: int
      workflowId:
        description: Unique identifier of the device
          replacement workflow.
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Device
      Replacement MarkDeviceForReplacement
    description: Complete reference of the MarkDeviceForReplacement
      API.
    link: https://developer.cisco.com/docs/dna-center/#!mark-device-for-replacement
  - name: Cisco DNA Center documentation for Device
      Replacement UnMarkDeviceForReplacement
    description: Complete reference of the UnMarkDeviceForReplacement
      API.
    link: https://developer.cisco.com/docs/dna-center/#!un-mark-device-for-replacement
notes:
  - SDK Method used are
    device_replacement.DeviceReplacement.mark_device_for_replacement,
    device_replacement.DeviceReplacement.unmark_device_for_replacement,
  - Paths used are
    post /dna/intent/api/v1/device-replacement,
    put /dna/intent/api/v1/device-replacement,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.device_replacement:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - creationTime: 0
        family: string
        faultyDeviceId: string
        faultyDeviceName: string
        faultyDevicePlatform: string
        faultyDeviceSerialNumber: string
        id: string
        neighbourDeviceId: string
        networkReadinessTaskId: string
        replacementDevicePlatform: string
        replacementDeviceSerialNumber: string
        replacementStatus: string
        replacementTime: 0
        workflowId: string
- name: Create
  cisco.dnac.device_replacement:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - creationTime: 0
        family: string
        faultyDeviceId: string
        faultyDeviceName: string
        faultyDevicePlatform: string
        faultyDeviceSerialNumber: string
        id: string
        neighbourDeviceId: string
        networkReadinessTaskId: string
        replacementDevicePlatform: string
        replacementDeviceSerialNumber: string
        replacementStatus: string
        replacementTime: 0
        workflowId: string
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
