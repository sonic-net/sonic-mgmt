#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: device_replacement_deploy
short_description: Resource module for Device Replacement
  Deploy
description:
  - Manage operation create of the resource Device Replacement
    Deploy. - > API to trigger RMA workflow that will
    replace faulty device with replacement device with
    same configuration and images.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  faultyDeviceSerialNumber:
    description: Faulty device serial number.
    type: str
  replacementDeviceSerialNumber:
    description: Replacement device serial number.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Device
      Replacement DeployDeviceReplacementWorkflow
    description: Complete reference of the DeployDeviceReplacementWorkflow
      API.
    link: https://developer.cisco.com/docs/dna-center/#!deploy-device-replacement-workflow
notes:
  - SDK Method used are
    device_replacement.DeviceReplacement.deploy_device_replacement_workflow,
  - Paths used are
    post /dna/intent/api/v1/device-replacement/workflow,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.device_replacement_deploy:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    faultyDeviceSerialNumber: string
    replacementDeviceSerialNumber: string
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
