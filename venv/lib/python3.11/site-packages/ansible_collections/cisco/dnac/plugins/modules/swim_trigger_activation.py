#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: swim_trigger_activation
short_description: Resource module for Swim Trigger
  Activation
description:
  - Manage operation create of the resource Swim Trigger
    Activation.
  - Activates a software image on a given device. Software
    image must be present in the device flash.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  payload:
    description: Swim Trigger Activation's payload.
    elements: dict
    suboptions:
      activateLowerImageVersion:
        description: ActivateLowerImageVersion flag.
        type: bool
      deviceUpgradeMode:
        description: Swim Trigger Activation's deviceUpgradeMode.
        type: str
      deviceUuid:
        description: Swim Trigger Activation's deviceUuid.
        type: str
      distributeIfNeeded:
        description: DistributeIfNeeded flag.
        type: bool
      imageUuidList:
        description: Swim Trigger Activation's imageUuidList.
        elements: str
        type: list
      smuImageUuidList:
        description: Swim Trigger Activation's smuImageUuidList.
        elements: str
        type: list
    type: list
  scheduleValidate:
    description: ScheduleValidate query parameter. ScheduleValidate,
      validates data before schedule (Optional).
    type: bool
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) TriggerSoftwareImageActivation
    description: Complete reference of the TriggerSoftwareImageActivation
      API.
    link: https://developer.cisco.com/docs/dna-center/#!trigger-software-image-activation
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.trigger_software_image_activation,
  - Paths used are
    post /dna/intent/api/v1/image/activation/device,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.swim_trigger_activation:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: '{{my_headers | from_json}}'
    payload:
      - activateLowerImageVersion: true
        deviceUpgradeMode: string
        deviceUuid: string
        distributeIfNeeded: true
        imageUuidList:
          - string
        smuImageUuidList:
          - string
    scheduleValidate: true
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
