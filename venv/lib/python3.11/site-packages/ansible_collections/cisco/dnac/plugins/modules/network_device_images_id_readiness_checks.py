#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_images_id_readiness_checks
short_description: Resource module for Network Device
  Images Id Readiness Checks
description:
  - Manage operation create of the resource Network
    Device Images Id Readiness Checks. - > Triggers
    an on-demand network device update readiness check,
    where system-defined pre-checks will be performed.
    Upon task completion, the task API response's `resultLocation`
    attribute will contain the URL for fetching the
    validation result.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. Network device identifier.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) TriggerUpdateReadinessForNetworkDevice
    description: Complete reference of the TriggerUpdateReadinessForNetworkDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!trigger-update-readiness-for-network-device
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.trigger_update_readiness_for_network_device,
  - Paths used are
    post /dna/intent/api/v1/networkDeviceImages/{id}/readinessChecks,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.network_device_images_id_readiness_checks:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
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
