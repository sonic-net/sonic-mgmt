#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_replacements_id_info
short_description: Information module for Network Device
  Replacements Id
description:
  - Get Network Device Replacements Id by id. - > Fetches
    the status of the device replacement workflow for
    a given device replacement `id`. Invoke the API
    `/dna/intent/api/v1/networkDeviceReplacements` to
    `GET` the list of all device replacements and use
    the `id` field data as input to this API.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. Instance UUID of the device
        replacement.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Device
      Replacement RetrieveTheStatusOfDeviceReplacementWorkflowThatReplacesAFaultyDeviceWithAReplacementDevice
    description:
      Complete reference of the RetrieveTheStatusOfDeviceReplacementWorkflowThatReplacesAFaultyDeviceWithAReplacementDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieve-the-status-
          of-device-replacement-workflow-that-replaces-a-faulty-device-with-a-replacement-device
notes:
  - SDK Method used are
    device_replacement.DeviceReplacement.retrieve_the_status_of_device_replacement_workflow_that_replaces_a_faulty_device_with_a_replacement_device,
  - Paths used are
    get /dna/intent/api/v1/networkDeviceReplacements/{id},
"""

EXAMPLES = r"""
---
- name: Get Network Device Replacements Id by id
  cisco.dnac.network_device_replacements_id_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "creationTime": 0,
        "family": "string",
        "faultyDeviceId": "string",
        "faultyDeviceName": "string",
        "faultyDevicePlatform": "string",
        "faultyDeviceSerialNumber": "string",
        "id": "string",
        "neighborDeviceId": "string",
        "replacementDevicePlatform": "string",
        "replacementDeviceSerialNumber": "string",
        "replacementStatus": "string",
        "replacementTime": 0,
        "workflow": {
          "id": "string",
          "name": "string",
          "workflowStatus": "string",
          "startTime": 0,
          "endTime": 0,
          "steps": [
            {
              "name": "string",
              "status": "string",
              "statusMessage": "string",
              "startTime": 0,
              "endTime": 0
            }
          ]
        }
      },
      "version": "string"
    }
"""
