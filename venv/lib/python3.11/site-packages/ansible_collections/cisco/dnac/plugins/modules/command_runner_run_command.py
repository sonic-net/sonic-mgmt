#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: command_runner_run_command
short_description: Resource module for Command Runner
  Run Command
description:
  - Manage operation create of the resource Command
    Runner Run Command.
  - Submit request for read-only CLIs.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  commands:
    description: Commands to be executed.
    elements: str
    type: list
  description:
    description: Describe the details about the command
      request.
    type: str
  deviceUuids:
    description: Device Id of the device.
    elements: str
    type: list
  name:
    description: Name of the the request like getshowrun
      , deviceinterfacestatusCli.
    type: str
  timeout:
    description: The timeout value in unit of second.
      If no timeout provided wait till 300sec.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Command
      Runner RunReadOnlyCommandsOnDevicesToGetTheirRealTimeConfiguration
    description: Complete reference of the RunReadOnlyCommandsOnDevicesToGetTheirRealTimeConfiguration
      API.
    link: https://developer.cisco.com/docs/dna-center/#!run-read-only-commands-on-devices-to-get-their-real-time-configuration
notes:
  - SDK Method used are
    command_runner.CommandRunner.run_read_only_commands_on_devices,
  - Paths used are
    post /dna/intent/api/v1/network-device-poller/cli/read-request,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.command_runner_run_command:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    commands:
      - string
    description: string
    deviceUuids:
      - string
    name: string
    timeout: 0
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
