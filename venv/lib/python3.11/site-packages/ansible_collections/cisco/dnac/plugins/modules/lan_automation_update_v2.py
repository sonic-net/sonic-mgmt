#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: lan_automation_update_v2
short_description: Resource module for Lan Automation
  Update V2
description:
  - Manage operation update of the resource Lan Automation
    Update V2. - > Invoke this API to stop LAN Automation
    and update device parameters such as Loopback0 IP
    address and/or hostname discovered in the current
    session.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. LAN Automation id
      can be obtained from /dna/intent/api/v1/lan-automation/status.
    type: str
  payload:
    description: Lan Automation Update V2's payload.
    elements: dict
    suboptions:
      deviceManagementIPAddress:
        description: Device Management IP Address.
        type: str
      newHostName:
        description: New hostname to be assigned to
          the device.
        type: str
      newLoopback0IPAddress:
        description: New Loopback0 IP Address from LAN
          pool of Device Discovery Site.
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for LAN Automation
      LANAutomationStopAndUpdateDevicesV2
    description: Complete reference of the LANAutomationStopAndUpdateDevicesV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!l-an-automation-stop-and-update-devices-v-2
notes:
  - SDK Method used are
    lan_automation.LanAutomation.lan_automation_stop_and_update_devices_v2,
  - Paths used are
    put /dna/intent/api/v2/lan-automation/{id},
"""

EXAMPLES = r"""
---
- name: Update by id
  cisco.dnac.lan_automation_update_v2:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    id: string
    payload:
      - deviceManagementIPAddress: string
        newHostName: string
        newLoopback0IPAddress: string
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
