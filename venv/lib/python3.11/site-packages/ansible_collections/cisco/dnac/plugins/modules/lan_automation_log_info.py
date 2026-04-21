#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: lan_automation_log_info
short_description: Information module for Lan Automation
  Log
description:
  - Get all Lan Automation Log.
  - Get Lan Automation Log by id.
  - Invoke this API to get the LAN Automation session
    logs based on the given LAN Automation session id.
  - Invoke this API to get the LAN Automation session
    logs.
version_added: '6.0.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  offset:
    description:
      - Offset query parameter. Starting index of the
        LAN Automation session. Minimum value is 1.
    type: int
  limit:
    description:
      - Limit query parameter. Number of LAN Automation
        sessions to be retrieved. Limit value can range
        between 1 to 10.
    type: int
  id:
    description:
      - Id path parameter. LAN Automation session identifier.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for LAN Automation
      LANAutomationLog
    description: Complete reference of the LANAutomationLog
      API.
    link: https://developer.cisco.com/docs/dna-center/#!l-an-automation-log
  - name: Cisco DNA Center documentation for LAN Automation
      LANAutomationLogById
    description: Complete reference of the LANAutomationLogById
      API.
    link: https://developer.cisco.com/docs/dna-center/#!l-an-automation-log-by-id
notes:
  - SDK Method used are
    lan_automation.LanAutomation.lan_automation_log,
    lan_automation.LanAutomation.lan_automation_log_by_id,
  - Paths used are
    get /dna/intent/api/v1/lan-automation/log,
    get /dna/intent/api/v1/lan-automation/log/{id},
"""

EXAMPLES = r"""
---
- name: Get all Lan Automation Log
  cisco.dnac.lan_automation_log_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    offset: 0
    limit: 0
  register: result
- name: Get Lan Automation Log by id
  cisco.dnac.lan_automation_log_info:
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
      "response": [
        {
          "nwOrchId": "string",
          "entry": [
            {
              "logLevel": "string",
              "timeStamp": "string",
              "record": "string",
              "deviceId": "string"
            }
          ]
        }
      ],
      "version": "string"
    }
"""
