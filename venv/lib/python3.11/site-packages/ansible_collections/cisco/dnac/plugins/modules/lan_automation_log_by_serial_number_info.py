#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: lan_automation_log_by_serial_number_info
short_description: Information module for Lan Automation
  Log By Serial Number
description:
  - Get Lan Automation Log By Serial Number by id. -
    > Invoke this API to get the LAN Automation session
    logs for individual devices based on the given LAN
    Automation session id and device serial number.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. LAN Automation session identifier.
    type: str
  serialNumber:
    description:
      - SerialNumber path parameter. Device serial number.
    type: str
  logLevel:
    description:
      - >
        LogLevel query parameter. Supported levels are
        ERROR, INFO, WARNING, TRACE, CONFIG and ALL.
        Specifying ALL will display device specific
        logs with the exception of CONFIG logs. In order
        to view CONFIG logs along with the remaining
        logs, please leave the query parameter blank.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for LAN Automation
      LANAutomationLogsForIndividualDevices
    description: Complete reference of the LANAutomationLogsForIndividualDevices
      API.
    link: https://developer.cisco.com/docs/dna-center/#!l-an-automation-logs-for-individual-devices
notes:
  - SDK Method used are
    lan_automation.LanAutomation.lan_automation_logs_for_individual_devices,
  - Paths used are
    get /dna/intent/api/v1/lan-automation/log/{id}/{serialNumber},
"""

EXAMPLES = r"""
---
- name: Get Lan Automation Log By Serial Number by id
  cisco.dnac.lan_automation_log_by_serial_number_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    logLevel: string
    id: string
    serialNumber: string
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
          "logs": [
            {
              "logLevel": "string",
              "timeStamp": "string",
              "record": "string"
            }
          ],
          "serialNumber": "string"
        }
      ],
      "version": "string"
    }
"""
