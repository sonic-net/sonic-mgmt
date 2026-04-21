#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: lan_automation_count_info
short_description: Information module for Lan Automation
  Count
description:
  - Get all Lan Automation Count.
  - Invoke this API to get the total count of LAN Automation
    sessions.
version_added: '6.0.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for LAN Automation
      LANAutomationSessionCount
    description: Complete reference of the LANAutomationSessionCount
      API.
    link: https://developer.cisco.com/docs/dna-center/#!l-an-automation-session-count
notes:
  - SDK Method used are
    lan_automation.LanAutomation.lan_automation_session_count,
  - Paths used are
    get /dna/intent/api/v1/lan-automation/count,
"""

EXAMPLES = r"""
---
- name: Get all Lan Automation Count
  cisco.dnac.lan_automation_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "sessionCount": "string"
    }
"""
