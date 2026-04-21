#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: lan_automation_delete
short_description: Resource module for Lan Automation
  Delete
description:
  - Manage operation delete of the resource Lan Automation
    Delete.
  - Invoke this API to stop LAN Automation for the given
    site.
version_added: '6.0.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. LAN Automation id
      can be obtained from /dna/intent/api/v1/lan-automation/status.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for LAN Automation
      LANAutomationStop
    description: Complete reference of the LANAutomationStop
      API.
    link: https://developer.cisco.com/docs/dna-center/#!l-an-automation-stop
notes:
  - SDK Method used are
    lan_automation.LanAutomation.lan_automation_stop,
  - Paths used are
    delete /dna/intent/api/v1/lan-automation/{id},
"""

EXAMPLES = r"""
---
- name: Delete by id
  cisco.dnac.lan_automation_delete:
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
        "errorCode": "string",
        "message": "string",
        "detail": "string"
      },
      "version": "string"
    }
"""
