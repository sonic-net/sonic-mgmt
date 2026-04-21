#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_custom_prompt_info
short_description: Information module for Network Device
  Custom Prompt Info
description:
  - Get all Network Device Custom Prompt Info.
  - Returns supported custom prompts by Catalyst Center.
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
  - name: Cisco DNA Center documentation for System
      Settings CustomPromptSupportGETAPI
    description: Complete reference of the CustomPromptSupportGETAPI
      API.
    link: https://developer.cisco.com/docs/dna-center/#!custom-prompt-support-getapi
notes:
  - SDK Method used are
    system_settings.SystemSettings.custom_prompt_support_get_api,
  - Paths used are
    get /dna/intent/api/v1/network-device/custom-prompt,
"""

EXAMPLES = r"""
---
- name: Get all Network Device Custom Prompt Info
  cisco.dnac.network_device_custom_prompt_info:
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
      "response": {
        "customUsernamePrompt": "string",
        "customPasswordPrompt": "string",
        "defaultUsernamePrompt": "string",
        "defaultPasswordPrompt": "string"
      },
      "version": "string"
    }
"""
