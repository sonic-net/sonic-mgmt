#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: connection_modesetting
short_description: Resource module for Connection Mode
  Setting
description:
  - Manage operation update of the resource Connection
    Mode Setting.
  - Update Cisco Smart Software Manager CSSM connection
    mode for the system.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  connectionMode:
    description: The CSSM connection modes of Catalyst
      Center are DIRECT, ON_PREMISE and SMART_PROXY.
    type: str
  parameters:
    description: Connection Mode Setting's parameters.
    suboptions:
      clientId:
        description: On-premise CSSM client id.
        type: str
      clientSecret:
        description: On-premise CSSM client secret.
        type: str
      onPremiseHost:
        description: On-premise CSSM hostname or IP
          address.
        type: str
      smartAccountName:
        description: On-premise CSSM local smart account
          name.
        type: str
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Licenses
      UpdateCSSMConnectionMode
    description: Complete reference of the UpdateCSSMConnectionMode
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-cssm-connection-mode
notes:
  - SDK Method used are
    licenses.Licenses.update_c_s_s_m_connection_mode,
  - Paths used are
    put /dna/intent/api/v1/connectionModeSetting,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.connection_mode_setting:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    connectionMode: string
    parameters:
      clientId: string
      clientSecret: string
      onPremiseHost: string
      smartAccountName: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "version": "string",
      "response": {
        "url": "string",
        "taskId": "string"
      }
    }
"""
