#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: service_provider_update
short_description: Resource module for Service Provider
  Update
description:
  - Manage operation update of the resource Service
    Provider Update.
  - API to update Service Provider Profile QoS .
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  settings:
    description: Service Provider Update's settings.
    suboptions:
      qos:
        description: Service Provider Update's qos.
        elements: dict
        suboptions:
          model:
            description: Model.
            type: str
          oldProfileName:
            description: Old Profile Name.
            type: str
          profileName:
            description: Profile Name.
            type: str
          wanProvider:
            description: Wan Provider.
            type: str
        type: list
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings UpdateSPProfile
    description: Complete reference of the UpdateSPProfile
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-sp-profile
notes:
  - SDK Method used are
    network_settings.NetworkSettings.update_sp_profile,
  - Paths used are
    put /dna/intent/api/v1/service-provider,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.service_provider_update:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    settings:
      qos:
        - model: string
          oldProfileName: string
          profileName: string
          wanProvider: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "executionId": "string",
      "executionStatusUrl": "string",
      "message": "string"
    }
"""
