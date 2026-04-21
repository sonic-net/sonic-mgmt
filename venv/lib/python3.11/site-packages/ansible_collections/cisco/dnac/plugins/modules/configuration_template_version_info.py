#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: configuration_template_version_info
short_description: Information module for Configuration
  Template Version
description:
  - Get Configuration Template Version by id.
  - Get all the versions of template by its id.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  templateId:
    description:
      - TemplateId path parameter. TemplateId(UUID)
        to get list of versioned templates.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Configuration
      Templates GetsAllTheVersionsOfAGivenTemplate
    description: Complete reference of the GetsAllTheVersionsOfAGivenTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!gets-all-the-versions-of-a-given-template
notes:
  - SDK Method used are
    configuration_templates.ConfigurationTemplates.get_template_versions,
  - Paths used are
    get /dna/intent/api/v1/template-programmer/template/version/{templateId},
"""

EXAMPLES = r"""
---
- name: Get Configuration Template Version by id
  cisco.dnac.configuration_template_version_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    templateId: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "composite": true,
        "name": "string",
        "projectId": "string",
        "projectName": "string",
        "templateId": "string",
        "versionsInfo": [
          {
            "author": "string",
            "description": "string",
            "id": "string",
            "version": "string",
            "versionComment": "string",
            "versionTime": 0
          }
        ]
      }
    ]
"""
