#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: projects_project_id_info
short_description: Information module for Projects Project
  Id
description:
  - Get Projects Project Id by id.
  - Get a template project by the project's ID.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  projectId:
    description:
      - ProjectId path parameter. The id of the project
        to get, retrieveable from `GET /dna/intent/api/v1/projects`.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Configuration
      Templates GetTemplateProject
    description: Complete reference of the GetTemplateProject
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-template-project
notes:
  - SDK Method used are
    configuration_templates.ConfigurationTemplates.get_template_project,
  - Paths used are
    get /dna/intent/api/v1/projects/{projectId},
"""

EXAMPLES = r"""
---
- name: Get Projects Project Id by id
  cisco.dnac.projects_project_id_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    projectId: string
  register: result
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
        "projectId": "string",
        "name": "string",
        "description": "string",
        "lastUpdateTime": 0
      }
    }
"""
