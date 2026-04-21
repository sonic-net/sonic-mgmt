#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: configuration_template_export_project
short_description: Resource module for Configuration
  Template Export Project
description:
  - Manage operation create of the resource Configuration
    Template Export Project.
  - Exports the projects for given projectNames.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  payload:
    description: Configuration Template Export Project's
      payload.
    elements: dict
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Configuration
      Templates ExportsTheProjectsForAGivenCriteria
    description: Complete reference of the ExportsTheProjectsForAGivenCriteria
      API.
    link: https://developer.cisco.com/docs/dna-center/#!exports-the-projects-for-a-given-criteria
notes:
  - SDK Method used are
    configuration_templates.ConfigurationTemplates.export_projects,
  - Paths used are
    post /dna/intent/api/v1/template-programmer/project/name/exportprojects,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.configuration_template_export_project:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    payload:
      - {}
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
