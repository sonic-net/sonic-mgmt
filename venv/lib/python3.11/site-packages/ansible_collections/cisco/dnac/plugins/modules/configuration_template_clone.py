#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: configuration_template_clone
short_description: Resource module for Configuration
  Template Clone
description:
  - Manage operation create of the resource Configuration
    Template Clone.
  - API to clone template.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  name:
    description: Name path parameter. Template name
      to clone template(Name should be different than
      existing template name within same project).
    type: str
  projectId:
    description: ProjectId query parameter. UUID of
      the project in which the template needs to be
      created.
    type: str
  templateId:
    description: TemplateId path parameter. UUID of
      the template to clone it.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Configuration
      Templates CreatesACloneOfTheGivenTemplate
    description: Complete reference of the CreatesACloneOfTheGivenTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!creates-a-clone-of-the-given-template
notes:
  - SDK Method used are
    configuration_templates.ConfigurationTemplates.clone_given_template,
  - Paths used are
    post /dna/intent/api/v1/template-programmer/clone/name/{name}/project/{projectId}/template/{templateId},
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.configuration_template_clone:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    name: string
    projectId: string
    templateId: string
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
