#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: templates_template_id_versions_count_info
short_description: Information module for Templates
  Template Id Versions Count
description:
  - Get all Templates Template Id Versions Count.
  - Get the count of a template's version information.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  templateId:
    description:
      - >
        TemplateId path parameter. The id of the template
        to get versions of, retrieveable from `GET /dna/intent/api/v1/templates`.
    type: str
  versionNumber:
    description:
      - VersionNumber query parameter. Filter response
        to only get the template version that matches
        this version number.
    type: int
  latestVersion:
    description:
      - LatestVersion query parameter. Filter response
        to only include the latest version of a template.
    type: bool
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Configuration
      Templates GetTemplateVersionsCount
    description: Complete reference of the GetTemplateVersionsCount
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-template-versions-count
notes:
  - SDK Method used are
    configuration_templates.ConfigurationTemplates.get_template_versions_count,
  - Paths used are
    get /dna/intent/api/v1/templates/{templateId}/versions/count,
"""

EXAMPLES = r"""
---
- name: Get all Templates Template Id Versions Count
  cisco.dnac.templates_template_id_versions_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    versionNumber: 0
    latestVersion: true
    templateId: string
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
        "count": 0
      }
    }
"""
