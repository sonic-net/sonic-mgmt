#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: templates_template_id_versions_info
short_description: Information module for Templates
  Template Id Versions
description:
  - Get all Templates Template Id Versions.
  - Get a template's version information.
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
  order:
    description:
      - Order query parameter. Whether ascending or
        descending order should be used to sort the
        response.
    type: str
  limit:
    description:
      - Limit query parameter. The number of records
        to show for this page;The minimum is 1, and
        the maximum is 500.
    type: float
  offset:
    description:
      - Offset query parameter. The first record to
        show for this page; the first record is numbered
        1.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Configuration
      Templates GetTemplateVersions
    description: Complete reference of the GetTemplateVersions
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-template-versions
notes:
  - SDK Method used are
    configuration_templates.ConfigurationTemplates.get_template_versions,
  - Paths used are
    get /dna/intent/api/v1/templates/{templateId}/versions,
"""

EXAMPLES = r"""
---
- name: Get all Templates Template Id Versions
  cisco.dnac.templates_template_id_versions_info:
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
    order: string
    limit: 0
    offset: 0
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
      "response": [
        {
          "versionId": "string",
          "version": 0,
          "versionTime": 0,
          "RegularTemplate": {
            "templateId": "string",
            "name": "string",
            "projectId": "string",
            "description": "string",
            "softwareFamily": "string",
            "author": "string",
            "products": [
              {
                "productFamily": "string",
                "productSeries": "string",
                "productName": "string"
              }
            ],
            "lastUpdateTime": 0,
            "type": "string",
            "language": "string",
            "templateContent": "string"
          },
          "CompositeTemplate": {
            "templateId": "string",
            "name": "string",
            "projectId": "string",
            "description": "string",
            "softwareFamily": "string",
            "author": "string",
            "products": [
              {
                "productFamily": "string",
                "productSeries": "string",
                "productName": "string"
              }
            ],
            "lastUpdateTime": 0,
            "type": "string",
            "failurePolicy": "string"
          }
        }
      ]
    }
"""
