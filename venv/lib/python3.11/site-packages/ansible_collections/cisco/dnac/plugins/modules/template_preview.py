#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: template_preview
short_description: Resource module for Template Preview
description:
  - Manage operation update of the resource Template
    Preview.
  - API to preview a template.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  deviceId:
    description: UUID of device to get template preview.
    type: str
  params:
    description: Params to render preview.
    type: dict
  resourceParams:
    description: Resource params to render preview.
    type: dict
  templateId:
    description: UUID of template to get template preview.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Configuration
      Templates PreviewTemplate
    description: Complete reference of the PreviewTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!preview-template
notes:
  - SDK Method used are
    configuration_templates.ConfigurationTemplates.preview_template,
  - Paths used are
    put /dna/intent/api/v1/template-programmer/template/preview,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.template_preview:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    deviceId: string
    params: {}
    resourceParams: {}
    templateId: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "cliPreview": "string",
      "deviceId": "string",
      "templateId": "string",
      "validationErrors": {}
    }
"""
