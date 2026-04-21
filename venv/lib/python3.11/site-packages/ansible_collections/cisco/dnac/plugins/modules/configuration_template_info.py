#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: configuration_template_info
short_description: Information module for Configuration
  Template
description:
  - Get all Configuration Template.
  - Get Configuration Template by id.
  - Details of the template by its id.
  - List the templates available.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  projectId:
    description:
      - ProjectId query parameter. Filter template(s)
        based on project UUID.
    type: str
  softwareType:
    description:
      - SoftwareType query parameter. Filter template(s)
        based software type.
    type: str
  softwareVersion:
    description:
      - SoftwareVersion query parameter. Filter template(s)
        based softwareVersion.
    type: str
  productFamily:
    description:
      - ProductFamily query parameter. Filter template(s)
        based on device family.
    type: str
  productSeries:
    description:
      - ProductSeries query parameter. Filter template(s)
        based on device series.
    type: str
  productType:
    description:
      - ProductType query parameter. Filter template(s)
        based on device type.
    type: str
  filterConflictingTemplates:
    description:
      - FilterConflictingTemplates query parameter.
        Filter template(s) based on confliting templates.
    type: bool
  tags:
    description:
      - Tags query parameter. Filter template(s) based
        on tags.
    elements: str
    type: list
  projectNames:
    description:
      - ProjectNames query parameter. Filter template(s)
        based on project names.
    elements: str
    type: list
  unCommitted:
    description:
      - UnCommitted query parameter. Filter template(s)
        based on template commited or not.
    type: bool
  sortOrder:
    description:
      - SortOrder query parameter. Sort Order Ascending
        (asc) or Descending (des).
    type: str
  templateId:
    description:
      - TemplateId path parameter. TemplateId(UUID)
        to get details of the template.
    type: str
  latestVersion:
    description:
      - LatestVersion query parameter. LatestVersion
        flag to get the latest versioned template.
    type: bool
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Configuration
      Templates GetsDetailsOfAGivenTemplate
    description: Complete reference of the GetsDetailsOfAGivenTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!gets-details-of-a-given-template
  - name: Cisco DNA Center documentation for Configuration
      Templates GetsTheTemplatesAvailable
    description: Complete reference of the GetsTheTemplatesAvailable
      API.
    link: https://developer.cisco.com/docs/dna-center/#!gets-the-templates-available
notes:
  - SDK Method used are
    configuration_templates.ConfigurationTemplates.get_template_details,
    configuration_templates.ConfigurationTemplates.gets_the_templates_available,
  - Paths used are
    get /dna/intent/api/v1/template-programmer/template,
    get /dna/intent/api/v1/template-programmer/template/{templateId},
"""

EXAMPLES = r"""
---
- name: Get all Configuration Template
  cisco.dnac.configuration_template_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    projectId: string
    softwareType: string
    softwareVersion: string
    productFamily: string
    productSeries: string
    productType: string
    filterConflictingTemplates: true
    tags: []
    projectNames: []
    unCommitted: true
    sortOrder: string
  register: result
- name: Get Configuration Template by id
  cisco.dnac.configuration_template_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
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
      "tags": [
        {
          "id": "string",
          "name": "string"
        }
      ],
      "author": "string",
      "composite": true,
      "containingTemplates": [
        {
          "tags": [
            {
              "id": "string",
              "name": "string"
            }
          ],
          "composite": true,
          "description": "string",
          "deviceTypes": [
            {
              "productFamily": "string",
              "productSeries": "string",
              "productType": "string"
            }
          ],
          "id": "string",
          "language": "string",
          "name": "string",
          "projectName": "string",
          "rollbackTemplateParams": [
            {
              "binding": "string",
              "customOrder": 0,
              "dataType": "string",
              "defaultValue": "string",
              "description": "string",
              "displayName": "string",
              "group": "string",
              "id": "string",
              "instructionText": "string",
              "key": "string",
              "notParam": true,
              "order": 0,
              "paramArray": true,
              "parameterName": "string",
              "provider": "string",
              "range": [
                {
                  "id": "string",
                  "maxValue": 0,
                  "minValue": 0
                }
              ],
              "required": true,
              "selection": {
                "defaultSelectedValues": [
                  "string"
                ],
                "id": "string",
                "selectionType": "string",
                "selectionValues": {}
              }
            }
          ],
          "templateContent": "string",
          "templateParams": [
            {
              "binding": "string",
              "customOrder": 0,
              "dataType": "string",
              "defaultValue": "string",
              "description": "string",
              "displayName": "string",
              "group": "string",
              "id": "string",
              "instructionText": "string",
              "key": "string",
              "notParam": true,
              "order": 0,
              "paramArray": true,
              "parameterName": "string",
              "provider": "string",
              "range": [
                {
                  "id": "string",
                  "maxValue": 0,
                  "minValue": 0
                }
              ],
              "required": true,
              "selection": {
                "defaultSelectedValues": [
                  "string"
                ],
                "id": "string",
                "selectionType": "string",
                "selectionValues": {}
              }
            }
          ],
          "version": "string"
        }
      ],
      "createTime": 0,
      "customParamsOrder": true,
      "description": "string",
      "deviceTypes": [
        {
          "productFamily": "string",
          "productSeries": "string",
          "productType": "string"
        }
      ],
      "failurePolicy": "string",
      "id": "string",
      "language": "string",
      "lastUpdateTime": 0,
      "latestVersionTime": 0,
      "name": "string",
      "parentTemplateId": "string",
      "projectId": "string",
      "projectName": "string",
      "rollbackTemplateContent": "string",
      "rollbackTemplateParams": [
        {
          "binding": "string",
          "customOrder": 0,
          "dataType": "string",
          "defaultValue": "string",
          "description": "string",
          "displayName": "string",
          "group": "string",
          "id": "string",
          "instructionText": "string",
          "key": "string",
          "notParam": true,
          "order": 0,
          "paramArray": true,
          "parameterName": "string",
          "provider": "string",
          "range": [
            {
              "id": "string",
              "maxValue": 0,
              "minValue": 0
            }
          ],
          "required": true,
          "selection": {
            "defaultSelectedValues": [
              "string"
            ],
            "id": "string",
            "selectionType": "string",
            "selectionValues": {}
          }
        }
      ],
      "softwareType": "string",
      "softwareVariant": "string",
      "softwareVersion": "string",
      "templateContent": "string",
      "templateParams": [
        {
          "binding": "string",
          "customOrder": 0,
          "dataType": "string",
          "defaultValue": "string",
          "description": "string",
          "displayName": "string",
          "group": "string",
          "id": "string",
          "instructionText": "string",
          "key": "string",
          "notParam": true,
          "order": 0,
          "paramArray": true,
          "parameterName": "string",
          "provider": "string",
          "range": [
            {
              "id": "string",
              "maxValue": 0,
              "minValue": 0
            }
          ],
          "required": true,
          "selection": {
            "defaultSelectedValues": [
              "string"
            ],
            "id": "string",
            "selectionType": "string",
            "selectionValues": {}
          }
        }
      ],
      "validationErrors": {
        "rollbackTemplateErrors": {},
        "templateErrors": {},
        "templateId": "string",
        "templateVersion": "string"
      },
      "version": "string"
    }
"""
