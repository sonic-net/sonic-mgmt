#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: templates_details_info
short_description: Information module for Templates
  Details
description:
  - Get all Templates Details.
  - Get templates details.
version_added: '4.0.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id query parameter. Id of template to be searched.
    type: str
  name:
    description:
      - Name query parameter. Name of template to be
        searched.
    type: str
  projectId:
    description:
      - ProjectId query parameter. Filter template(s)
        based on project id.
    type: str
  projectName:
    description:
      - ProjectName query parameter. Filter template(s)
        based on project name.
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
  unCommitted:
    description:
      - UnCommitted query parameter. Return uncommitted
        template.
    type: bool
  sortOrder:
    description:
      - SortOrder query parameter. Sort Order Ascending
        (asc) or Descending (dsc).
    type: str
  allTemplateAttributes:
    description:
      - AllTemplateAttributes query parameter. Return
        all template attributes.
    type: bool
  includeVersionDetails:
    description:
      - IncludeVersionDetails query parameter. Include
        template version details.
    type: bool
  offset:
    description:
      - Offset query parameter. Index of first result.
    type: int
  limit:
    description:
      - Limit query parameter. The number of records
        to show for this page;The minimum is 1, and
        the maximum is 500.
    type: float
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Configuration
      Templates GetTemplatesDetailsV2
    description: Complete reference of the GetTemplatesDetailsV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-templates-details-v-2
notes:
  - SDK Method used are
    configuration_templates.ConfigurationTemplates.get_templates_details_v2,
  - Paths used are
    get /dna/intent/api/v2/template-programmer/template,
"""

EXAMPLES = r"""
---
- name: Get all Templates Details
  cisco.dnac.templates_details_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
    name: string
    projectId: string
    projectName: string
    softwareType: string
    softwareVersion: string
    productFamily: string
    productSeries: string
    productType: string
    filterConflictingTemplates: true
    tags: []
    unCommitted: true
    sortOrder: string
    allTemplateAttributes: true
    includeVersionDetails: true
    offset: 0
    limit: 0
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "author": "string",
      "composite": true,
      "containingTemplates": [
        {
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
          "tags": [
            {
              "id": "string",
              "name": "string"
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
      "projectAssociated": true,
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
      "tags": [
        {
          "id": "string",
          "name": "string"
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
      "validationErrors": {
        "rollbackTemplateErrors": {},
        "templateErrors": {},
        "templateId": "string",
        "templateVersion": "string"
      },
      "version": "string",
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
"""
