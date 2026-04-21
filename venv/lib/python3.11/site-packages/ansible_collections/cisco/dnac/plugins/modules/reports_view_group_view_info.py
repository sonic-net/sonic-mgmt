#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: reports_view_group_view_info
short_description: Information module for Reports View
  Group View
description:
  - Get Reports View Group View by id. - > Gives complete
    information of the view that is required to configure
    a report. Use "Get views for a given view group"
    API to get the viewIds required as a query param
    for this API for available views.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  viewGroupId:
    description:
      - ViewGroupId path parameter. ViewGroupId of viewgroup.
    type: str
  viewId:
    description:
      - ViewId path parameter. View id of view.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Reports
      GetViewDetailsForAGivenViewGroup_View
    description: Complete reference of the GetViewDetailsForAGivenViewGroup_View
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-view-details-for-a-given-view-group-view
notes:
  - SDK Method used are
    reports.Reports.get_view_details_for_a_given_view_group_and_view,
  - Paths used are
    get /dna/intent/api/v1/data/view-groups/{viewGroupId}/views/{viewId},
"""

EXAMPLES = r"""
---
- name: Get Reports View Group View by id
  cisco.dnac.reports_view_group_view_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    viewGroupId: string
    viewId: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "deliveries": [
        {
          "type": "string",
          "default": true
        }
      ],
      "description": "string",
      "fieldGroups": [
        {
          "fieldGroupDisplayName": "string",
          "fieldGroupName": "string",
          "fields": [
            {
              "displayName": "string",
              "name": "string"
            }
          ],
          "tableId": "string"
        }
      ],
      "filters": [
        {
          "additionalInfo": {},
          "cacheFilter": true,
          "dataType": "string",
          "displayName": "string",
          "filterSource": {
            "dataSource": {},
            "displayValuePath": "string",
            "rootPath": "string",
            "valuePath": "string"
          },
          "name": "string",
          "required": true,
          "timeOptions": [
            {
              "info": "string",
              "maxValue": 0,
              "minValue": 0,
              "name": "string",
              "value": "string"
            }
          ],
          "type": "string"
        }
      ],
      "formats": [
        {
          "format": "string",
          "name": "string",
          "default": true,
          "template": {
            "jsTemplateId": "string"
          }
        }
      ],
      "schedules": [
        {
          "type": "string",
          "default": true
        }
      ],
      "viewId": "string",
      "viewInfo": "string",
      "viewName": "string"
    }
"""
