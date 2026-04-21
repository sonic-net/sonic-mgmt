#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: integration_settings_itsm_instances_info
short_description: Information module for Integration
  Settings Itsm Instances
description:
  - Get all Integration Settings Itsm Instances.
  - Fetches all ITSM Integration settings.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  page_size:
    description:
      - Page_size query parameter. Specifies the number
        of records to display per page.
    type: float
  page:
    description:
      - Page query parameter. Indicates the current
        page number to display.
    type: float
  sortBy:
    description:
      - SortBy query parameter. The field name used
        to sort the records.
    type: str
  order:
    description:
      - Order query parameter. Specify the sorting order
        - asc for ascending or desc for descending.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for ITSM Integration
      GetAllITSMIntegrationSettings
    description: Complete reference of the GetAllITSMIntegrationSettings
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-all-itsm-integration-settings
notes:
  - SDK Method used are
    itsm_integration.ItsmIntegration.get_all_itsm_integration_settings,
  - Paths used are
    get /dna/intent/api/v1/integration-settings/itsm/instances,
"""

EXAMPLES = r"""
---
- name: Get all Integration Settings Itsm Instances
  cisco.dnac.integration_settings_itsm_instances_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    page_size: 0
    page: 0
    sortBy: string
    order: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "page": 0,
      "pageSize": 0,
      "totalPages": 0,
      "data": [
        {
          "_id": "string",
          "id": "string",
          "createdBy": "string",
          "description": "string",
          "dypId": "string",
          "dypMajorVersion": 0,
          "dypName": "string",
          "name": "string",
          "schemaVersion": 0,
          "softwareVersionLog": [
            {}
          ],
          "uniqueKey": "string",
          "updatedBy": "string",
          "updatedDate": 0
        }
      ],
      "totalRecords": 0
    }
"""
