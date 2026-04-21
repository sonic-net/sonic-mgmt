#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: accesspoint_configuration_details_by_task_id_info
short_description: Information module for Accesspoint
  Configuration Details By Task Id
description:
  - Get Accesspoint Configuration Details By Task Id
    by id.
  - Users can query the access point configuration result
    using this intent API.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  task_id:
    description:
      - Task_id path parameter. Task id information
        of ap config.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      GetAccessPointConfigurationTaskResult
    description: Complete reference of the GetAccessPointConfigurationTaskResult
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-access-point-configuration-task-result
notes:
  - SDK Method used are
    wireless.Wireless.get_access_point_configuration_task_result,
  - Paths used are
    get /dna/intent/api/v1/wireless/accesspoint-configuration/details/{task_id},
"""

EXAMPLES = r"""
---
- name: Get Accesspoint Configuration Details By Task
    Id by id
  cisco.dnac.accesspoint_configuration_details_by_task_id_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    task_id: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "instanceUuid": {},
        "instanceId": 0,
        "authEntityId": {},
        "displayName": "string",
        "authEntityClass": {},
        "instanceTenantId": "string",
        "_orderedListOEIndex": 0,
        "_orderedListOEAssocName": {},
        "_creationOrderIndex": 0,
        "_isBeingChanged": true,
        "deployPending": "string",
        "instanceCreatedOn": {},
        "instanceUpdatedOn": {},
        "changeLogList": {},
        "instanceOrigin": {},
        "lazyLoadedEntities": {},
        "instanceVersion": 0,
        "apName": "string",
        "controllerName": "string",
        "locationHeirarchy": "string",
        "macAddress": "string",
        "status": "string",
        "statusDetails": "string",
        "internalKey": {
          "type": "string",
          "id": 0,
          "longType": "string",
          "url": "string"
        }
      }
    ]
"""
