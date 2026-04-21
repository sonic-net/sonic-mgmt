#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: itsm_cmdb_sync_status_info
short_description: Information module for Itsm Cmdb
  Sync Status
description:
  - Get all Itsm Cmdb Sync Status. - > This API allows
    to retrieve the detail of CMDB sync status.It accepts
    two query parameter "status","date".The supported
    values for status field are "Success","Failed","Unknown"
    and date field should be in "YYYY-MM-DD" format.
    By default all the cmdb sync status will be send
    as response and based on the query parameter filtered
    detail will be send as response.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  status:
    description:
      - >
        Status query parameter. Supported values are
        "Success","Failed" and "Unknown". Providing
        other values will result in all the available
        sync job status.
    type: str
  date:
    description:
      - Date query parameter. Provide date in "YYYY-MM-DD"
        format.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for ITSM GetCMDBSyncStatus
    description: Complete reference of the GetCMDBSyncStatus
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-cmdb-sync-status
notes:
  - SDK Method used are
    itsm.Itsm.get_cmdb_sync_status,
  - Paths used are
    get /dna/intent/api/v1/cmdb-sync/detail,
"""

EXAMPLES = r"""
---
- name: Get all Itsm Cmdb Sync Status
  cisco.dnac.itsm_cmdb_sync_status_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    status: string
    date: string
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
        "successCount": "string",
        "failureCount": "string",
        "devices": [
          {
            "deviceId": "string",
            "status": "string"
          }
        ],
        "unknownErrorCount": "string",
        "message": "string",
        "syncTime": "string"
      }
    ]
"""
