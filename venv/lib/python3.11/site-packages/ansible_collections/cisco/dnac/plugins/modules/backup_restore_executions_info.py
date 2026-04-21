#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: backup_restore_executions_info
short_description: Information module for Backup Restore
  Executions
description:
  - Get all Backup Restore Executions.
  - This api is used to get all the backup and restore
    executions.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  backupId:
    description:
      - >
        BackupId query parameter. The `backupId` of
        the backup execution to be retrieved.Obtain
        the `backupId` from the id attribute in the
        response of the `/dna/system/api/v1/backups`
        API.
    type: str
  jobType:
    description:
      - JobType query parameter. The `jobType` of the
        backup execution to be retrieved.
    type: str
  status:
    description:
      - Status query parameter. The `status` of the
        backup execution to be retrieved.
    type: str
  offset:
    description:
      - Offset query parameter. The first record to
        show for this page.
    type: int
  limit:
    description:
      - Limit query parameter. The number of records
        to show for this page.
    type: int
  sortBy:
    description:
      - SortBy query parameter. A property within the
        response to sort by.
    type: str
  order:
    description:
      - Order query parameter. Whether ascending or
        descending order should be used to sort the
        response.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Backup
      GetBackupAndRestoreExecutions
    description: Complete reference of the GetBackupAndRestoreExecutions
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-backup-and-restore-executions
notes:
  - SDK Method used are
    backup.Backup.get_backup_and_restore_executions,
  - Paths used are
    get /dna/system/api/v1/backupRestoreExecutions,
"""

EXAMPLES = r"""
---
- name: Get all Backup Restore Executions
  cisco.dnac.backup_restore_executions_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    backupId: string
    jobType: string
    status: string
    offset: 0
    limit: 0
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
      "filter": {},
      "page": {},
      "response": [
        {
          "_metadata": {},
          "backupId": "string",
          "completedPercentage": 0,
          "createdBy": "string",
          "duration": 0,
          "endDate": "string",
          "errorCode": "string",
          "errorMessage": "string",
          "failedTaskDetail": {},
          "id": "string",
          "isForceUpdate": true,
          "jobType": "string",
          "scope": "string",
          "startDate": "string",
          "status": "string",
          "systemErrorMessage": "string",
          "updateMessage": "string"
        }
      ],
      "version": "string"
    }
"""
