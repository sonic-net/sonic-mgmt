#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: backup_restore_executions_id_info
short_description: Information module for Backup Restore
  Executions Id
description:
  - Get Backup Restore Executions Id by id.
  - This api is used to get the execution detail of
    a specific backup or restore worflow process.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. The `id` of the backup execution
        to be retrieved.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Backup
      GetBackupAndRestoreExecution
    description: Complete reference of the GetBackupAndRestoreExecution
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-backup-and-restore-execution
notes:
  - SDK Method used are
    backup.Backup.get_backup_and_restore_execution,
  - Paths used are
    get /dna/system/api/v1/backupRestoreExecutions/{id},
"""

EXAMPLES = r"""
---
- name: Get Backup Restore Executions Id by id
  cisco.dnac.backup_restore_executions_id_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {},
      "version": "string"
    }
"""
