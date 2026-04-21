#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: backup_storages_info
short_description: Information module for Backup Storages
description:
  - Get all Backup Storages. - > This api is used to
    get all the mounted backup storage information like
    mount point, disk size based on the provided storage
    type.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  storageType:
    description:
      - StorageType query parameter. The `storageType`
        of the backup storage to be retrieved.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Backup
      GetBackupStorages
    description: Complete reference of the GetBackupStorages
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-backup-storages
notes:
  - SDK Method used are
    backup.Backup.get_backup_storages,
  - Paths used are
    get /dna/system/api/v1/backupStorages,
"""

EXAMPLES = r"""
---
- name: Get all Backup Storages
  cisco.dnac.backup_storages_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    storageType: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": [
        {
          "diskName": "string",
          "fstype": "string",
          "label": "string",
          "mountPoint": "string",
          "partitionName": "string",
          "percentUsage": 0,
          "sizeUnit": "string",
          "totalSize": 0,
          "usedSize": 0
        }
      ],
      "version": "string"
    }
"""
