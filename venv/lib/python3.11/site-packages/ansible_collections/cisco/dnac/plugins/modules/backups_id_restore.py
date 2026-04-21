#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: backups_id_restore
short_description: Resource module for Backups Id Restore
description:
  - Manage operation create of the resource Backups
    Id Restore. - > This api is used to trigger restore
    workflow of a specific backup. Obtain the `id` from
    the id attribute in the response of the `/dna/system/api/v1/backups`
    API. To monitor the progress and completion of the
    backup deletion , please call `/dna/system/api/v1/backupRestoreExecutions/{id}`
    api , where id is the taskId attribute from the
    response of the curent endpoint.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  encryptionPassphrase:
    description: Passphrase to restore backup.
    type: str
  id:
    description: Id path parameter. The `id` of the
      backup to be restored.Obtain the `id` from the
      id attribute in the response of the `/dna/system/api/v1/backups`
      API.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Backup
      RestoreBackup
    description: Complete reference of the RestoreBackup
      API.
    link: https://developer.cisco.com/docs/dna-center/#!restore-backup
notes:
  - SDK Method used are
    backup.Backup.restore_backup,
  - Paths used are
    post /dna/system/api/v1/backups/{id}/restore,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.backups_id_restore:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    encryptionPassphrase: string
    id: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
