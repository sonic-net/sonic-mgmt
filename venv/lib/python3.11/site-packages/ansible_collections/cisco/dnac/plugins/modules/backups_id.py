#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: backups_id
short_description: Resource module for Backups Id
description:
  - Manage operation delete of the resource Backups
    Id. - > This api is used to trigger delete workflow
    of a specific backup based on the provided `id`
    Obtain the `id` from the id attribute in the response
    of the `/dna/system/api/v1/backups` API. To monitor
    the progress and completion of the backup deletion
    , please call `/dna/system/api/v1/backupRestoreExecutions/{id}`
    api , where id is the taskId attribute from the
    response of the curent endpoint.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. The `id` of the
      backup to be deleted.Obtain the 'id' from the
      id attribute in the response of the `/dna/system/api/v1/backups`
      API.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Backup
      DeleteBackup
    description: Complete reference of the DeleteBackup
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-backup
notes:
  - SDK Method used are
    backup.Backup.delete_backup,
  - Paths used are
    delete /dna/system/api/v1/backups/{id},
"""

EXAMPLES = r"""
---
- name: Delete by id
  cisco.dnac.backups_id:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
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
