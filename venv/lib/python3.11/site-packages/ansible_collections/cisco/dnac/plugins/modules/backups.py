#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: backups
short_description: Resource module for Backups
description:
  - Manage operation create of the resource Backups.
    - > This api is used to trigger a workflow to create
    an on demand backup. To monitor the progress and
    completion of the backup creation , please call
    `/dna/system/api/v1/backupRestoreExecutions/{id}`
    api , where id is the taskId attribute from the
    response of the curent endpoint.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  name:
    description: The backup name.
    type: str
  scope:
    description: The backup scope states whether the
      backup is with assurance or without assurance
      data.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Backup
      CreateBackup
    description: Complete reference of the CreateBackup
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-backup
notes:
  - SDK Method used are
    backup.Backup.create_backup,
  - Paths used are
    post /dna/system/api/v1/backups,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.backups:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    name: string
    scope: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
