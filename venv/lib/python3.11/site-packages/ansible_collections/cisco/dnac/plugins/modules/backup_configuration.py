#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: backup_configuration
short_description: Resource module for Backup Configuration
description:
  - Manage operation create of the resource Backup Configuration.
    - > This api is used to create or update backup
    configuration. Obtain the `mountPath` value from
    the mountPoint attribute in the response of the
    `/dna/system/api/v1/backupStorages` API.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  dataRetention:
    description: Date retention policy of the backup.
    type: int
  encryptionPassphrase:
    description: Password to encrypt the backup information.
    type: str
  mountPath:
    description: Backup storage mount path.
    type: str
  type:
    description: The storage type.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Backup
      CreateBackupConfiguration
    description: Complete reference of the CreateBackupConfiguration
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-backup-configuration
notes:
  - SDK Method used are
    backup.Backup.create_backup_configuration,
  - Paths used are
    post /dna/system/api/v1/backupConfiguration,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.backup_configuration:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    dataRetention: 0
    encryptionPassphrase: string
    mountPath: string
    type: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
