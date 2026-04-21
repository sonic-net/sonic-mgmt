#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: backup_nfs_configurations_info
short_description: Information module for Backup Nfs
  Configurations
description:
  - Get all Backup Nfs Configurations.
  - This api is used to get all the configured NFS.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Backup
      GetAllNFSConfigurations
    description: Complete reference of the GetAllNFSConfigurations
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-all-nfs-configurations
notes:
  - SDK Method used are
    backup.Backup.get_all_n_f_s_configurations,
  - Paths used are
    get /dna/system/api/v1/backupNfsConfigurations,
"""

EXAMPLES = r"""
---
- name: Get all Backup Nfs Configurations
  cisco.dnac.backup_nfs_configurations_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
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
          "id": "string",
          "spec": {},
          "status": {}
        }
      ],
      "version": "string"
    }
"""
