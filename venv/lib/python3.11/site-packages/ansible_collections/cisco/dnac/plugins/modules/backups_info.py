#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: backups_info
short_description: Information module for Backups
description:
  - Get all Backups.
  - This api is used to get all the backup available
    in the configured storage.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  query:
    description:
      - Query query parameter. Filter based on the provided
        text on predefined fields.
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
      GetAllBackup
    description: Complete reference of the GetAllBackup
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-all-backup
notes:
  - SDK Method used are
    backup.Backup.get_all_backup,
  - Paths used are
    get /dna/system/api/v1/backups,
"""

EXAMPLES = r"""
---
- name: Get all Backups
  cisco.dnac.backups_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    query: string
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
          "compatibilityError": [
            {
              "endDate": "string",
              "namespace": "string",
              "response": {},
              "serviceName": "string",
              "startDate": "string"
            }
          ],
          "context": {},
          "createdBy": "string",
          "createdDate": "string",
          "duration": 0,
          "endDate": "string",
          "fipsEnabled": true,
          "id": "string",
          "installedPackages": [
            {
              "displayName": "string",
              "name": "string",
              "version": "string"
            }
          ],
          "internetProtocolVersion": "string",
          "isBackupAvailable": true,
          "isCompatible": true,
          "name": "string",
          "numberOfNodes": 0,
          "productType": "string",
          "productVersion": "string",
          "releaseDisplayName": "string",
          "releaseDisplayVersion": "string",
          "releaseName": "string",
          "releaseVersion": "string",
          "scope": "string",
          "size": 0,
          "status": "string",
          "storage": {},
          "versions": [
            "string"
          ]
        }
      ],
      "version": "string"
    }
"""
