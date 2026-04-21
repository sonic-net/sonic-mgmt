#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: maps_import
short_description: Resource module for Maps Import
description:
  - Manage operation delete of the resource Maps Import.
    - > Cancels a previously initatied import, allowing
    the system to cleanup cached resources about that
    import data, and ensures the import cannot accidentally
    be performed / approved at a later time.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  importContextUuid:
    description: ImportContextUuid path parameter. The
      unique import context UUID given by a previous
      call to Start Import API.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Sites ImportMapArchiveCancelAnImport
    description: Complete reference of the ImportMapArchiveCancelAnImport
      API.
    link: https://developer.cisco.com/docs/dna-center/#!import-map-archive-cancel-an-import
notes:
  - SDK Method used are
    sites.Sites.import_map_archive_cancel_an_import,
  - Paths used are
    delete /dna/intent/api/v1/maps/import/{importContextUuid},
"""

EXAMPLES = r"""
---
- name: Delete by id
  cisco.dnac.maps_import:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    importContextUuid: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
