#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: areas
short_description: Resource module for Areas
description:
  - Manage operations create, update and delete of the
    resource Areas.
  - Creates an area in the network hierarchy. - > Deletes
    an area in the network hierarchy. This operations
    fails if there are any child areas or buildings
    for this area.
  - Updates an area in the network hierarchy.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. Area Id.
    type: str
  name:
    description: Area name.
    type: str
  parentId:
    description: Parent Id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Site Design
      CreatesAnArea
    description: Complete reference of the CreatesAnArea
      API.
    link: https://developer.cisco.com/docs/dna-center/#!creates-an-area
  - name: Cisco DNA Center documentation for Site Design
      DeletesAnArea
    description: Complete reference of the DeletesAnArea
      API.
    link: https://developer.cisco.com/docs/dna-center/#!deletes-an-area
  - name: Cisco DNA Center documentation for Site Design
      UpdatesAnArea
    description: Complete reference of the UpdatesAnArea
      API.
    link: https://developer.cisco.com/docs/dna-center/#!updates-an-area
notes:
  - SDK Method used are
    site_design.SiteDesign.creates_an_area,
    site_design.SiteDesign.deletes_an_area,
    site_design.SiteDesign.updates_an_area,
  - Paths used are
    post /dna/intent/api/v1/areas,
    delete
    /dna/intent/api/v1/areas/{id},
    put /dna/intent/api/v1/areas/{id},
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.areas:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    name: string
    parentId: string
- name: Update by id
  cisco.dnac.areas:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    id: string
    name: string
    parentId: string
- name: Delete by id
  cisco.dnac.areas:
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
    {
      "version": "string",
      "response": {
        "url": "string",
        "taskId": "string"
      }
    }
"""
