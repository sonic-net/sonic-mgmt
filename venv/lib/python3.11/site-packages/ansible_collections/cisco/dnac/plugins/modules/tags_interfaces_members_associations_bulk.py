#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: tags_interfaces_members_associations_bulk
short_description: Resource module for Tags Interfaces
  Members Associations Bulk
description:
  - Manage operation update of the resource Tags Interfaces
    Members Associations Bulk. - > Updates the tags
    associated with the interfaces. A tag is a user-defined
    or system-defined construct to group resources.
    When an interface is tagged, it is called a member
    of the tag. A tag can be created by using this POST
    `/dna/intent/api/v1/tag` API.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  payload:
    description: Tags Interfaces Members Associations
      Bulk's payload.
    elements: dict
    suboptions:
      id:
        description: Interface id.
        type: str
      tags:
        description: Tags Interfaces Members Associations
          Bulk's tags.
        elements: dict
        suboptions:
          id:
            description: Tag id.
            type: str
        type: list
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Tag UpdateTagsAssociatedWithTheInterfaces
    description: Complete reference of the UpdateTagsAssociatedWithTheInterfaces
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-tags-associated-with-the-interfaces
notes:
  - SDK Method used are
    tag.Tag.update_tags_associated_with_the_interfaces,
  - Paths used are
    put /dna/intent/api/v1/tags/interfaces/membersAssociations/bulk,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.tags_interfaces_members_associations_bulk:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    payload:
      - id: string
        tags:
          - id: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""
