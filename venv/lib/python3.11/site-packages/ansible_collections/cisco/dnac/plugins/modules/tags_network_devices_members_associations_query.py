#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: tags_network_devices_members_associations_query
short_description: Resource module for Tags Network
  Devices Members Associations Query
description:
  - Manage operation create of the resource Tags Network
    Devices Members Associations Query. - > Fetches
    the tags associated with the given network device
    `ids`. Devices that don't have any tags associated
    will not be included in the response. A tag is a
    user-defined or system-defined construct to group
    resources. When a device is tagged, it is called
    a member of the tag. `ids` can be fetched via `/dna/intent/api/v1/network-device`
    API.
version_added: '6.16.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  ids:
    description: List of member ids (network device
      or interface), maximum 500 ids can be passed.
    elements: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Tag QueryTheTagsAssociatedWithNetworkDevices
    description: Complete reference of the QueryTheTagsAssociatedWithNetworkDevices
      API.
    link: https://developer.cisco.com/docs/dna-center/#!query-the-tags-associated-with-network-devices
notes:
  - SDK Method used are
    tag.Tag.query_the_tags_associated_with_network_devices,
  - Paths used are
    post /dna/intent/api/v1/tags/networkDevices/membersAssociations/query,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.tags_network_devices_members_associations_query:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    ids:
      - string
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
          "tags": [
            {
              "id": "string",
              "name": "string"
            }
          ]
        }
      ],
      "version": "string"
    }
"""
