#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_pending_fabric_events_apply
short_description: Resource module for Sda Pending Fabric
  Events Apply
description:
  - Manage operation create of the resource Sda Pending
    Fabric Events Apply.
  - Applies pending fabric events based on user input.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  payload:
    description: Sda Pending Fabric Events Apply's payload.
    elements: dict
    suboptions:
      fabricId:
        description: ID of the fabric.
        type: str
      id:
        description: ID of the pending fabric event
          to be applied.
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA ApplyPendingFabricEvents
    description: Complete reference of the ApplyPendingFabricEvents
      API.
    link: https://developer.cisco.com/docs/dna-center/#!apply-pending-fabric-events
notes:
  - SDK Method used are
    sda.Sda.apply_pending_fabric_events,
  - Paths used are
    post /dna/intent/api/v1/sda/pendingFabricEvents/apply,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.sda_pending_fabric_events_apply:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    payload:
      - fabricId: string
        id: string
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
