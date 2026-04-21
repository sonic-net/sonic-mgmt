#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: execute_suggested_actions_commands
short_description: Resource module for Execute Suggested
  Actions Commands
description:
  - Manage operation create of the resource Execute
    Suggested Actions Commands. - > This API fetches
    the issue details and suggested actions for an issue,
    given the Issue Id, executes the commands associated
    with the suggested actions to remediate the issue.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  entity_type:
    description: Commands provided as part of the suggested
      actions for an issue can be executed based on
      issue id. The value here must be issue_id.
    type: str
  entity_value:
    description: Contains the actual value for the entity
      type that has been defined.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Issues
      ExecuteSuggestedActionsCommands
    description: Complete reference of the ExecuteSuggestedActionsCommands
      API.
    link: https://developer.cisco.com/docs/dna-center/#!execute-suggested-actions-commands
notes:
  - SDK Method used are
    issues.Issues.execute_suggested_actions_commands,
  - Paths used are
    post /dna/intent/api/v1/execute-suggested-actions-commands,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.execute_suggested_actions_commands:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    entity_type: string
    entity_value: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
