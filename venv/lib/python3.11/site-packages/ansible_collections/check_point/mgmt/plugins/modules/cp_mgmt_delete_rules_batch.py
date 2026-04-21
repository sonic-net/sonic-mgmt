#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Ansible module to manage CheckPoint Firewall (c) 2019
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: cp_mgmt_delete_rules_batch
short_description: Delete rules in batch from the same layer. Use this API to achieve optimum performance when removing more than one rule.
description:
  - Delete rules in batch from the same layer. Use this API to achieve optimum performance when removing more than one rule.
  - Warnings are ignored when using this API, operation will apply changes while ignoring warnings.
  - Supported rules types are access-rule, nat-rule, https-rule and threat-exception.
  - This module is not idempotent.
  - All operations are performed over Web Services API.
  - Available from R81.10 JHF management version.
version_added: "3.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  objects:
    description:
      - Batch of rules separated by types.
    type: list
    elements: dict
    suboptions:
      layer:
        description:
          - Layer name or uid.
        type: str
      type:
        description:
          - Type of rules to be deleted. <br>Only types from above are supported.
        type: str
      list:
        description:
          - List of rules from the same type to be deleted. <br>Use the "delete" API reference documentation for a single rule command to find the
            expected fields for the request.<br>For example, to delete access-rule, use the "delete-access-rule" command found in the API reference
            documentation (under Access Control & NAT). <br>Note, "ignore-errors", "ignore-warnings" and "details-level" options are not supported when
            deleting a batch of objects.
        type: list
        elements: dict
  auto_publish_session:
    description:
    - Publish the current session if changes have been performed after task completes.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: delete-rules-batch
  cp_mgmt_delete_rules_batch:
    objects:
      - layer: Network
        list:
          - rule_number: 1
          - rule_number: 2
        type: access-rule
      - layer: Standard
        list:
          - rule_number: 1
          - rule_number: 2
        type: nat-rule
      - layer: Default Layer
        list:
          - rule_number: 1
          - rule_number: 2
        type: https-rule
"""

RETURN = """
cp_mgmt_delete_rules_batch:
  description: The checkpoint delete-rules-batch output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    checkpoint_argument_spec_for_commands,
    api_command,
)


def main():
    argument_spec = dict(
        objects=dict(
            type="list",
            elements="dict",
            options=dict(
                layer=dict(type="str"),
                type=dict(type="str"),
                list=dict(type="list", elements="dict"),
            ),
        ),
        auto_publish_session=dict(type="bool"),
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "delete-rules-batch"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
