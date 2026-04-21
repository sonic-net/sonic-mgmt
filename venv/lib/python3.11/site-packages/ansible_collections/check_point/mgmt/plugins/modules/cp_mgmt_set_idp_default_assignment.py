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
module: cp_mgmt_set_idp_default_assignment
short_description: Set default Identity Provider assignment to be use for Management server administrator access.
description:
  - Set default Identity Provider assignment to be use for Management server administrator access.
  - All operations are performed over Web Services API.
  - Available from R81.20 management version.
version_added: "3.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  identity_provider:
    description:
      - Represents the Identity Provider to be used for Login by this assignment identified by the name or UID, to cancel existing assignment should
        set to 'none'.
    type: str
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
  ignore_warnings:
    description:
      - Apply changes ignoring warnings.
    type: bool
  ignore_errors:
    description:
      - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
    type: bool
  auto_publish_session:
    description:
    - Publish the current session if changes have been performed after task completes.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: set-idp-default-assignment
  cp_mgmt_set_idp_default_assignment:
    identity_provider: azure
"""

RETURN = """
cp_mgmt_set_idp_default_assignment:
  description: The checkpoint set-idp-default-assignment output.
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
        identity_provider=dict(type="str"),
        details_level=dict(type="str", choices=["uid", "standard", "full"]),
        ignore_warnings=dict(type="bool"),
        ignore_errors=dict(type="bool"),
        auto_publish_session=dict(type="bool"),
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "set-idp-default-assignment"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
