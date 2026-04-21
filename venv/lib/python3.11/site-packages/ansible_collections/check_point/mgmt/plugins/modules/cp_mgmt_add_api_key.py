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
module: cp_mgmt_add_api_key
short_description: Add API key for administrator, to enable login with it. For the key to be valid publish is needed.
description:
  - Add API key for administrator, to enable login with it. For the key to be valid publish is needed. <br>When using mgmt_cli tool, add -f json to get
    the key in the command's output.
  - All operations are performed over Web Services API.
  - Available from R80.40 management version.
version_added: "2.0.0"
author: "Or Soffer (@chkp-orso)"
options:
  admin_uid:
    description:
      - Administrator uid to generate API key for.
    type: str
  admin_name:
    description:
      - Administrator name to generate API key for.
    type: str
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: add-api-key
  cp_mgmt_add_api_key:
    admin_name: admin
"""

RETURN = """
cp_mgmt_add_api_key:
  description: The checkpoint add-api-key output.
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
        admin_uid=dict(type="str"), admin_name=dict(type="str")
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "add-api-key"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
