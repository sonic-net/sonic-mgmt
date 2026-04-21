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
module: cp_mgmt_install_database
short_description: Copies the user database and network objects information to specified targets.
description:
  - Copies the user database and network objects information to specified targets.
  - All operations are performed over Web Services API.
  - Available from R80.40 management version.
version_added: "2.1.0"
author: "Or Soffer (@chkp-orso)"
options:
  targets:
    description:
      - Check Point host(s) with one or more Management Software Blades enabled. The targets can be identified by their name or unique identifier.
    type: list
    elements: str
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: install-database
  cp_mgmt_install_database:
    targets:
      - checkpointhost1
      - checkpointhost2
"""

RETURN = """
cp_mgmt_install_database:
  description: The checkpoint install-database output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    checkpoint_argument_spec_for_commands,
    api_command,
)


def main():
    argument_spec = dict(targets=dict(type="list", elements="str"))
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "install-database"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
