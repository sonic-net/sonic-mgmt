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
module: cp_mgmt_verify_software_package
short_description: Verifies the software package on target machines.
description:
  - Verifies the software package on target machines.
  - All operations are performed over Web Services API.
  - Available from R80.40 management version.
version_added: "2.0.0"
author: "Or Soffer (@chkp-orso)"
options:
  name:
    description:
      - The name of the software package.
    type: str
  targets:
    description:
      - On what targets to execute this command. Targets may be identified by their name, or object unique identifier.
    type: list
    elements: str
  concurrency_limit:
    description:
      - The number of targets, on which the same package is installed at the same time.
    type: int
  download_package:
    description:
      - NOTE, Supported from Check Point version R81
      - Should the package be downloaded before verification.
    type: bool
  download_package_from:
    description:
      - NOTE, Supported from Check Point version R81
      - Where is the package located.
    type: str
    choices: ['automatic', 'central', 'target-machine']
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: verify-software-package
  cp_mgmt_verify_software_package:
    download_package: 'true'
    download_package_from: target-machine
    name: Check_Point_R80_40_JHF_MCD_DEMO_019_MAIN_Bundle_T1_VISIBLE_FULL.tgz
    targets.1: corporate-gateway
"""

RETURN = """
cp_mgmt_verify_software_package:
  description: The checkpoint verify-software-package output.
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
        name=dict(type="str"),
        targets=dict(type="list", elements="str"),
        concurrency_limit=dict(type="int"),
        download_package=dict(type="bool"),
        download_package_from=dict(
            type="str", choices=["automatic", "central", "target-machine"]
        ),
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "verify-software-package"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
