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
module: cp_mgmt_test_sic_status
short_description: Test SIC Status reflects the state of the gateway after it has received the certificate issued by the
                   ICA. If the SIC status is Unknown then there is no connection between the gateway and the Security
                   Management Server. If the SIC status is No Communication, an error message will appear. It may
                   contain specific instructions on how to fix the situation.
description:
  - Test SIC Status reflects the state of the gateway after it has received the certificate issued by the ICA. If the SIC status is Unknown then there is
    no connection between the gateway and the Security Management Server. If the SIC status is No Communication, an error message will appear. It may contain
    specific instructions on how to fix the situation.
  - All operations are performed over Web Services API.
  - Available from R81.20 management version.
version_added: "3.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  name:
    description:
      - Gateway, cluster member or Check Point host name.
    type: str
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: test-sic-status
  cp_mgmt_test_sic_status:
    name: gw1
"""

RETURN = """
cp_mgmt_test_sic_status:
  description: The checkpoint test-sic-status output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    checkpoint_argument_spec_for_commands,
    api_command,
)


def main():
    argument_spec = dict(name=dict(type="str"))
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "test-sic-status"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
