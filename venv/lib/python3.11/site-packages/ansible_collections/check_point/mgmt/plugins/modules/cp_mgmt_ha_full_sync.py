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

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: cp_mgmt_ha_full_sync
short_description: Perform full sync from active server to standby peer.
description:
  - Perform full sync from active server to standby peer. <br>Run this command from the active server. <br>When performing a full sync on the global
    domain, use the Multi Domain Server name of the standby global domain.
  - All operations are performed over Web Services API.
  - Available from R80.40 JHF management version.
version_added: "5.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  name:
    description:
      - Peer name (Multi Domain Server, Domain Server or Security Management Server).
    type: str
  ignore_errors:
    description:
      - Apply changes ignoring errors.
      - Available from R81.20 management version.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: ha-full-sync
  cp_mgmt_ha_full_sync:
    name: mypeer
"""

RETURN = """
cp_mgmt_ha_full_sync:
  description: The checkpoint ha-full-sync output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        name=dict(type='str'),
        ignore_errors=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "ha-full-sync"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
