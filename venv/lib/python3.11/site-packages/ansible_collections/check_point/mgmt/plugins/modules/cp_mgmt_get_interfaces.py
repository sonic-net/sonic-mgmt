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
module: cp_mgmt_get_interfaces
short_description: Get physical interfaces with or without their topology from a Gaia Security Gateway or Cluster.
description:
  - Get physical interfaces with or without their topology from a Gaia Security Gateway or Cluster.
  - The fetched topology is based on static routes.
  - SIC must be established in the Security Gateway or Cluster Member object.
  - Security Gateway or Cluster Members must be up and running.
  - All operations are performed over Web Services API.
  - Available from R81 management version.
version_added: "5.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  target_name:
    description:
      - Target name.
    type: str
  group_interfaces_by_subnet:
    description:
      - Specify whether to group the cluster interfaces by a subnet.
        Otherwise, group the cluster interfaces by their names.
    type: bool
  use_defined_by_routes:
    description:
      - Specify whether to configure the topology "Defined by Routes" where applicable.
        Otherwise, configure the topology to "This Network" as default for internal interfaces.
    type: bool
  with_topology:
    description:
      - Specify whether to fetch the interfaces with their topology. Otherwise, the Management Server fetches
        the interfaces without their topology.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: get-interfaces
  cp_mgmt_get_interfaces:
    target_name: gw1
    with_topology: true
"""

RETURN = """
cp_mgmt_get_interfaces:
  description: The checkpoint get-interfaces output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        target_name=dict(type='str'),
        group_interfaces_by_subnet=dict(type='bool'),
        use_defined_by_routes=dict(type='bool'),
        with_topology=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "get-interfaces"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
