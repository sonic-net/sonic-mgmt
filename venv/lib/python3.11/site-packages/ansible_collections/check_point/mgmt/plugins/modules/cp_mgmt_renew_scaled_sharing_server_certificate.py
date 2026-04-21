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
module: cp_mgmt_renew_scaled_sharing_server_certificate
short_description: Renew the server certificate for the scaled sharing on the specified PDP Security Gateway or Cluster.
description:
  - Renew the server certificate for the scaled sharing on the specified PDP Security Gateway or Cluster.
  - This operation generates a new certificate and replaces the existing certificate for scaled sharing.
  - You must install the Access Control policy to apply the changes.
  - All operations are performed over Web Services API.
  - Available from R82.10 management version.
version_added: "6.7.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  name:
    description:
      - Gateway or cluster name.
    type: str
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: renew-scaled-sharing-server-certificate
  cp_mgmt_renew_scaled_sharing_server_certificate:
    name: gw1
"""

RETURN = """
cp_mgmt_renew_scaled_sharing_server_certificate:
  description: The checkpoint renew-scaled-sharing-server-certificate output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        name=dict(type='str')
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "renew-scaled-sharing-server-certificate"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
