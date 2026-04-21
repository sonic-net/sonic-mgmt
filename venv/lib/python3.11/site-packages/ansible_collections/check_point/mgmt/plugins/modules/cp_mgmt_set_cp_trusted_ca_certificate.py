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
module: cp_mgmt_set_cp_trusted_ca_certificate
short_description: Edit existing Check Point trusted CA certificate using name or uid.
description:
  - Edit existing Check Point trusted CA certificate using name or uid. </br>By default all CP trusted CA certificates are enabled.
  - All operations are performed over Web Services API.
  - Available from R82 management version.
version_added: "6.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  status:
    description:
      - Indicates whether the trusted CP CA certificate is enabled/disabled.
    type: str
    choices: ['enabled', 'disabled']
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
  domains_to_process:
    description:
      - Indicates which domains to process the commands on. It cannot be used with the details-level full, must be run from the System Domain only and
        with ignore-warnings true. Valid values are, CURRENT_DOMAIN, ALL_DOMAINS_ON_THIS_SERVER.
    type: list
    elements: str
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: set-cp-trusted-ca-certificate
  cp_mgmt_set_cp_trusted_ca_certificate:
    name: CA_0090EA36_7A7C_42DF_93EE_CFE97D542FFB
    status: disabled
"""

RETURN = """
cp_mgmt_set_cp_trusted_ca_certificate:
  description: The checkpoint set-cp-trusted-ca-certificate output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        status=dict(type='str', choices=['enabled', 'disabled']),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        domains_to_process=dict(type='list', elements='str')
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "set-cp-trusted-ca-certificate"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
