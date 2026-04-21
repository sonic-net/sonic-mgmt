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
module: cp_mgmt_set_trust
short_description: Configure a Trusted communication between the Management Server and the managed Security Gateway.
description:
  - Configure a Trusted communication between the Management Server and the managed Security Gateway.
  - All operations are performed over Web Services API.
  - Available from R82.10 management version.
version_added: "6.7.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  name:
    description:
      - Object name.
    type: str
  ipv4_address:
    description:
      - IP address of the object, for establishing trust with dynamic gateways.
    type: str
  one_time_password:
    description:
      - Shared password to establish SIC between the Security Management and the Security Gateway.
    type: str
  trust_method:
    description:
      - Establish the trust communication method.
    type: str
    choices: ['one_time_password', 'without_password_not_secure', 'cloud_token']
  trust_settings:
    description:
      - Settings for the trusted communication establishment.
    type: dict
    suboptions:
      gateway_mac_address:
        description:
          - Use the Security Gateway MAC address, relevant for the gateway_mac_address identification-method.
        type: str
      identification_method:
        description:
          - How to identify the gateway (relevant for Spark DAIP gateways only).
        type: str
        choices: ['gateway_name', 'mac_address', 'none_not_secure', 'ip_address']
      initiation_phase:
        description:
          - Push the certificate to the Security Gateway immediately, or wait for the Security Gateway to pull the certificate. Default value for
            Spark Gateway is 'when_gateway_connects'.
        type: str
        choices: ['now', 'when_gateway_connects']
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
- name: set-trust
  cp_mgmt_set_trust:
    name: gw1
    one_time_password: aaaa
"""

RETURN = """
cp_mgmt_set_trust:
  description: The checkpoint set-trust output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        name=dict(type='str'),
        ipv4_address=dict(type='str'),
        one_time_password=dict(type='str', no_log=True),
        trust_method=dict(type='str', choices=['one_time_password', 'without_password_not_secure', 'cloud_token']),
        trust_settings=dict(type='dict', options=dict(
            gateway_mac_address=dict(type='str'),
            identification_method=dict(type='str', choices=['gateway_name', 'mac_address', 'none_not_secure', 'ip_address']),
            initiation_phase=dict(type='str', choices=['now', 'when_gateway_connects'])
        )),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        domains_to_process=dict(type='list', elements='str')
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "set-trust"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
