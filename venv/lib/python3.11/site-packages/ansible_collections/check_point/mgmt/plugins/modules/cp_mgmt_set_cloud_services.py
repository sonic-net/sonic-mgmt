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
module: cp_mgmt_set_cloud_services
short_description: Set the connection settings between the Management Server and Check Point's Infinity Portal.
description:
  - Set the connection settings between the Management Server and Check Point's Infinity Portal.
  - All operations are performed over Web Services API.
  - Available from R81.20 management version.
version_added: "5.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  gateways_onboarding_settings:
    description:
      - Gateways on-boarding to Infinity Portal settings.
    type: dict
    suboptions:
      connection_method:
        description:
          - Indicate whether Gateways will be connected to Infinity Portal automatically or only after policy installation.
        type: str
        choices: ['automatically', 'after install policy']
      participant_gateways:
        description:
          - Which Gateways will be connected to Infinity Portal.
        type: str
        choices: ['all', 'specific']
      specific_gateways:
        description:
          - Selection of targets identified by the name or UID which will be on-boarded to the cloud. Configuration will be applied only when
            "participant-gateways" field is set to "specific".
        type: list
        elements: str
      details_level:
        description:
          - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
            representation of the object.
        type: str
        choices: ['uid', 'standard', 'full']
  status:
    description:
      - Connection status.
    type: str
    choices: ['connected', 'disabled']
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: set-cloud-services
  cp_mgmt_set_cloud_services:
    gateways_onboarding_settings:
      connection_method: after install policy
      participant_gateways: specific
      specific_gateways: gw1
"""

RETURN = """
cp_mgmt_set_cloud_services:
  description: The checkpoint set-cloud-services output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        gateways_onboarding_settings=dict(type='dict', options=dict(
            connection_method=dict(type='str', choices=['automatically', 'after install policy']),
            participant_gateways=dict(type='str', choices=['all', 'specific']),
            specific_gateways=dict(type='list', elements='str'),
            details_level=dict(type='str', choices=['uid', 'standard', 'full'])
        )),
        status=dict(type='str', choices=['connected', 'disabled'])
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "set-cloud-services"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
