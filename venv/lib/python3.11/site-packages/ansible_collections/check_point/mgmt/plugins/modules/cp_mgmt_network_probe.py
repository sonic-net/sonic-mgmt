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
module: cp_mgmt_network_probe
short_description: Manages network-probe objects on Checkpoint over Web Services API
description:
  - Manages network-probe objects on Checkpoint devices including creating, updating and removing objects.
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
  http_options:
    description:
      - Additional options when [protocol] is set to "http".
    type: dict
    suboptions:
      destination:
        description:
          - The destination URL.
        type: str
  icmp_options:
    description:
      - Additional options when [protocol] is set to "icmp".
    type: dict
    suboptions:
      destination:
        description:
          - One of these,<br>- Name or UID of an existing object with a unicast IPv4 address (Host, Security Gateway, and so on).<br>- A unicast
            IPv4 address string (if you do not want to create such an object).
        type: str
      source:
        description:
          - One of these,<br>- The string "main-ip" (the probe uses the main IPv4 address of the Security Gateway objects you specified in the
            parameter [install-on]).<br>- Name or UID of an existing object of type 'Host' with a unicast IPv4 address.<br>- A unicast IPv4 address string (if
            you do not want to create such an object).
        type: str
  install_on:
    description:
      - Collection of Check Point Security Gateways that generate the probe, identified by name or UID.
    type: list
    elements: str
  protocol:
    description:
      - The probing protocol to use.
    type: str
    choices: ['http', 'icmp']
  tags:
    description:
      - Collection of tag identifiers.
    type: list
    elements: str
  interval:
    description:
      - The time interval in the range of 5-300 (seconds) between each probe request.
        Best Practice - The interval value should be lower than the timeout value.
    type: int
  timeout:
    description:
      - The probe expiration timeout in the range of 5-300 (seconds).
        If there is not a single reply within this time, the status of the probe changes to "Down".
    type: int
  color:
    description:
      - Color of the object. Should be one of existing colors.
    type: str
    choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange', 'dark sea green',
             'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon',
             'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna', 'yellow']
  comments:
    description:
      - Comments string.
    type: str
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
  ignore_warnings:
    description:
      - Apply changes ignoring warnings.
    type: bool
  ignore_errors:
    description:
      - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_objects
"""

EXAMPLES = """
- name: add-network-probe
  cp_mgmt_network_probe:
    icmp_options:
      destination: HOST_20.20.20.20
      source: Host_10.10.10.10
    install_on: GW_1
    name: probe_GW1
    state: present

- name: set-network-probe
  cp_mgmt_network_probe:
    icmp_options:
      destination: 2.2.2.2
      source: 1.1.1.1
    name: probe_GW1
    state: present

- name: delete-network-probe
  cp_mgmt_network_probe:
    name: probe_GW1
    state: absent
"""

RETURN = """
cp_mgmt_network_probe:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, api_call


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        http_options=dict(type='dict', options=dict(
            destination=dict(type='str')
        )),
        icmp_options=dict(type='dict', options=dict(
            destination=dict(type='str'),
            source=dict(type='str')
        )),
        install_on=dict(type='list', elements='str'),
        protocol=dict(type='str', choices=['http', 'icmp']),
        tags=dict(type='list', elements='str'),
        interval=dict(type='int'),
        timeout=dict(type='int'),
        color=dict(type='str', choices=['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green',
                                        'khaki', 'orchid', 'dark orange', 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown',
                                        'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon', 'coral', 'sea green',
                                        'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna',
                                        'yellow']),
        comments=dict(type='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        domains_to_process=dict(type='list', elements='str'),
        ignore_warnings=dict(type='bool'),
        ignore_errors=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api_call_object = 'network-probe'

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
