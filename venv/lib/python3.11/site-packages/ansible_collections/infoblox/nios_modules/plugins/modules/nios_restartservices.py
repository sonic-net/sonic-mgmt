#!/usr/bin/python
# Copyright (c) 2018-2019 Red Hat, Inc.
# Copyright (c) 2020 Infoblox, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: nios_restartservices
author: "Mauricio Teixeira (@badnetmask)"
short_description: Restart grid services.
version_added: "1.1.0"
description:
  - Restart grid services.
  - When invoked without any options, will restart ALL services on the
    default restart group IF NEEDED.
requirements:
  - infoblox-client
extends_documentation_fragment: infoblox.nios_modules.nios
notes:
    - This module supports C(check_mode).
options:
  groups:
    description:
      - The list of the Service Restart Groups to restart.
    required: false
    type: list
    elements: str
  members:
    description:
      - The list of the Grid Members to restart.
    required: false
    type: list
    elements: str
  mode:
    description:
      - The restart method in case of grid restart.
    required: false
    type: str
    choices:
      - GROUPED
      - SEQUENTIAL
      - SIMULTANEOUS
  restart_option:
    description:
      - Controls whether services are restarted unconditionally or when needed
    required: false
    type: str
    default: RESTART_IF_NEEDED
    choices:
      - RESTART_IF_NEEDED
      - FORCE_RESTART
  services:
    description:
      - The list of services the restart applicable to.
    required: false
    type: list
    elements: str
    default: ALL
    choices:
      - ALL
      - DNS
      - DHCP
      - DHCPV4
      - DHCPV6
'''

EXAMPLES = '''
- name: Restart all grid services if needed.
  infoblox.nios_modules.nios_restartservices:
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Restart DNS service if needed.
  infoblox.nios_modules.nios_restartservices:
    services:
      - DNS
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local
'''

RETURN = ''' # '''

from ansible.module_utils.basic import AnsibleModule
from ..module_utils.api import WapiModule
from ..module_utils.api import normalize_ib_spec


def main():
    ''' Main entry point for module execution
    '''

    ib_spec = dict(
        groups=dict(type='list', elements='str'),
        members=dict(type='list', elements='str'),
        mode=dict(type='str', choices=['GROUPED', 'SEQUENTIAL',
                                       'SIMULTANEOUS']),
        restart_option=dict(type='str', default='RESTART_IF_NEEDED',
                            choices=['RESTART_IF_NEEDED', 'FORCE_RESTART']),
        services=dict(type='list', elements='str', default=['ALL'],
                      choices=['ALL', 'DNS', 'DHCP', 'DHCPV4', 'DHCPV6'])
    )

    argument_spec = dict(
        provider=dict(required=True)
    )

    argument_spec.update(normalize_ib_spec(ib_spec))
    argument_spec.update(WapiModule.provider_spec)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    wapi = WapiModule(module)

    # restart is a grid function, so we need to properly format
    # the arguments before sending the command
    restart_params = module.params
    del restart_params['provider']
    if restart_params['groups'] is None:
        del restart_params['groups']
    if restart_params['members'] is None:
        del restart_params['members']
    if restart_params['mode'] is None:
        del restart_params['mode']
    grid_obj = wapi.get_object('grid')
    if grid_obj is None:
        module.fail_json(msg='Failed to get NIOS grid information.')
    result = wapi.call_func('restartservices', grid_obj[0]['_ref'], restart_params)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
