#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Alexander Gil Casas <alexander.gilcasas@trustyou.net>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
module: v_switch
short_description: Manage Hetzner's vSwitch
version_added: 1.7.0
author:
  - Alexander Gil Casas (@pando85)
description:
  - Manage Hetzner's vSwitch.
seealso:
  - name: vSwitch documentation
    description: Hetzner's documentation on vSwitch for connecting dedicated servers.
    link: https://docs.hetzner.com/robot/dedicated-server/network/vswitch
extends_documentation_fragment:
  - community.hrobot.robot
  - community.hrobot.attributes
  - community.hrobot.attributes.actiongroup_robot

attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
  idempotent:
    support: full
  action_group:
    version_added: 2.1.0

options:
  vlan:
    description:
      - The vSwitch's VLAN ID.
      - Range can be from 4000 to 4091.
      - In order to identify a vSwitch both name and VLAN must match. If not, a new vSwitch will be created.
    type: int
    required: true
  name:
    description:
      - The vSwitch's name.
      - In order to identify a vSwitch both name and VLAN must match. If not, a new vSwitch will be created.
    type: str
    required: true
  state:
    description:
      - State of the vSwitch.
      - VSwitch is created if state is V(present), and deleted if state is V(absent).
      - V(absent) just cancels the vSwitch at the end of the current day.
      - When cancelling, you have to specify O(servers=[]) if you want to actively remove the servers in the vSwitch.
    type: str
    default: present
    choices: [present, absent]
  servers:
    description:
      - List of server identifiers (server's numeric ID or server's main IPv4 or IPv6).
      - If servers is not specified, servers are not going to be deleted.
    type: list
    elements: str
  wait:
    description:
      - Whether to wait until the vSwitch has been successfully configured before determining what to do, and before returning
        from the module.
      - The API returns status C(in process) when the vSwitch is currently being set up in the servers. If this happens, the
        module will try again until the status changes to C(ready) or server has been removed from vSwitch.
      - Please note that if you disable wait while deleting and removing servers module will fail with C(VSWITCH_IN_PROCESS)
        error.
    type: bool
    default: true
  wait_delay:
    description:
      - Delay to wait (in seconds) before checking again whether the vSwitch servers has been configured.
    type: int
    default: 10
  timeout:
    description:
      - Timeout (in seconds) for waiting for vSwitch servers to be configured.
    type: int
    default: 180
"""

EXAMPLES = r"""
---
- name: Create vSwitch with VLAN 4010 and name foo
  community.hrobot.v_switch:
    hetzner_user: foo
    hetzner_password: bar
    vlan: 4010
    name: foo

- name: Create vSwitch with VLAN 4020 and name foo with two servers
  community.hrobot.v_switch:
    hetzner_user: foo
    hetzner_password: bar
    vlan: 4010
    name: foo
    servers:
      - 123.123.123.123
      - 154323
"""

RETURN = r"""
v_switch:
  description:
    - Information on the vSwitch.
  returned: success
  type: dict
  contains:
    id:
      description:
        - The vSwitch's ID.
      type: int
      sample: 4321
      returned: success
    name:
      description:
        - The vSwitch's name.
      type: str
      sample: 'my vSwitch'
      returned: success
    vlan:
      description:
        - The vSwitch's VLAN ID.
      type: int
      sample: 4000
      returned: success
    cancelled:
      description:
        - Cancellation status.
      type: bool
      sample: false
      returned: success
    server:
      description:
        - The vSwitch's VLAN.
      type: list
      elements: dict
      sample:
        - server_ip: '123.123.123.123'
          server_ipv6_net: '2a01:4f8:111:4221::'
          server_number: 321
          status: 'ready'
      contains:
        server_ip:
          description:
            - The server's main IP address.
          type: str
          sample: '123.123.123.123'
        server_ipv6_net:
          description:
            - The server's main IPv6 network address.
          type: str
          sample: '2a01:f48:111:4221::'
        server_number:
          description:
            - The server's numeric ID.
          type: int
          sample: 321
        status:
          description:
            - Status of vSwitch for this server.
          type: str
          choices:
            - ready
            - in process
            - failed
          sample: 'ready'
      returned: success
    subnet:
      description:
        - List of assigned IP addresses.
      type: list
      elements: dict
      sample:
        - ip: '213.239.252.48'
          mask: 29
          gateway: '213.239.252.49'
      contains:
        ip:
          description:
            - IP address.
          type: str
          sample: '213.239.252.48'
        mask:
          description:
            - Subnet mask in CIDR notation.
          type: int
          sample: 29
        gateway:
          description:
            - Gateway of the subnet.
          type: str
          sample: '213.239.252.49'
      returned: success
    cloud_network:
      description:
        - List of assigned Cloud networks.
      type: list
      elements: dict
      sample:
        - id: 123
          ip: '10.0.2.0'
          mask: 24
          gateway: '10.0.2.1'
      contains:
        id:
          description:
            - Cloud network ID.
          type: int
          sample: 123
        ip:
          description:
            - IP address.
          type: str
          sample: '10.0.2.0'
        mask:
          description:
            - Subnet mask in CIDR notation.
          type: int
          sample: 24
        gateway:
          description:
            - Gateway.
          type: str
          sample: '10.0.2.1'
      returned: success
"""


from datetime import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.hrobot.plugins.module_utils.common import (
    CheckDoneTimeoutException,
)
from ansible_collections.community.hrobot.plugins.module_utils.robot import (
    BASE_URL,
    ROBOT_DEFAULT_ARGUMENT_SPEC,
    get_x_www_form_urlenconded_dict_from_list,
    fetch_url_json,
    fetch_url_json_with_retries,
)

try:
    from urllib.parse import urlencode
except ImportError:
    # Python 2.x fallback:
    from urllib import urlencode

V_SWITCH_BASE_URL = '{0}/vswitch'.format(BASE_URL)


def get_v_switch(module, id_, wait_condition=None):
    url = '{0}/{1}'.format(V_SWITCH_BASE_URL, id_)
    accept_errors = ['NOT_FOUND']
    if wait_condition:
        try:
            result, error = fetch_url_json_with_retries(
                module,
                url,
                check_done_callback=wait_condition,
                check_done_delay=module.params['wait_delay'],
                check_done_timeout=module.params['timeout'],
                accept_errors=accept_errors,
            )
        except CheckDoneTimeoutException as dummy:
            module.fail_json(msg='Timeout waiting vSwitch operation to finish')
    else:
        result, error = fetch_url_json(
            module,
            url,
            accept_errors=accept_errors,
        )

    if error == 'NOT_FOUND':
        module.fail_json(msg='vSwitch not found.')

    return result


def print_list(possible_list):
    if isinstance(possible_list, list):
        return ', '.join([to_native(x) for x in possible_list])
    return repr(possible_list)


def create_v_switch(module):
    headers = {'Content-type': 'application/x-www-form-urlencoded'}
    data = {'name': module.params['name'], 'vlan': module.params['vlan']}
    result, error = fetch_url_json(
        module,
        V_SWITCH_BASE_URL,
        data=urlencode(data),
        headers=headers,
        method='POST',
        accept_errors=['INVALID_INPUT', 'VSWITCH_LIMIT_REACHED'],
    )
    if error == 'INVALID_INPUT':
        invalid_parameters = print_list(result['error']['invalid'])
        module.fail_json(msg='vSwitch invalid parameter ({0})'.format(invalid_parameters))
    elif error == 'VSWITCH_LIMIT_REACHED':
        module.fail_json(msg='The maximum count of vSwitches is reached')

    return result


def delete_v_switch(module, id_):
    url = '{0}/{1}'.format(V_SWITCH_BASE_URL, id_)
    headers = {'Content-type': 'application/x-www-form-urlencoded'}
    data = {'cancellation_date': datetime.now().strftime('%y-%m-%d')}
    result, error = fetch_url_json(
        module,
        url,
        data=urlencode(data),
        headers=headers,
        method='DELETE',
        accept_errors=['INVALID_INPUT', 'NOT_FOUND', 'CONFLICT'],
        allow_empty_result=True,
    )
    if error == 'INVALID_INPUT':
        invalid_parameters = print_list(result['error']['invalid'])
        module.fail_json(msg='vSwitch invalid parameter ({0})'.format(invalid_parameters))
    elif error == 'NOT_FOUND':
        module.fail_json(msg='vSwitch not found to delete')
    elif error == 'CONFLICT':
        module.fail_json(msg='The vSwitch is already cancelled')

    return result


def is_all_servers_ready(result, dummy):
    return all(server['status'] == 'ready' for server in result['server'])


def add_servers(module, id_, servers):
    url = '{0}/{1}/server'.format(V_SWITCH_BASE_URL, id_)
    headers = {'Content-type': 'application/x-www-form-urlencoded'}
    data = get_x_www_form_urlenconded_dict_from_list('server', servers)
    result, error = fetch_url_json(
        module,
        url,
        data=urlencode(data),
        headers=headers,
        method='POST',
        # TODO: missing NOT_FOUND, VSWITCH_NOT_AVAILABLE, VSWITCH_PER_SERVER_LIMIT_REACHED
        accept_errors=[
            'INVALID_INPUT',
            'SERVER_NOT_FOUND',
            'VSWITCH_VLAN_NOT_UNIQUE',
            'VSWITCH_IN_PROCESS',
            'VSWITCH_SERVER_LIMIT_REACHED',
        ],
        allow_empty_result=True,
        allowed_empty_result_status_codes=(201,),
    )
    if error == 'INVALID_INPUT':
        invalid_parameters = print_list(result['error']['invalid'])
        module.fail_json(msg='Invalid parameter adding server ({0})'.format(invalid_parameters))
    elif error == 'SERVER_NOT_FOUND':
        # information about which servers are failing is only there
        module.fail_json(msg=result['error']['message'])
    elif error == 'VSWITCH_VLAN_NOT_UNIQUE':
        # information about which servers are failing is only there
        module.fail_json(msg=result['error']['message'])
    elif error == 'VSWITCH_IN_PROCESS':
        module.fail_json(msg='There is a update running, therefore the vswitch can not be updated')
    elif error == 'VSWITCH_SERVER_LIMIT_REACHED':
        module.fail_json(msg='The maximum number of servers is reached for this vSwitch')

    # TODO: add and delete with `wait=false`
    wait_condition = is_all_servers_ready if module.params['wait'] else None
    return get_v_switch(module, id_, wait_condition)


def delete_servers(module, id_, servers):
    url = '{0}/{1}/server'.format(V_SWITCH_BASE_URL, id_)
    headers = {'Content-type': 'application/x-www-form-urlencoded'}
    data = get_x_www_form_urlenconded_dict_from_list('server', servers)
    result, error = fetch_url_json(
        module,
        url,
        data=urlencode(data),
        headers=headers,
        method='DELETE',
        # TODO: missing INVALID_INPUT, NOT_FOUND
        accept_errors=['SERVER_NOT_FOUND', 'VSWITCH_IN_PROCESS'],
        allow_empty_result=True,
    )
    if error == 'SERVER_NOT_FOUND':
        # information about which servers are failing is only there
        module.fail_json(msg=result['error']['message'])
    elif error == 'VSWITCH_IN_PROCESS':
        module.fail_json(msg='There is a update running, therefore the vswitch can not be updated')

    wait_condition = is_all_servers_ready if module.params['wait'] else None
    return get_v_switch(module, id_, wait_condition)


def get_servers_to_delete(current_servers, desired_servers):
    return [
        server['server_ip']
        for server in current_servers
        if server['server_ip'] not in desired_servers
        and server['server_ipv6_net'] not in desired_servers
        and str(server['server_number']) not in desired_servers
    ]


def get_servers_to_add(current_servers, desired_servers):
    current_ids = [str(server['server_number']) for server in current_servers]
    current_ips = [server['server_ip'] for server in current_servers]
    current_ipv6s = [server['server_ipv6_net'] for server in current_servers]

    return [
        server
        for server in desired_servers
        if server not in current_ips and server not in current_ids and server not in current_ipv6s
    ]


def set_desired_servers(module, id_):
    v_switch = get_v_switch(module, id_)
    changed = False

    if module.params['servers'] is None:
        return (v_switch, changed)

    servers_to_delete = get_servers_to_delete(v_switch['server'], module.params['servers'])
    if servers_to_delete:
        if not module.check_mode:
            v_switch = delete_servers(module, id_, servers_to_delete)
        changed = True
    servers_to_add = get_servers_to_add(v_switch['server'], module.params['servers'])
    if servers_to_add:
        if not module.check_mode:
            v_switch = add_servers(module, id_, servers_to_add)
        changed = True
    return (v_switch, changed)


def main():
    argument_spec = dict(
        vlan=dict(type='int', required=True),
        name=dict(type='str', required=True),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        servers=dict(type='list', elements='str'),
        wait=dict(type='bool', default=True),
        wait_delay=dict(type='int', default=10),
        timeout=dict(type='int', default=180),
    )
    argument_spec.update(ROBOT_DEFAULT_ARGUMENT_SPEC)
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    v_switches, error = fetch_url_json(module, V_SWITCH_BASE_URL, accept_errors=['UNAUTHORIZED'])

    if error:
        module.fail_json(msg='Please check your current user and password configuration')

    matched_v_switches = [
        v
        for v in v_switches
        if v['name'] == module.params['name'] and v['vlan'] == module.params['vlan']
    ]
    non_cancelled_v_switches = [m for m in matched_v_switches if m['cancelled'] is False]
    result = {'changed': False}

    if len(non_cancelled_v_switches) > 1:
        module.fail_json(
            msg='Multiple vSwitches with same name and VLAN ID in non cancelled status. Clean it.'
        )

    elif len(non_cancelled_v_switches) == 1:
        id_ = non_cancelled_v_switches[0]['id']
        v_switch, changed = set_desired_servers(module, id_)
        if changed:
            result['changed'] = True

        if module.params['state'] == 'present':
            result['v_switch'] = v_switch
        elif module.params['state'] == 'absent':
            if not module.check_mode:
                delete_v_switch(module, id_)
            result['changed'] = True
        else:  # pragma: no cover
            raise NotImplementedError("not reachable")  # pragma: no cover
    else:
        if module.params['state'] == 'present':
            result['changed'] = True
            if not module.check_mode:
                v_switch = create_v_switch(module)
                if module.params['servers']:
                    result['v_switch'] = add_servers(module, v_switch['id'], module.params['servers'])
                else:
                    result['v_switch'] = v_switch

    module.exit_json(**result)


if __name__ == '__main__':  # pragma: no cover
    main()  # pragma: no cover
