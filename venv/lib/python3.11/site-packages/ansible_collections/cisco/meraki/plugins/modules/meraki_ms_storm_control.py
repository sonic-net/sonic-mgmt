#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Kevin Breit (@kbreit) <kevin.breit@kevinbreit.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    "status": ['deprecated'],
    'supported_by': 'community'
}

DOCUMENTATION = r'''
---
module: meraki_ms_storm_control
short_description: Manage storm control configuration on a switch in the Meraki cloud
version_added: "0.0.1"
description:
- Allows for management of storm control settings for Meraki MS switches.
deprecated:
  removed_in: '3.0.0'
  why: Updated modules released with increased functionality
  alternative: cisco.meraki.networks_switch_storm_control
options:
    state:
        description:
        - Specifies whether storm control configuration should be queried or modified.
        choices: [query, present]
        default: query
        type: str
    net_name:
        description:
        - Name of network.
        type: str
    net_id:
        description:
        - ID of network.
        type: str
    broadcast_threshold:
        description:
            - Percentage (1 to 99) of total available port bandwidth for broadcast traffic type.
            - Default value 100 percent rate is to clear the configuration.
        type: int
    multicast_threshold:
        description:
            - Percentage (1 to 99) of total available port bandwidth for multicast traffic type.
            - Default value 100 percent rate is to clear the configuration.
        type: int
    unknown_unicast_threshold:
        description:
            - Percentage (1 to 99) of total available port bandwidth for unknown unicast traffic type.
            - Default value 100 percent rate is to clear the configuration.
        type: int

author:
- Kevin Breit (@kbreit)
extends_documentation_fragment: cisco.meraki.meraki
'''

EXAMPLES = r'''
- name: Set broadcast settings
  meraki_switch_storm_control:
    auth_key: abc123
    state: present
    org_name: YourOrg
    net_name: YourNet
    broadcast_threshold: 75
    multicast_threshold: 70
    unknown_unicast_threshold: 65
  delegate_to: localhost

- name: Query storm control settings
  meraki_switch_storm_control:
    auth_key: abc123
    state: query
    org_name: YourOrg
    net_name: YourNet
  delegate_to: localhost
'''

RETURN = r'''
data:
    description: Information queried or updated storm control configuration.
    returned: success
    type: complex
    contains:
        broadcast_threshold:
            description:
                - Percentage (1 to 99) of total available port bandwidth for broadcast traffic type.
                - Default value 100 percent rate is to clear the configuration.
            returned: success
            type: int
            sample: 42
        multicast_threshold:
            description:
                - Percentage (1 to 99) of total available port bandwidth for multicast traffic type.
                - Default value 100 percent rate is to clear the configuration.
            returned: success
            type: int
            sample: 42
        unknown_unicast_threshold:
            description:
                - Percentage (1 to 99) of total available port bandwidth for unknown unicast traffic type.
                - Default value 100 percent rate is to clear the configuration.
            returned: success
            type: int
            sample: 42
'''

from ansible.module_utils.basic import AnsibleModule, json
from ansible.module_utils.common.dict_transformations import recursive_diff
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import MerakiModule, meraki_argument_spec


def construct_payload(params):
    payload = dict()
    if 'broadcast_threshold' in params:
        payload['broadcastThreshold'] = params['broadcast_threshold']
    if 'multicast_threshold' in params:
        payload['multicastThreshold'] = params['multicast_threshold']
    if 'unknown_unicast_threshold' in params:
        payload['unknownUnicastThreshold'] = params['unknown_unicast_threshold']
    return payload


def main():
    # define the available arguments/parameters that a user can pass to
    # the module
    argument_spec = meraki_argument_spec()
    argument_spec.update(state=dict(type='str', choices=['present', 'query'], default='query'),
                         net_name=dict(type='str'),
                         net_id=dict(type='str'),
                         broadcast_threshold=dict(type='int'),
                         multicast_threshold=dict(type='int'),
                         unknown_unicast_threshold=dict(type='int'),
                         )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           )
    meraki = MerakiModule(module, function='switch_storm_control')
    meraki.params['follow_redirects'] = 'all'

    query_urls = {'switch_storm_control': '/networks/{net_id}/switch/stormControl'}
    update_url = {'switch_storm_control': '/networks/{net_id}/switch/stormControl'}

    meraki.url_catalog['get_all'].update(query_urls)
    meraki.url_catalog['update'] = update_url

    payload = None

    org_id = meraki.params['org_id']
    if not org_id:
        org_id = meraki.get_org_id(meraki.params['org_name'])
    net_id = meraki.params['net_id']
    if net_id is None:
        nets = meraki.get_nets(org_id=org_id)
        net_id = meraki.get_net_id(net_name=meraki.params['net_name'], data=nets)

    # execute checks for argument completeness

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    if meraki.params['state'] == 'query':
        path = meraki.construct_path('get_all', net_id=net_id)
        response = meraki.request(path, method='GET')
        if meraki.status == 200:
            meraki.result['data'] = response
    elif meraki.params['state'] == 'present':
        path = meraki.construct_path('get_all', net_id=net_id)
        original = meraki.request(path, method='GET')
        payload = construct_payload(meraki.params)
        if meraki.is_update_required(original, payload) is True:
            diff = recursive_diff(original, payload)
            if meraki.check_mode is True:
                original.update(payload)
                meraki.result['data'] = original
                meraki.result['changed'] = True
                meraki.result['diff'] = {'before': diff[0],
                                         'after': diff[1]}
                meraki.exit_json(**meraki.result)
            path = meraki.construct_path('update', net_id=net_id)
            response = meraki.request(path, method='PUT', payload=json.dumps(payload))
            if meraki.status == 200:
                meraki.result['diff'] = {'before': diff[0],
                                         'after': diff[1]}
                meraki.result['data'] = response
                meraki.result['changed'] = True
        else:
            meraki.result['data'] = original

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    meraki.exit_json(**meraki.result)


if __name__ == '__main__':
    main()
