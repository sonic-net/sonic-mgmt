#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Kevin Breit (@kbreit) <kevin.breit@kevinbreit.net>
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
module: meraki_ms_ospf
short_description: Manage OSPF configuration on MS switches
description:
- Configure OSPF for compatible Meraki MS switches.
deprecated:
  removed_in: '3.0.0'
  why: Updated modules released with increased functionality
  alternative: cisco.meraki.networks_switch_routing_ospf
options:
    state:
        description:
        - Read or edit OSPF settings.
        type: str
        choices: [ present, query ]
        default: present
    net_name:
        description:
        - Name of network containing OSPF configuration.
        type: str
        aliases: [ name, network ]
    net_id:
        description:
        - ID of network containing OSPF configuration.
        type: str
    enabled:
        description:
        - Enable or disable OSPF on the network.
        type: bool
    hello_timer:
        description:
        - Time interval, in seconds, at which hello packets will be sent to OSPF neighbors to maintain connectivity.
        - Value must be between 1 and 255.
        - Default is 10 seconds.
        type: int
    dead_timer:
        description:
        - Time interval to determine when the peer will be declared inactive.
        - Value must be between 1 and 65535.
        type: int
    md5_authentication_enabled:
        description:
        - Whether to enable or disable MD5 authentication.
        type: bool
    md5_authentication_key:
        description:
        - MD5 authentication credentials.
        type: dict
        suboptions:
            id:
                description:
                - MD5 authentication key index.
                - Must be between 1 and 255.
                type: str
            passphrase:
                description:
                - Plain text authentication passphrase
                type: str
    areas:
        description:
        - List of areas in OSPF network.
        type: list
        elements: dict
        suboptions:
            area_id:
                description:
                - OSPF area ID
                type: int
                aliases: [ id ]
            area_name:
                description:
                - Descriptive name of OSPF area.
                type: str
                aliases: [ name ]
            area_type:
                description:
                - OSPF area type.
                choices: [normal, stub, nssa]
                type: str
                aliases: [ type ]
author:
- Kevin Breit (@kbreit)
extends_documentation_fragment: cisco.meraki.meraki
'''

EXAMPLES = r'''
- name: Query OSPF settings
  meraki_ms_ospf:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    state: query
  delegate_to: localhost

- name: Enable OSPF with check mode
  meraki_ms_ospf:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    state: present
    enabled: true
    hello_timer: 20
    dead_timer: 60
    areas:
      area_id: 0
      area_name: Backbone
      area_type: normal
      md5_authentication_enabled: false
'''

RETURN = r'''
data:
    description: Information about queried object.
    returned: success
    type: complex
    contains:
        enabled:
            description:
            - Enable or disable OSPF on the network.
            type: bool
        hello_timer_in_seconds:
            description:
            - Time interval, in seconds, at which hello packets will be sent to OSPF neighbors to maintain connectivity.
            type: int
        dead_timer_in_seconds:
            description:
            - Time interval to determine when the peer will be declared inactive.
            type: int
        areas:
            description:
            - List of areas in OSPF network.
            type: complex
            contains:
                area_id:
                    description:
                    - OSPF area ID
                    type: int
                area_name:
                    description:
                    - Descriptive name of OSPF area.
                    type: str
                area_type:
                    description:
                    - OSPF area type.
                    type: str
        md5_authentication_enabled:
            description:
            - Whether to enable or disable MD5 authentication.
            type: bool
        md5_authentication_key:
            description:
            - MD5 authentication credentials.
            type: complex
            contains:
                id:
                    description:
                    - MD5 key index.
                    type: int
                passphrase:
                    description:
                    - Passphrase for MD5 key.
                    type: str
'''

from ansible.module_utils.basic import AnsibleModule, json
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import MerakiModule, meraki_argument_spec


def construct_payload(meraki):
    payload_key_mapping = {'enabled': 'enabled',
                           'hello_timer': 'helloTimerInSeconds',
                           'dead_timer': 'deadTimerInSeconds',
                           'areas': 'areas',
                           'area_id': 'areaId',
                           'area_name': 'areaName',
                           'area_type': 'areaType',
                           'md5_authentication_enabled': 'md5AuthenticationEnabled',
                           'md5_authentication_key': 'md5AuthenticationKey',
                           'id': 'id',
                           'passphrase': 'passphrase',
                           }
    payload = {}

    # This may need to be reworked to avoid overwiting
    for snake, camel in payload_key_mapping.items():
        try:
            if meraki.params[snake] is not None:
                payload[camel] = meraki.params[snake]
                if snake == 'areas':
                    if meraki.params['areas'] is not None and len(meraki.params['areas']) > 0:
                        payload['areas'] = []
                        for area in meraki.params['areas']:
                            area_settings = {'areaName': area['area_name'],
                                             'areaId': area['area_id'],
                                             'areaType': area['area_type'],
                                             }
                            payload['areas'].append(area_settings)
                # TODO: Does this code below have a purpose?
                # elif snake == 'md5_authentication_key':
                #     if meraki.params['md5_authentication_key'] is not None:
                #         md5_settings = {'id': meraki.params['md5_authentication_key']['id'],
                #                         'passphrase': meraki.params['md5_authentication_key']['passphrase'],
                #                         }
        except KeyError:
            pass

    return payload


def main():
    # define the available arguments/parameters that a user can pass to
    # the module

    areas_arg_spec = dict(area_id=dict(type='int', aliases=['id']),
                          area_name=dict(type='str', aliases=['name']),
                          area_type=dict(type='str', aliases=['type'], choices=['normal', 'stub', 'nssa']),
                          )

    md5_auth_arg_spec = dict(id=dict(type='str'),
                             passphrase=dict(type='str', no_log=True),
                             )

    argument_spec = meraki_argument_spec()
    argument_spec.update(state=dict(type='str', choices=['present', 'query'], default='present'),
                         net_id=dict(type='str'),
                         net_name=dict(type='str', aliases=['name', 'network']),
                         enabled=dict(type='bool'),
                         hello_timer=dict(type='int'),
                         dead_timer=dict(type='int'),
                         areas=dict(type='list', default=None, elements='dict', options=areas_arg_spec),
                         md5_authentication_enabled=dict(type='bool'),
                         md5_authentication_key=dict(type='dict', default=None, options=md5_auth_arg_spec, no_log=True),
                         )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           )
    meraki = MerakiModule(module, function='ms_ospf')

    meraki.params['follow_redirects'] = 'all'

    query_urls = {'ms_ospf': '/networks/{net_id}/switch/routing/ospf'}
    update_urls = {'ms_ospf': '/networks/{net_id}/switch/routing/ospf'}

    meraki.url_catalog['get_all'].update(query_urls)
    meraki.url_catalog['update'] = update_urls

    payload = None

    # execute checks for argument completeness

    if meraki.params['dead_timer'] is not None:
        if meraki.params['dead_timer'] < 1 or meraki.params['dead_timer'] > 65535:
            meraki.fail_json(msg='dead_timer must be between 1 and 65535')
    if meraki.params['hello_timer'] is not None:
        if meraki.params['hello_timer'] < 1 or meraki.params['hello_timer'] > 255:
            meraki.fail_json(msg='hello_timer must be between 1 and 65535')
    if meraki.params['md5_authentication_enabled'] is False:
        if meraki.params['md5_authentication_key'] is not None:
            meraki.fail_json(msg='md5_authentication_key must not be configured when md5_authentication_enabled is false')

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)

    org_id = meraki.params['org_id']
    if not org_id:
        org_id = meraki.get_org_id(meraki.params['org_name'])
    net_id = meraki.params['net_id']
    if net_id is None and meraki.params['net_name']:
        nets = meraki.get_nets(org_id=org_id)
        net_id = meraki.get_net_id(net_name=meraki.params['net_name'], data=nets)
    if meraki.params['state'] == 'query':
        path = meraki.construct_path('get_all', net_id=net_id)
        response = meraki.request(path, method='GET')
        meraki.result['data'] = response
        meraki.exit_json(**meraki.result)
    elif meraki.params['state'] == 'present':
        original = meraki.request(meraki.construct_path('get_all', net_id=net_id), method='GET')
        payload = construct_payload(meraki)
        if meraki.is_update_required(original, payload) is True:
            if meraki.check_mode is True:
                meraki.result['data'] = payload
                meraki.result['changed'] = True
                meraki.exit_json(**meraki.result)
            path = meraki.construct_path('update', net_id=net_id)
            response = meraki.request(path, method='PUT', payload=json.dumps(payload))
            if 'md5_authentication_key' in response:
                response['md5_authentication_key']['passphrase'] = 'VALUE_SPECIFIED_IN_NO_LOG_PARAMETER'
            meraki.result['data'] = response
            meraki.result['changed'] = True
            meraki.exit_json(**meraki.result)
        else:
            if 'md5_authentication_key' in original:
                original['md5_authentication_key']['passphrase'] = 'VALUE_SPECIFIED_IN_NO_LOG_PARAMETER'
            meraki.result['data'] = original
            meraki.exit_json(**meraki.result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    meraki.exit_json(**meraki.result)


if __name__ == '__main__':
    main()
