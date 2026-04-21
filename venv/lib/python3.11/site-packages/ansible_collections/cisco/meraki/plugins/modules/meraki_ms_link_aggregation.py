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
module: meraki_ms_link_aggregation
short_description: Manage link aggregations on MS switches
version_added: "1.2.0"
description:
- Allows for management of MS switch link aggregations in a Meraki environment.
notes:
- Switch profile ports are not supported in this module.
deprecated:
  removed_in: '3.0.0'
  why: Updated modules released with increased functionality
  alternative: cisco.meraki.networks_switch_link_aggregations
options:
    state:
        description:
        - Specifies whether SNMP information should be queried or modified.
        type: str
        choices: [ absent, query, present ]
        default: present
    net_name:
        description:
        - Name of network.
        type: str
    net_id:
        description:
        - ID of network.
        type: str
    lag_id:
        description:
        - ID of lag to query or modify.
        type: str
    switch_ports:
        description:
        - List of switchports to include in link aggregation.
        type: list
        elements: dict
        suboptions:
            serial:
                description:
                - Serial number of switch to own link aggregation.
                type: str
            port_id:
                description:
                - Port number which should be included in link aggregation.
                type: str
author:
- Kevin Breit (@kbreit)
extends_documentation_fragment: cisco.meraki.meraki
'''

EXAMPLES = r'''
- name: Create LAG
  meraki_ms_link_aggregation:
    auth_key: '{{ auth_key }}'
    state: present
    org_name: '{{ test_org_name }}'
    net_name: '{{ test_switch_net_name }}'
    switch_ports:
      - serial: '{{ serial_switch }}'
        port_id: "1"
      - serial: '{{ serial_switch }}'
        port_id: "2"
  delegate_to: localhost

- name: Update LAG
  meraki_ms_link_aggregation:
    auth_key: '{{ auth_key }}'
    state: present
    org_name: '{{ test_org_name }}'
    net_name: '{{ test_switch_net_name }}'
    lag_id: '{{ lag_id }}'
    switch_ports:
      - serial: '{{ serial_switch }}'
        port_id: "1"
      - serial: '{{ serial_switch }}'
        port_id: "2"
      - serial: '{{ serial_switch }}'
        port_id: "3"
      - serial: '{{ serial_switch }}'
        port_id: "4"
  delegate_to: localhost
'''

RETURN = r'''
data:
  description: List of aggregated links.
  returned: success
  type: complex
  contains:
      id:
          description:
            - ID of link aggregation.
          returned: success
          type: str
          sample: "MTK3M4A2ZDdfM3=="
      switch_ports:
          description:
            - List of switch ports to be included in link aggregation.
          returned: success
          type: complex
          contains:
              port_id:
                description:
                  - Port number.
                type: str
                returned: success
                sample: "1"
              serial:
                description:
                  - Serial number of switch on which port resides.
                type: str
                returned: success
                sample: "ABCD-1234-WXYZ"
'''

from ansible.module_utils.basic import AnsibleModule, json
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import MerakiModule, meraki_argument_spec


def get_lags(meraki, net_id):
    path = meraki.construct_path('get_all', net_id=net_id)
    return meraki.request(path, method='GET')


def is_lag_valid(lags, lag_id):
    for lag in lags:
        if lag['id'] == lag_id:
            return lag
    return False


def construct_payload(meraki):
    payload = dict()
    if meraki.params['switch_ports'] is not None:
        payload['switchPorts'] = []
        for port in meraki.params['switch_ports']:
            port_config = {'serial': port['serial'],
                           'portId': port['port_id'],
                           }
            payload['switchPorts'].append(port_config)
    # if meraki.params['switch_profile_ports'] is not None:
    #     payload['switchProfilePorts'] = []
    #     for port in meraki.params['switch_profile_ports']:
    #         port_config = {'profile': port['profile'],
    #                        'portId': port['port_id'],
    #                        }
    #         payload['switchProfilePorts'].append(port_config)
    return payload


def main():

    # define the available arguments/parameters that a user can pass to
    # the module

    switch_ports_args = dict(serial=dict(type='str'),
                             port_id=dict(type='str'),
                             )

    # switch_profile_ports_args = dict(profile=dict(type='str'),
    #                                  port_id=dict(type='str'),
    #                                  )

    argument_spec = meraki_argument_spec()
    argument_spec.update(state=dict(type='str', choices=['absent', 'present', 'query'], default='present'),
                         org_name=dict(type='str', aliases=['organization']),
                         org_id=dict(type='str'),
                         net_name=dict(type='str'),
                         net_id=dict(type='str'),
                         lag_id=dict(type='str'),
                         switch_ports=dict(type='list', default=None, elements='dict', options=switch_ports_args),
                         # switch_profile_ports=dict(type='list', default=None, elements='dict', options=switch_profile_ports_args),
                         )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           )
    meraki = MerakiModule(module, function='ms_link_aggregation')
    meraki.params['follow_redirects'] = 'all'

    query_urls = {'ms_link_aggregation': '/networks/{net_id}/switch/linkAggregations'}
    create_url = {'ms_link_aggregation': '/networks/{net_id}/switch/linkAggregations'}
    update_url = {'ms_link_aggregation': '/networks/{net_id}/switch/linkAggregations/{lag_id}'}
    delete_url = {'ms_link_aggregation': '/networks/{net_id}/switch/linkAggregations/{lag_id}'}

    meraki.url_catalog['get_all'].update(query_urls)
    meraki.url_catalog['create'] = create_url
    meraki.url_catalog['update'] = update_url
    meraki.url_catalog['delete'] = delete_url

    payload = None

    # execute checks for argument completeness
    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    org_id = meraki.params['org_id']
    if org_id is None:
        org_id = meraki.get_org_id(meraki.params['org_name'])
    net_id = meraki.params['net_id']
    if net_id is None:
        nets = meraki.get_nets(org_id=org_id)
        net_id = meraki.get_net_id(org_id, meraki.params['net_name'], data=nets)

    if meraki.params['state'] == 'query':
        path = meraki.construct_path('get_all', net_id=net_id)
        response = meraki.request(path, method='GET')
        meraki.result['data'] = response
        meraki.exit_json(**meraki.result)
    elif meraki.params['state'] == 'present':
        if meraki.params['lag_id'] is not None:  # Need to update
            lag = is_lag_valid(get_lags(meraki, net_id), meraki.params['lag_id'])
            if lag is not False:  # Lag ID is valid
                payload = construct_payload(meraki)
                if meraki.is_update_required(lag, payload) is True:
                    path = meraki.construct_path('update', net_id=net_id, custom={'lag_id': meraki.params['lag_id']})
                    response = meraki.request(path, method='PUT', payload=json.dumps(payload))
                    meraki.result['changed'] = True
                    meraki.result['data'] = response
                else:
                    meraki.result['data'] = lag
            else:
                meraki.fail_json("Provided lag_id is not valid.")
        else:
            path = meraki.construct_path('create', net_id=net_id)
            payload = construct_payload(meraki)
            response = meraki.request(path, method='POST', payload=json.dumps(payload))
            meraki.result['changed'] = True
            meraki.result['data'] = response
        meraki.exit_json(**meraki.result)
    elif meraki.params['state'] == 'absent':
        path = meraki.construct_path('delete', net_id=net_id, custom={'lag_id': meraki.params['lag_id']})
        response = meraki.request(path, method='DELETE')
        meraki.result['data'] = {}
        meraki.result['changed'] = True

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    meraki.exit_json(**meraki.result)


if __name__ == '__main__':
    main()
