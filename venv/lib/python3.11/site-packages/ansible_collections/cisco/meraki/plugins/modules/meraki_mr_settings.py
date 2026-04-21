#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Kevin Breit (@kbreit) <kevin.breit@kevinbreit.net>
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
module: meraki_mr_settings
short_description: Manage general settings for Meraki wireless networks
description:
- Allows for configuration of general settings in Meraki MR wireless networks.
deprecated:
  removed_in: '3.0.0'
  why: Updated modules released with increased functionality
  alternative: cisco.meraki.networks_wireless_settings
options:
    state:
        description:
        - Query or edit wireless settings.
        type: str
        choices: [ present, query]
        default: present
    net_name:
        description:
        - Name of network.
        type: str
    net_id:
        description:
        - ID of network.
        type: str
    upgrade_strategy:
        description:
        - The upgrade strategy to apply to the network.
        - Requires firmware version MR 26.8 or higher.
        choices: [ minimize_upgrade_time, minimize_client_downtime ]
        type: str
    ipv6_bridge_enabled:
        description:
        - Toggle for enabling or disabling IPv6 bridging in a network.
        - If enabled, SSIDs must also be configured to use bridge mode.
        type: bool
    led_lights_on:
        description:
        - Toggle for enabling or disabling LED lights on all APs in the network.
        type: bool
    location_analytics_enabled:
        description:
        - Toggle for enabling or disabling location analytics for your network.
        type: bool
    meshing_enabled:
        description: Toggle for enabling or disabling meshing in a network.
        type: bool
author:
- Kevin Breit (@kbreit)
extends_documentation_fragment: cisco.meraki.meraki
'''

EXAMPLES = r'''
- name: Query all settings
  meraki_mr_settings:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    state: query
  delegate_to: localhost
- name: Configure settings
  meraki_mr_settings:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    state: present
    upgrade_strategy: minimize_upgrade_time
    ipv6_bridge_enabled: false
    led_lights_on: true
    location_analytics_enabled: true
    meshing_enabled: true
  delegate_to: localhost
'''

RETURN = r'''
data:
    description: List of wireless settings.
    returned: success
    type: complex
    contains:
        upgrade_strategy:
            description:
            - The upgrade strategy to apply to the network.
            - Requires firmware version MR 26.8 or higher.
            type: str
            returned: success
            sample: minimize_upgrade_time
        ipv6_bridge_enabled:
            description:
            - Toggle for enabling or disabling IPv6 bridging in a network.
            - If enabled, SSIDs must also be configured to use bridge mode.
            type: bool
            returned: success
            sample: true
        led_lights_on:
            description:
            - Toggle for enabling or disabling LED lights on all APs in the network.
            type: bool
            returned: success
            sample: true
        location_analytics_enabled:
            description:
            - Toggle for enabling or disabling location analytics for your network.
            type: bool
            returned: success
            sample: true
        meshing_enabled:
            description: Toggle for enabling or disabling meshing in a network.
            type: bool
            returned: success
            sample: true
'''

from ansible.module_utils.basic import AnsibleModule, json
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import MerakiModule, meraki_argument_spec
from re import sub


def convert_to_camel_case(string):
    string = sub(r"(_|-)+", " ", string).title().replace(" ", "")
    return string[0].lower() + string[1:]


def construct_payload(meraki):
    payload = {}
    if meraki.params['upgrade_strategy'] is not None:
        payload['upgradeStrategy'] = convert_to_camel_case(meraki.params['upgrade_strategy'])
    if meraki.params['ipv6_bridge_enabled'] is not None:
        payload['ipv6BridgeEnabled'] = meraki.params['ipv6_bridge_enabled']
    if meraki.params['led_lights_on'] is not None:
        payload['ledLightsOn'] = meraki.params['led_lights_on']
    if meraki.params['location_analytics_enabled'] is not None:
        payload['locationAnalyticsEnabled'] = meraki.params['location_analytics_enabled']
    if meraki.params['meshing_enabled'] is not None:
        payload['meshingEnabled'] = meraki.params['meshing_enabled']
    return payload


def main():
    # define the available arguments/parameters that a user can pass to
    # the module
    argument_spec = meraki_argument_spec()
    argument_spec.update(state=dict(type='str', choices=['present', 'query'], default='present'),
                         org_name=dict(type='str', aliases=['organization']),
                         org_id=dict(type='str'),
                         net_name=dict(type='str'),
                         net_id=dict(type='str'),
                         upgrade_strategy=dict(type='str', choices=['minimize_upgrade_time',
                                                                    'minimize_client_downtime']),
                         ipv6_bridge_enabled=dict(type='bool'),
                         led_lights_on=dict(type='bool'),
                         location_analytics_enabled=dict(type='bool'),
                         meshing_enabled=dict(type='bool'),
                         )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           )
    meraki = MerakiModule(module, function='mr_settings')

    meraki.params['follow_redirects'] = 'all'

    query_urls = {'mr_settings': '/networks/{net_id}/wireless/settings'}
    update_urls = {'mr_settings': '/networks/{net_id}/wireless/settings'}

    meraki.url_catalog['get_one'].update(query_urls)
    meraki.url_catalog['update'] = update_urls

    org_id = meraki.params['org_id']
    net_id = meraki.params['net_id']
    if org_id is None:
        org_id = meraki.get_org_id(meraki.params['org_name'])
    if net_id is None:
        nets = meraki.get_nets(org_id=org_id)
        net_id = meraki.get_net_id(org_id, meraki.params['net_name'], data=nets)

    if meraki.params['state'] == 'query':
        path = meraki.construct_path('get_one', net_id=net_id)
        response = meraki.request(path, method='GET')
        meraki.result['data'] = response
        meraki.exit_json(**meraki.result)
    elif meraki.params['state'] == 'present':
        path = meraki.construct_path('get_one', net_id=net_id)
        original = meraki.request(path, method='GET')
        payload = construct_payload(meraki)
        if meraki.is_update_required(original, payload) is True:
            if meraki.check_mode is True:
                meraki.result['data'] = payload
                meraki.result['changed'] = True
                meraki.exit_json(**meraki.result)
            path = meraki.construct_path('update', net_id=net_id)
            response = meraki.request(path, method='PUT', payload=json.dumps(payload))
            meraki.result['data'] = response
            meraki.result['changed'] = True
            meraki.exit_json(**meraki.result)
        else:
            meraki.result['data'] = original
            meraki.exit_json(**meraki.result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    meraki.exit_json(**meraki.result)


if __name__ == '__main__':
    main()
