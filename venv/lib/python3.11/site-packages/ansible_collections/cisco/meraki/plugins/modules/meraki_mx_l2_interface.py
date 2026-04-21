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
module: meraki_mx_l2_interface
short_description: Configure MX layer 2 interfaces
version_added: "2.1.0"
description:
- Allows for management and visibility of Merkai MX layer 2 ports.

deprecated:
  removed_in: '3.0.0'
  why: Updated modules released with increased functionality
  alternative: cisco.meraki.networks_appliance_ports
options:
    state:
        description:
        - Modify or query an port.
        choices: [present, query]
        default: present
        type: str
    net_name:
        description:
        - Name of a network.
        aliases: [name, network]
        type: str
    net_id:
        description:
        - ID number of a network.
        type: str
    org_id:
        description:
        - ID of organization associated to a network.
        type: str
    number:
        description:
        - ID number of MX port.
        aliases: [port, port_id]
        type: int
    vlan:
        description:
        - Native VLAN when the port is in Trunk mode.
        - Access VLAN when the port is in Access mode.
        type: int
    access_policy:
        description:
        - The name of the policy. Only applicable to access ports.
        choices: [open, 8021x-radius, mac-radius, hybris-radius]
        type: str
    allowed_vlans:
        description:
        - Comma-delimited list of the VLAN ID's allowed on the port, or 'all' to permit all VLAN's on the port.
        type: str
    port_type:
        description:
        - Type of port.
        choices: [access, trunk]
        type: str
    drop_untagged_traffic:
        description:
        - Trunk port can Drop all Untagged traffic. When true, no VLAN is required.
        - Access ports cannot have dropUntaggedTraffic set to true.
        type: bool
    enabled:
        description:
        - Enabled state of port.
        type: bool

author:
    - Kevin Breit (@kbreit)
extends_documentation_fragment: cisco.meraki.meraki
'''

EXAMPLES = r'''
- name: Query layer 2 interface settings
  meraki_mx_l2_interface:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    state: query
  delegate_to: localhost

- name: Query a single layer 2 interface settings
  meraki_mx_l2_interface:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    state: query
    number: 2
  delegate_to: localhost

- name: Update interface configuration
  meraki_mx_l2_interface:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    state: present
    number: 2
    port_type: access
    vlan: 10
  delegate_to: localhost
'''

RETURN = r'''
data:
    description: Information about the created or manipulated object.
    returned: success
    type: complex
    contains:
        number:
            description:
            - ID number of MX port.
            type: int
            returned: success
            sample: 4
        vlan:
            description:
            - Native VLAN when the port is in Trunk mode.
            - Access VLAN when the port is in Access mode.
            type: int
            returned: success
            sample: 1
        access_policy:
            description:
            - The name of the policy. Only applicable to access ports.
            type: str
            returned: success
            sample: guestUsers
        allowed_vlans:
            description:
            - Comma-delimited list of the VLAN ID's allowed on the port, or 'all' to permit all VLAN's on the port.
            type: str
            returned: success
            sample: 1,5,10
        type:
            description:
            - Type of port.
            type: str
            returned: success
            sample: access
        drop_untagged_traffic:
            description:
            - Trunk port can Drop all Untagged traffic. When true, no VLAN is required.
            - Access ports cannot have dropUntaggedTraffic set to true.
            type: bool
            returned: success
            sample: true
        enabled:
            description:
            - Enabled state of port.
            type: bool
            returned: success
            sample: true
'''

from ansible.module_utils.basic import AnsibleModule, json
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import MerakiModule, meraki_argument_spec


def construct_payload(meraki):
    payload = {}
    if meraki.params['vlan'] is not None:
        payload['vlan'] = meraki.params['vlan']
    if meraki.params['access_policy'] is not None:
        payload['accessPolicy'] = meraki.params['access_policy']
    if meraki.params['allowed_vlans'] is not None:
        payload['allowedVlans'] = meraki.params['allowed_vlans']
    if meraki.params['port_type'] is not None:
        payload['type'] = meraki.params['port_type']
    if meraki.params['drop_untagged_traffic'] is not None:
        payload['dropUntaggedTraffic'] = meraki.params['drop_untagged_traffic']
    if meraki.params['enabled'] is not None:
        payload['enabled'] = meraki.params['enabled']
    return payload


def main():

    # define the available arguments/parameters that a user can pass to
    # the module

    argument_spec = meraki_argument_spec()
    argument_spec.update(
        net_id=dict(type='str'),
        net_name=dict(type='str', aliases=['name', 'network']),
        state=dict(type='str', choices=['present', 'query'], default='present'),
        number=dict(type='int', aliases=['port', 'port_id']),
        vlan=dict(type='int'),
        access_policy=dict(type='str', choices=['open', '8021x-radius', 'mac-radius', 'hybris-radius']),
        allowed_vlans=dict(type='str'),
        port_type=dict(type='str', choices=['access', 'trunk']),
        drop_untagged_traffic=dict(type='bool'),
        enabled=dict(type='bool'),
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           )

    meraki = MerakiModule(module, function='mx_l2_interface')
    module.params['follow_redirects'] = 'all'

    get_all_urls = {'mx_l2_interface': '/networks/{net_id}/appliance/ports'}
    get_one_urls = {'mx_l2_interface': '/networks/{net_id}/appliance/ports/{port_id}'}
    update_urls = {'mx_l2_interface': '/networks/{net_id}/appliance/ports/{port_id}'}
    meraki.url_catalog['query_all'] = get_all_urls
    meraki.url_catalog['query_one'] = get_one_urls
    meraki.url_catalog['update'] = update_urls

    if meraki.params['net_name'] and meraki.params['net_id']:
        meraki.fail_json(msg='net_name and net_id are mutually exclusive.')
    if meraki.params['port_type'] == 'access':
        if meraki.params['allowed_vlans'] is not None:
            meraki.meraki.fail_json(msg='allowed_vlans is mutually exclusive with port type trunk.')

    org_id = meraki.params['org_id']
    if not org_id:
        org_id = meraki.get_org_id(meraki.params['org_name'])
    net_id = meraki.params['net_id']
    if net_id is None:
        nets = meraki.get_nets(org_id=org_id)
        net_id = meraki.get_net_id(org_id, meraki.params['net_name'], data=nets)

    if meraki.params['state'] == 'query':
        if meraki.params['number'] is not None:
            path = meraki.construct_path('query_one', net_id=net_id, custom={'port_id': meraki.params['number']})
        else:
            path = meraki.construct_path('query_all', net_id=net_id)
        response = meraki.request(path, method='GET')
        meraki.result['data'] = response
        meraki.exit_json(**meraki.result)
    elif meraki.params['state'] == 'present':
        path = meraki.construct_path('query_one', net_id=net_id, custom={'port_id': meraki.params['number']})
        original = meraki.request(path, method='GET')
        payload = construct_payload(meraki)
        if meraki.is_update_required(original, payload):
            meraki.generate_diff(original, payload)
            if meraki.check_mode is True:
                original.update(payload)
                meraki.result['data'] = original
                meraki.result['changed'] = True
                meraki.exit_json(**meraki.result)
            path = meraki.construct_path('update', net_id=net_id, custom={'port_id': meraki.params['number']})
            response = meraki.request(path, method='PUT', payload=json.dumps(payload))
            if meraki.status == 200:
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
