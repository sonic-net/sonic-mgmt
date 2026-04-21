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
module: meraki_ms_l3_interface
short_description: Manage routed interfaces on MS switches
description:
- Allows for creation, management, and visibility into routed interfaces on Meraki MS switches.
notes:
- Once a layer 3 interface is created, the API does not allow updating the interface and specifying C(default_gateway).
deprecated:
  removed_in: '3.0.0'
  why: Updated modules released with increased functionality
  alternative: cisco.meraki.devices_switch_routing_interfaces
options:
    state:
        description:
        - Create or modify an organization.
        type: str
        choices: [ present, query, absent ]
        default: present
    serial:
        description:
        - Serial number of MS switch hosting the layer 3 interface.
        type: str
    vlan_id:
        description:
        - The VLAN this routed interface is on.
        - VLAN must be between 1 and 4094.
        type: int
    default_gateway:
        description:
        - The next hop for any traffic that isn't going to a directly connected subnet or over a static route.
        - This IP address must exist in a subnet with a routed interface.
        type: str
    interface_ip:
        description:
        - The IP address this switch will use for layer 3 routing on this VLAN or subnet.
        - This cannot be the same as the switch's management IP.
        type: str
    interface_id:
        description:
        - Uniqiue identification number for layer 3 interface.
        type: str
    multicast_routing:
        description:
        - Enable multicast support if multicast routing between VLANs is required.
        type: str
        choices: [disabled, enabled, IGMP snooping querier]
    name:
        description:
        - A friendly name or description for the interface or VLAN.
        type: str
    subnet:
        description:
        - The network that this routed interface is on, in CIDR notation.
        type: str
    ospf_settings:
        description:
        - The OSPF routing settings of the interface.
        type: dict
        suboptions:
            cost:
                description:
                - The path cost for this interface.
                type: int
            area:
                description:
                - The OSPF area to which this interface should belong.
                - Can be either 'disabled' or the identifier of an existing OSPF area.
                type: str
            is_passive_enabled:
                description:
                - When enabled, OSPF will not run on the interface, but the subnet will still be advertised.
                type: bool
author:
- Kevin Breit (@kbreit)
extends_documentation_fragment: cisco.meraki.meraki
'''

EXAMPLES = r'''
- name: Query all l3 interfaces
  meraki_ms_l3_interface:
    auth_key: abc123
    state: query
    serial: aaa-bbb-ccc

- name: Query one l3 interface
  meraki_ms_l3_interface:
    auth_key: abc123
    state: query
    serial: aaa-bbb-ccc
    name: Test L3 interface

- name: Create l3 interface
  meraki_ms_l3_interface:
    auth_key: abc123
    state: present
    serial: aaa-bbb-ccc
    name: "Test L3 interface 2"
    subnet: "192.168.3.0/24"
    interface_ip: "192.168.3.2"
    multicast_routing: disabled
    vlan_id: 11
    ospf_settings:
      area: 0
      cost: 1
      is_passive_enabled: true

- name: Update l3 interface
  meraki_ms_l3_interface:
    auth_key: abc123
    state: present
    serial: aaa-bbb-ccc
    name: "Test L3 interface 2"
    subnet: "192.168.3.0/24"
    interface_ip: "192.168.3.2"
    multicast_routing: disabled
    vlan_id: 11
    ospf_settings:
      area: 0
      cost: 2
      is_passive_enabled: true

- name: Delete l3 interface
  meraki_ms_l3_interface:
    auth_key: abc123
    state: absent
    serial: aaa-bbb-ccc
    interface_id: abc123344566
'''

RETURN = r'''
data:
    description: Information about the layer 3 interfaces.
    returned: success
    type: complex
    contains:
        vlan_id:
            description: The VLAN this routed interface is on.
            returned: success
            type: int
            sample: 10
        default_gateway:
            description: The next hop for any traffic that isn't going to a directly connected subnet or over a static route.
            returned: success
            type: str
            sample: 192.168.2.1
        interface_ip:
            description: The IP address this switch will use for layer 3 routing on this VLAN or subnet.
            returned: success
            type: str
            sample: 192.168.2.2
        interface_id:
            description: Uniqiue identification number for layer 3 interface.
            returned: success
            type: str
            sample: 62487444811111120
        multicast_routing:
            description: Enable multicast support if multicast routing between VLANs is required.
            returned: success
            type: str
            sample: disabled
        name:
            description: A friendly name or description for the interface or VLAN.
            returned: success
            type: str
            sample: L3 interface
        subnet:
            description: The network that this routed interface is on, in CIDR notation.
            returned: success
            type: str
            sample: 192.168.2.0/24
        ospf_settings:
            description: The OSPF routing settings of the interface.
            returned: success
            type: complex
            contains:
                cost:
                    description: The path cost for this interface.
                    returned: success
                    type: int
                    sample: 1
                area:
                    description: The OSPF area to which this interface should belong.
                    returned: success
                    type: str
                    sample: 0
                is_passive_enabled:
                    description: When enabled, OSPF will not run on the interface, but the subnet will still be advertised.
                    returned: success
                    type: bool
                    sample: true
'''

from ansible.module_utils.basic import AnsibleModule, json
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import MerakiModule, meraki_argument_spec


def construct_payload(meraki):
    payload = {}
    if meraki.params['name'] is not None:
        payload['name'] = meraki.params['name']
    if meraki.params['subnet'] is not None:
        payload['subnet'] = meraki.params['subnet']
    if meraki.params['interface_ip'] is not None:
        payload['interfaceIp'] = meraki.params['interface_ip']
    if meraki.params['multicast_routing'] is not None:
        payload['multicastRouting'] = meraki.params['multicast_routing']
    if meraki.params['vlan_id'] is not None:
        payload['vlanId'] = meraki.params['vlan_id']
    if meraki.params['default_gateway'] is not None:
        payload['defaultGateway'] = meraki.params['default_gateway']
    if meraki.params['ospf_settings'] is not None:
        payload['ospfSettings'] = {}
        if meraki.params['ospf_settings']['area'] is not None:
            payload['ospfSettings']['area'] = meraki.params['ospf_settings']['area']
        if meraki.params['ospf_settings']['cost'] is not None:
            payload['ospfSettings']['cost'] = meraki.params['ospf_settings']['cost']
        if meraki.params['ospf_settings']['is_passive_enabled'] is not None:
            payload['ospfSettings']['isPassiveEnabled'] = meraki.params['ospf_settings']['is_passive_enabled']
    return payload


def get_interface_id(meraki, data, name):
    # meraki.fail_json(msg=data)
    for interface in data:
        if interface['name'] == name:
            return interface['interfaceId']
    return None


def get_interface(interfaces, interface_id):
    for interface in interfaces:
        if interface['interfaceId'] == interface_id:
            return interface
    return None


def main():
    # define the available arguments/parameters that a user can pass to
    # the module

    ospf_arg_spec = dict(area=dict(type='str'),
                         cost=dict(type='int'),
                         is_passive_enabled=dict(type='bool'),
                         )

    argument_spec = meraki_argument_spec()
    argument_spec.update(state=dict(type='str', choices=['present', 'query', 'absent'], default='present'),
                         serial=dict(type='str'),
                         name=dict(type='str'),
                         subnet=dict(type='str'),
                         interface_id=dict(type='str'),
                         interface_ip=dict(type='str'),
                         multicast_routing=dict(type='str', choices=['disabled', 'enabled', 'IGMP snooping querier']),
                         vlan_id=dict(type='int'),
                         default_gateway=dict(type='str'),
                         ospf_settings=dict(type='dict', default=None, options=ospf_arg_spec),
                         )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           )
    meraki = MerakiModule(module, function='ms_l3_interfaces')

    meraki.params['follow_redirects'] = 'all'

    query_urls = {'ms_l3_interfaces': '/devices/{serial}/switch/routing/interfaces'}
    query_one_urls = {'ms_l3_interfaces': '/devices/{serial}/switch/routing/interfaces'}
    create_urls = {'ms_l3_interfaces': '/devices/{serial}/switch/routing/interfaces'}
    update_urls = {'ms_l3_interfaces': '/devices/{serial}/switch/routing/interfaces/{interface_id}'}
    delete_urls = {'ms_l3_interfaces': '/devices/{serial}/switch/routing/interfaces/{interface_id}'}

    meraki.url_catalog['get_all'].update(query_urls)
    meraki.url_catalog['get_one'].update(query_one_urls)
    meraki.url_catalog['create'] = create_urls
    meraki.url_catalog['update'] = update_urls
    meraki.url_catalog['delete'] = delete_urls

    payload = None

    if meraki.params['vlan_id'] is not None:
        if meraki.params['vlan_id'] < 1 or meraki.params['vlan_id'] > 4094:
            meraki.fail_json(msg='vlan_id must be between 1 and 4094')

    interface_id = meraki.params['interface_id']
    interfaces = None
    if interface_id is None:
        if meraki.params['name'] is not None:
            path = meraki.construct_path('get_all', custom={'serial': meraki.params['serial']})
            interfaces = meraki.request(path, method='GET')
            interface_id = get_interface_id(meraki, interfaces, meraki.params['name'])

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)

    if meraki.params['state'] == 'query':
        if interface_id is not None:  # Query one interface
            path = meraki.construct_path('get_one', custom={'serial': meraki.params['serial'],
                                                            'interface_id': interface_id})
            response = meraki.request(path, method='GET')
            meraki.result['data'] = response
            meraki.exit_json(**meraki.result)
        else:  # Query all interfaces
            path = meraki.construct_path('get_all', custom={'serial': meraki.params['serial']})
            response = meraki.request(path, method='GET')
            meraki.result['data'] = response
            meraki.exit_json(**meraki.result)
    elif meraki.params['state'] == 'present':
        if interface_id is None:  # Create a new interface
            payload = construct_payload(meraki)
            if meraki.check_mode is True:
                meraki.result['data'] = payload
                meraki.result['changed'] = True
                meraki.exit_json(**meraki.result)
            path = meraki.construct_path('create', custom={'serial': meraki.params['serial']})
            response = meraki.request(path, method='POST', payload=json.dumps(payload))
            meraki.result['data'] = response
            meraki.result['changed'] = True
            meraki.exit_json(**meraki.result)
        else:
            if interfaces is None:
                path = meraki.construct_path('get_all', custom={'serial': meraki.params['serial']})
                interfaces = meraki.request(path, method='GET')
            payload = construct_payload(meraki)
            interface = get_interface(interfaces, interface_id)
            if meraki.is_update_required(interface, payload):
                if meraki.check_mode is True:
                    interface.update(payload)
                    meraki.result['data'] = interface
                    meraki.result['changed'] = True
                    meraki.exit_json(**meraki.result)
                path = meraki.construct_path('update', custom={'serial': meraki.params['serial'],
                                                               'interface_id': interface_id})
                response = meraki.request(path, method='PUT', payload=json.dumps(payload))
                meraki.result['data'] = response
                meraki.result['changed'] = True
                meraki.exit_json(**meraki.result)
            else:
                meraki.result['data'] = interface
                meraki.exit_json(**meraki.result)
    elif meraki.params['state'] == 'absent':
        if meraki.check_mode is True:
            meraki.result['data'] = {}
            meraki.result['changed'] = True
            meraki.exit_json(**meraki.result)
        path = meraki.construct_path('delete', custom={'serial': meraki.params['serial'],
                                                       'interface_id': meraki.params['interface_id']})
        response = meraki.request(path, method='DELETE')
        meraki.result['data'] = response
        meraki.result['changed'] = True

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    meraki.exit_json(**meraki.result)


if __name__ == '__main__':
    main()
