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
module: meraki_mx_site_to_site_vpn
short_description: Manage AutoVPN connections in Meraki
version_added: "1.1.0"
description:
- Allows for creation, management, and visibility into AutoVPNs implemented on Meraki MX firewalls.
deprecated:
  removed_in: '3.0.0'
  why: Updated modules released with increased functionality
  alternative: cisco.meraki.networks_appliance_vpn_site_to_site_vpn
options:
    state:
        description:
        - Create or modify an organization.
        choices: ['present', 'query']
        default: present
        type: str
    net_name:
        description:
        - Name of network which MX firewall is in.
        type: str
    net_id:
        description:
        - ID of network which MX firewall is in.
        type: str
    mode:
        description:
        - Set VPN mode for network
        choices: ['none', 'hub', 'spoke']
        type: str
    hubs:
        description:
        - List of hubs to assign to a spoke.
        type: list
        elements: dict
        suboptions:
            hub_id:
                description:
                - Network ID of hub
                type: str
            use_default_route:
                description:
                - Indicates whether deafult troute traffic should be sent to this hub.
                - Only valid in spoke mode.
                type: bool
    subnets:
        description:
        - List of subnets to advertise over VPN.
        type: list
        elements: dict
        suboptions:
            local_subnet:
                description:
                - CIDR formatted subnet.
                type: str
            use_vpn:
                description:
                - Whether to advertise over VPN.
                type: bool
author:
- Kevin Breit (@kbreit)
extends_documentation_fragment: cisco.meraki.meraki
'''

EXAMPLES = r'''
- name: Set hub mode
  meraki_site_to_site_vpn:
    auth_key: abc123
    state: present
    org_name: YourOrg
    net_name: hub_network
    mode: hub
  delegate_to: localhost
  register: set_hub

- name: Set spoke mode
  meraki_site_to_site_vpn:
    auth_key: abc123
    state: present
    org_name: YourOrg
    net_name: spoke_network
    mode: spoke
    hubs:
      - hub_id: N_1234
        use_default_route: false
  delegate_to: localhost
  register: set_spoke

- name: Add subnet to hub for VPN. Hub is required.
  meraki_site_to_site_vpn:
    auth_key: abc123
    state: present
    org_name: YourOrg
    net_name: hub_network
    mode: hub
    hubs:
      - hub_id: N_1234
        use_default_route: false
    subnets:
      - local_subnet: 192.168.1.0/24
        use_vpn: true
  delegate_to: localhost
  register: set_hub

- name: Query rules for hub
  meraki_site_to_site_vpn:
    auth_key: abc123
    state: query
    org_name: YourOrg
    net_name: hub_network
  delegate_to: localhost
  register: query_all_hub
'''

RETURN = r'''
data:
    description: VPN settings.
    returned: success
    type: complex
    contains:
        mode:
            description: Mode assigned to network.
            returned: always
            type: str
            sample: spoke
        hubs:
            description: Hub networks to associate to.
            returned: always
            type: complex
            contains:
                hub_id:
                    description: ID of hub network.
                    returned: always
                    type: complex
                    sample: N_12345
                use_default_route:
                    description: Whether to send all default route traffic over VPN.
                    returned: always
                    type: bool
                    sample: true
        subnets:
            description: List of subnets to advertise over VPN.
            returned: always
            type: complex
            contains:
                local_subnet:
                    description: CIDR formatted subnet.
                    returned: always
                    type: str
                    sample: 192.168.1.0/24
                use_vpn:
                    description: Whether subnet should use the VPN.
                    returned: always
                    type: bool
                    sample: true
'''

from ansible.module_utils.basic import AnsibleModule, json
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import MerakiModule, meraki_argument_spec
from copy import deepcopy


def assemble_payload(meraki):
    payload = {'mode': meraki.params['mode']}
    if meraki.params['hubs'] is not None:
        payload['hubs'] = meraki.params['hubs']
        for hub in payload['hubs']:
            hub['hubId'] = hub.pop('hub_id')
            hub['useDefaultRoute'] = hub.pop('use_default_route')
    if meraki.params['subnets'] is not None:
        payload['subnets'] = meraki.params['subnets']
        for subnet in payload['subnets']:
            subnet['localSubnet'] = subnet.pop('local_subnet')
            subnet['useVpn'] = subnet.pop('use_vpn')
    return payload


def main():
    # define the available arguments/parameters that a user can pass to
    # the module

    hubs_args = dict(hub_id=dict(type='str'),
                     use_default_route=dict(type='bool'),
                     )
    subnets_args = dict(local_subnet=dict(type='str'),
                        use_vpn=dict(type='bool'),
                        )

    argument_spec = meraki_argument_spec()
    argument_spec.update(state=dict(type='str', choices=['present', 'query'], default='present'),
                         net_name=dict(type='str'),
                         net_id=dict(type='str'),
                         hubs=dict(type='list', default=None, elements='dict', options=hubs_args),
                         subnets=dict(type='list', default=None, elements='dict', options=subnets_args),
                         mode=dict(type='str', choices=['none', 'hub', 'spoke']),
                         )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           )
    meraki = MerakiModule(module, function='site_to_site_vpn')

    meraki.params['follow_redirects'] = 'all'

    query_urls = {'site_to_site_vpn': '/networks/{net_id}/appliance/vpn/siteToSiteVpn/'}
    update_urls = {'site_to_site_vpn': '/networks/{net_id}/appliance/vpn/siteToSiteVpn/'}

    meraki.url_catalog['get_all'].update(query_urls)
    meraki.url_catalog['update'] = update_urls

    payload = None

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    org_id = meraki.params['org_id']
    if org_id is None:
        orgs = meraki.get_orgs()
        for org in orgs:
            if org['name'] == meraki.params['org_name']:
                org_id = org['id']
    net_id = meraki.params['net_id']
    if net_id is None:
        net_id = meraki.get_net_id(net_name=meraki.params['net_name'],
                                   data=meraki.get_nets(org_id=org_id))

    if meraki.params['state'] == 'query':
        path = meraki.construct_path('get_all', net_id=net_id)
        response = meraki.request(path, method='GET')
        meraki.result['data'] = response
    elif meraki.params['state'] == 'present':
        path = meraki.construct_path('get_all', net_id=net_id)
        original = meraki.request(path, method='GET')
        payload = assemble_payload(meraki)
        comparable = deepcopy(original)
        comparable.update(payload)
        if meraki.is_update_required(original, payload):
            if meraki.check_mode is True:
                meraki.result['changed'] = True
                meraki.result['data'] = payload
                meraki.exit_json(**meraki.result)
            path = meraki.construct_path('update', net_id=net_id)
            response = meraki.request(path, method='PUT', payload=json.dumps(payload))
            meraki.result['changed'] = True
            meraki.result['data'] = response
        else:
            meraki.result['data'] = original

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    meraki.exit_json(**meraki.result)


if __name__ == '__main__':
    main()
