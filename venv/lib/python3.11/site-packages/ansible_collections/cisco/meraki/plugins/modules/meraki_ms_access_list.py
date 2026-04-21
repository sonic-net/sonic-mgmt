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
module: meraki_ms_access_list
short_description: Manage access lists for Meraki switches in the Meraki cloud
version_added: "0.1.0"
description:
- Configure and query information about access lists on Meraki switches within the Meraki cloud.
notes:
- Some of the options are likely only used for developers within Meraki.
deprecated:
  removed_in: '3.0.0'
  why: Updated modules released with increased functionality
  alternative: cisco.meraki.networks_switch_access_control_lists
options:
    state:
      description:
      - Specifies whether object should be queried, created/modified, or removed.
      choices: [absent, present, query]
      default: query
      type: str
    net_name:
      description:
      - Name of network which configuration is applied to.
      aliases: [network]
      type: str
    net_id:
      description:
      - ID of network which configuration is applied to.
      type: str
    rules:
      description:
      - List of access control rules.
      type: list
      elements: dict
      suboptions:
        comment:
            description:
            - Description of the rule.
            type: str
        policy:
            description:
            - Action to take on matching traffic.
            choices: [allow, deny]
            type: str
        ip_version:
            description:
            - Type of IP packets to match.
            choices: [any, ipv4, ipv6]
            type: str
        protocol:
            description:
            - Type of protocol to match.
            choices: [any, tcp, udp]
            type: str
        src_cidr:
            description:
            - CIDR notation of source IP address to match.
            type: str
        src_port:
            description:
            - Port number of source port to match.
            - May be a port number or 'any'.
            type: str
        dst_cidr:
            description:
            - CIDR notation of source IP address to match.
            type: str
        dst_port:
            description:
            - Port number of destination port to match.
            - May be a port number or 'any'.
            type: str
        vlan:
            description:
            - Incoming traffic VLAN.
            - May be any port between 1-4095 or 'any'.
            type: str
author:
  Kevin Breit (@kbreit)
extends_documentation_fragment: cisco.meraki.meraki
'''

EXAMPLES = r'''
- name: Set access list
  meraki_switch_access_list:
    auth_key: abc123
    state: present
    org_name: YourOrg
    net_name: YourNet
    rules:
      - comment: Fake rule
        policy: allow
        ip_version: ipv4
        protocol: udp
        src_cidr: 192.0.1.0/24
        src_port: "4242"
        dst_cidr: 1.2.3.4/32
        dst_port: "80"
        vlan: "100"
  delegate_to: localhost

- name: Query access lists
  meraki_switch_access_list:
    auth_key: abc123
    state: query
    org_name: YourOrg
    net_name: YourNet
  delegate_to: localhost
'''

RETURN = r'''
data:
    description: List of administrators.
    returned: success
    type: complex
    contains:
        rules:
          description:
          - List of access control rules.
          type: list
          contains:
            comment:
                description:
                - Description of the rule.
                type: str
                sample: User rule
                returned: success
            policy:
                description:
                - Action to take on matching traffic.
                type: str
                sample: allow
                returned: success
            ip_version:
                description:
                - Type of IP packets to match.
                type: str
                sample: ipv4
                returned: success
            protocol:
                description:
                - Type of protocol to match.
                type: str
                sample: udp
                returned: success
            src_cidr:
                description:
                - CIDR notation of source IP address to match.
                type: str
                sample: 192.0.1.0/24
                returned: success
            src_port:
                description:
                - Port number of source port to match.
                type: str
                sample: 1234
                returned: success
            dst_cidr:
                description:
                - CIDR notation of source IP address to match.
                type: str
                sample: 1.2.3.4/32
                returned: success
            dst_port:
                description:
                - Port number of destination port to match.
                type: str
                sample: 80
                returned: success
            vlan:
                description:
                - Incoming traffic VLAN.
                type: str
                sample: 100
                returned: success
'''

from ansible.module_utils.basic import AnsibleModule, json
from ansible.module_utils.common.dict_transformations import recursive_diff
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import MerakiModule, meraki_argument_spec
from copy import deepcopy


def construct_payload(params):
    payload = {'rules': []}
    for rule in params['rules']:
        new_rule = dict()
        if 'comment' in rule:
            new_rule['comment'] = rule['comment']
        if 'policy' in rule:
            new_rule['policy'] = rule['policy']
        if 'ip_version' in rule:
            new_rule['ipVersion'] = rule['ip_version']
        if 'protocol' in rule:
            new_rule['protocol'] = rule['protocol']
        if 'src_cidr' in rule:
            new_rule['srcCidr'] = rule['src_cidr']
        if 'src_port' in rule:
            try:  # Need to convert to int for comparison later
                new_rule['srcPort'] = int(rule['src_port'])
            except ValueError:
                pass
        if 'dst_cidr' in rule:
            new_rule['dstCidr'] = rule['dst_cidr']
        if 'dst_port' in rule:
            try:  # Need to convert to int for comparison later
                new_rule['dstPort'] = int(rule['dst_port'])
            except ValueError:
                pass
        if 'vlan' in rule:
            try:  # Need to convert to int for comparison later
                new_rule['vlan'] = int(rule['vlan'])
            except ValueError:
                pass
        payload['rules'].append(new_rule)
    return payload


def main():
    # define the available arguments/parameters that a user can pass to
    # the module

    rules_arg_spec = dict(comment=dict(type='str'),
                          policy=dict(type='str', choices=['allow', 'deny']),
                          ip_version=dict(type='str', choices=['ipv4', 'ipv6', 'any']),
                          protocol=dict(type='str', choices=['tcp', 'udp', 'any']),
                          src_cidr=dict(type='str'),
                          src_port=dict(type='str'),
                          dst_cidr=dict(type='str'),
                          dst_port=dict(type='str'),
                          vlan=dict(type='str'),
                          )

    argument_spec = meraki_argument_spec()
    argument_spec.update(state=dict(type='str', choices=['absent', 'present', 'query'], default='query'),
                         net_name=dict(type='str', aliases=['network']),
                         net_id=dict(type='str'),
                         rules=dict(type='list', elements='dict', options=rules_arg_spec),
                         )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           )
    meraki = MerakiModule(module, function='switch_access_list')

    meraki.params['follow_redirects'] = 'all'

    query_url = {'switch_access_list': '/networks/{net_id}/switch/accessControlLists'}
    update_url = {'switch_access_list': '/networks/{net_id}/switch/accessControlLists'}

    meraki.url_catalog['get_all'].update(query_url)
    meraki.url_catalog['update'] = update_url

    org_id = meraki.params['org_id']
    if org_id is None:
        org_id = meraki.get_org_id(meraki.params['org_name'])
    net_id = meraki.params['net_id']
    if net_id is None:
        nets = meraki.get_nets(org_id=org_id)
        net_id = meraki.get_net_id(net_name=meraki.params['net_name'], data=nets)

    if meraki.params['state'] == 'query':
        path = meraki.construct_path('get_all', net_id=net_id)
        result = meraki.request(path, method='GET')
        if meraki.status == 200:
            meraki.result['data'] = result
    elif meraki.params['state'] == 'present':
        path = meraki.construct_path('get_all', net_id=net_id)
        original = meraki.request(path, method='GET')
        payload = construct_payload(meraki.params)
        comparable = deepcopy(original)
        if len(comparable['rules']) > 1:
            del comparable['rules'][len(comparable['rules']) - 1]  # Delete the default rule for comparison
        else:
            del comparable['rules'][0]
        if meraki.is_update_required(comparable, payload):
            if meraki.check_mode is True:
                default_rule = original['rules'][len(original['rules']) - 1]
                payload['rules'].append(default_rule)
                new_rules = {'rules': payload['rules']}
                meraki.result['data'] = new_rules
                meraki.result['changed'] = True
                diff = recursive_diff(original, new_rules)
                meraki.result['diff'] = {'before': diff[0],
                                         'after': diff[1]}
                meraki.exit_json(**meraki.result)
            path = meraki.construct_path('update', net_id=net_id)
            response = meraki.request(path, method='PUT', payload=json.dumps(payload))
            if meraki.status == 200:
                diff = recursive_diff(original, payload)
                meraki.result['data'] = response
                meraki.result['changed'] = True
                meraki.result['diff'] = {'before': diff[0],
                                         'after': diff[1]}
        else:
            meraki.result['data'] = original

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    meraki.exit_json(**meraki.result)


if __name__ == '__main__':
    main()
