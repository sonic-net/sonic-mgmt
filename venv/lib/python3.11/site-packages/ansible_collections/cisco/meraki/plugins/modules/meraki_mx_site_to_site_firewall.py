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
module: meraki_mx_site_to_site_firewall
short_description: Manage MX appliance firewall rules for site-to-site VPNs
version_added: "1.0.0"
description:
- Allows for creation, management, and visibility into firewall rules for site-to-site VPNs implemented on Meraki MX firewalls.
notes:
- Module assumes a complete list of firewall rules are passed as a parameter.
deprecated:
  removed_in: '3.0.0'
  why: Updated modules released with increased functionality
  alternative: cisco.meraki.organizations_appliance_vpn_vpn_firewall_rules
options:
    state:
        description:
        - Create or modify an organization.
        choices: ['present', 'query']
        default: present
        type: str
    rules:
        description:
        - List of firewall rules.
        type: list
        elements: dict
        suboptions:
            policy:
                description:
                - Policy to apply if rule is hit.
                choices: [allow, deny]
                type: str
            protocol:
                description:
                - Protocol to match against.
                choices: [any, icmp, tcp, udp]
                type: str
            dest_port:
                description:
                - Comma separated list of destination port numbers to match against.
                - C(Any) must be capitalized.
                type: str
            dest_cidr:
                description:
                - Comma separated list of CIDR notation destination networks.
                - C(Any) must be capitalized.
                type: str
            src_port:
                description:
                - Comma separated list of source port numbers to match against.
                - C(Any) must be capitalized.
                type: str
            src_cidr:
                description:
                - Comma separated list of CIDR notation source networks.
                - C(Any) must be capitalized.
                type: str
            comment:
                description:
                - Optional comment to describe the firewall rule.
                type: str
            syslog_enabled:
                description:
                - Whether to log hints against the firewall rule.
                - Only applicable if a syslog server is specified against the network.
                type: bool
                default: false
    syslog_default_rule:
        description:
        - Whether to log hits against the default firewall rule.
        - Only applicable if a syslog server is specified against the network.
        - This is not shown in response from Meraki. Instead, refer to the C(syslog_enabled) value in the default rule.
        type: bool
author:
- Kevin Breit (@kbreit)
extends_documentation_fragment: cisco.meraki.meraki
'''

EXAMPLES = r'''
- name: Query firewall rules
  meraki_mx_site_to_site_firewall:
    auth_key: abc123
    org_name: YourOrg
    state: query
  delegate_to: localhost

- name: Set two firewall rules
  meraki_mx_site_to_site_firewall:
    auth_key: abc123
    org_name: YourOrg
    state: present
    rules:
      - comment: Block traffic to server
        src_cidr: 192.0.1.0/24
        src_port: any
        dest_cidr: 192.0.2.2/32
        dest_port: any
        protocol: any
        policy: deny
      - comment: Allow traffic to group of servers
        src_cidr: 192.0.1.0/24
        src_port: any
        dest_cidr: 192.0.2.0/24
        dest_port: any
        protocol: any
        policy: permit
  delegate_to: localhost

- name: Set one firewall rule and enable logging of the default rule
  meraki_mx_site_to_site_firewall:
    auth_key: abc123
    org_name: YourOrg
    state: present
    rules:
      - comment: Block traffic to server
        src_cidr: 192.0.1.0/24
        src_port: any
        dest_cidr: 192.0.2.2/32
        dest_port: any
        protocol: any
        policy: deny
    syslog_default_rule: true
  delegate_to: localhost
'''

RETURN = r'''
data:
    description: Firewall rules associated to network.
    returned: success
    type: complex
    contains:
        rules:
            description: List of firewall rules associated to network.
            returned: success
            type: complex
            contains:
                comment:
                    description: Comment to describe the firewall rule.
                    returned: always
                    type: str
                    sample: Block traffic to server
                src_cidr:
                    description: Comma separated list of CIDR notation source networks.
                    returned: always
                    type: str
                    sample: 192.0.1.1/32,192.0.1.2/32
                src_port:
                    description: Comma separated list of source ports.
                    returned: always
                    type: str
                    sample: 80,443
                dest_cidr:
                    description: Comma separated list of CIDR notation destination networks.
                    returned: always
                    type: str
                    sample: 192.0.1.1/32,192.0.1.2/32
                dest_port:
                    description: Comma separated list of destination ports.
                    returned: always
                    type: str
                    sample: 80,443
                protocol:
                    description: Network protocol for which to match against.
                    returned: always
                    type: str
                    sample: tcp
                policy:
                    description: Action to take when rule is matched.
                    returned: always
                    type: str
                syslog_enabled:
                    description: Whether to log to syslog when rule is matched.
                    returned: always
                    type: bool
                    sample: true
'''

from ansible.module_utils.basic import AnsibleModule, json
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import MerakiModule, meraki_argument_spec


def assemble_payload(meraki):
    params_map = {'policy': 'policy',
                  'protocol': 'protocol',
                  'dest_port': 'destPort',
                  'dest_cidr': 'destCidr',
                  'src_port': 'srcPort',
                  'src_cidr': 'srcCidr',
                  'syslog_enabled': 'syslogEnabled',
                  'comment': 'comment',
                  }
    normalize_keys = ['dest_port', 'dest_cidr', 'src_port', 'src_cidr']
    rules = []
    for rule in meraki.params['rules']:
        proposed_rule = dict()
        for k, v in rule.items():
            proposed_rule[params_map[k]] = v
            if k in normalize_keys:
                if v.lower() == "any":
                    proposed_rule[params_map[k]] = "Any"
        rules.append(proposed_rule)
    payload = {'rules': rules}
    return payload


def get_rules(meraki, org_id):
    path = meraki.construct_path('get_all', org_id=org_id)
    response = meraki.request(path, method='GET')
    if meraki.status == 200:
        return response


def compare_rule_count(original, payload):
    if len(original['rules']) - 1 != len(payload['rules']):  # Quick and simple check to avoid more processing
        return True
    return False


def compare_default_rule(original, default_rule):
    if original['rules'][len(original['rules']) - 1]['syslogEnabled'] != default_rule:
        return True
    return False


def main():
    # define the available arguments/parameters that a user can pass to
    # the module

    fw_rules = dict(policy=dict(type='str', choices=['allow', 'deny']),
                    protocol=dict(type='str', choices=['tcp', 'udp', 'icmp', 'any']),
                    dest_port=dict(type='str'),
                    dest_cidr=dict(type='str'),
                    src_port=dict(type='str'),
                    src_cidr=dict(type='str'),
                    comment=dict(type='str'),
                    syslog_enabled=dict(type='bool', default=False),
                    )

    argument_spec = meraki_argument_spec()
    argument_spec.update(state=dict(type='str', choices=['present', 'query'], default='present'),
                         rules=dict(type='list', default=None, elements='dict', options=fw_rules),
                         syslog_default_rule=dict(type='bool'),
                         )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           )
    meraki = MerakiModule(module, function='mx_site_to_site_firewall')

    meraki.params['follow_redirects'] = 'all'

    query_urls = {'mx_site_to_site_firewall': '/organizations/{org_id}/appliance/vpn/vpnFirewallRules/'}
    update_urls = {'mx_site_to_site_firewall': '/organizations/{org_id}/appliance/vpn/vpnFirewallRules/'}

    meraki.url_catalog['get_all'].update(query_urls)
    meraki.url_catalog['update'] = update_urls

    payload = None

    # execute checks for argument completeness

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    org_id = meraki.params['org_id']
    orgs = None
    if org_id is None:
        orgs = meraki.get_orgs()
        for org in orgs:
            if org['name'] == meraki.params['org_name']:
                org_id = org['id']

    if meraki.params['state'] == 'query':
        meraki.result['data'] = get_rules(meraki, org_id)
    elif meraki.params['state'] == 'present':
        rules = get_rules(meraki, org_id)
        path = meraki.construct_path('get_all', org_id=org_id)
        if meraki.params['rules'] is not None:
            payload = assemble_payload(meraki)
        else:
            payload = dict()
        update = False
        if meraki.params['syslog_default_rule'] is not None:
            payload['syslogDefaultRule'] = meraki.params['syslog_default_rule']
        try:
            if meraki.params['rules'] is not None:
                update = compare_rule_count(rules, payload)
            if update is False and meraki.params['syslog_default_rule'] is not None:
                update = compare_default_rule(rules, meraki.params['syslog_default_rule'])
            if update is False:
                default_rule = rules['rules'][len(rules['rules']) - 1].copy()  # Create copy of default rule
                del rules['rules'][len(rules['rules']) - 1]  # Remove default rule for comparison
                if len(rules['rules']) - 1 == 0:
                    if meraki.is_update_required(rules['rules'][0], payload['rules'][0]) is True:
                        update = True
                else:
                    for r in range(len(rules)):
                        if meraki.is_update_required(rules['rules'][r], payload['rules'][r]) is True:
                            update = True
                rules['rules'].append(default_rule)
        except IndexError:
            pass
        if update is True:
            if meraki.check_mode is True:
                if meraki.params['rules'] is not None:
                    data = payload
                    data['rules'].append(rules['rules'][len(rules['rules']) - 1])  # Append the default rule
                    if meraki.params['syslog_default_rule'] is not None:
                        data['rules'][len(payload['rules']) - 1]['syslog_enabled'] = meraki.params['syslog_default_rule']
                else:
                    if meraki.params['syslog_default_rule'] is not None:
                        data = rules
                        data['rules'][len(data['rules']) - 1]['syslogEnabled'] = meraki.params['syslog_default_rule']
                meraki.result['data'] = data
                meraki.result['changed'] = True
                meraki.exit_json(**meraki.result)
            response = meraki.request(path, method='PUT', payload=json.dumps(payload))
            if meraki.status == 200:
                meraki.result['data'] = response
                meraki.result['changed'] = True
        else:
            meraki.result['data'] = rules

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    meraki.exit_json(**meraki.result)


if __name__ == '__main__':
    main()
