#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2019 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: firewall
short_description: Manage Hetzner's dedicated server firewall
author:
  - Felix Fontein (@felixfontein)
description:
  - Manage Hetzner's dedicated server firewall.
  - Note that idempotency check for TCP flags simply compares strings and does not try to interpret the rules. This might
    change in the future.
requirements:
  - ipaddress
seealso:
  - name: Firewall documentation
    description: Hetzner's documentation on the stateless firewall for dedicated servers.
    link: https://docs.hetzner.com/robot/dedicated-server/firewall/
  - module: community.hrobot.firewall_info
    description: Retrieve information on firewall configuration.
extends_documentation_fragment:
  - community.hrobot.robot
  - community.hrobot.attributes
  - community.hrobot.attributes.actiongroup_robot

attributes:
  action_group:
    version_added: 1.6.0
  check_mode:
    support: full
  diff_mode:
    support: full
  idempotent:
    support: full

options:
  server_ip:
    description:
      - The server's main IP address.
      - Exactly one of O(server_ip) and O(server_number) must be specified.
      - Note that Hetzner deprecated identifying the server's firewall by the server's main IP. Using this option can thus
        stop working at any time in the future. Use O(server_number) instead.
    type: str
  server_number:
    description:
      - The server's number.
      - Exactly one of O(server_ip) and O(server_number) must be specified.
    type: int
    version_added: 1.8.0
  filter_ipv6:
    description:
      - Whether to filter IPv6 traffic as well.
      - IPv4 traffic is always filtered, IPv6 traffic filtering needs to be explicitly enabled.
    type: bool
    version_added: 1.8.0
  port:
    description:
      - Switch port of firewall.
    type: str
    choices: [main, kvm]
    default: main
  state:
    description:
      - Status of the firewall.
      - Firewall is active if state is V(present), and disabled if state is V(absent).
    type: str
    default: present
    choices: [present, absent]
  allowlist_hos:
    description:
      - Whether Hetzner services have access.
    type: bool
    aliases:
      - whitelist_hos
  rules:
    description:
      - Firewall rules.
    type: dict
    suboptions:
      input:
        description:
          - Input firewall rules.
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Name of the firewall rule.
              - Note that Hetzner restricts the characters that can be used for rule names. At the moment, only letters C(a-z),
                C(A-Z), space, and the symbols C(.), C(-), C(+), C(_), and C(@) are allowed.
            type: str
          ip_version:
            description:
              - Internet protocol version.
              - Leave away to filter both protocols. Note that in that case, none of O(rules.input[].dst_ip), O(rules.input[].src_ip),
                or O(rules.input[].protocol) can be specified.
            type: str
          dst_ip:
            description:
              - Destination IP address or subnet address.
              - CIDR notation.
            type: str
          dst_port:
            description:
              - Destination port or port range.
            type: str
          src_ip:
            description:
              - Source IP address or subnet address.
              - CIDR notation.
            type: str
          src_port:
            description:
              - Source port or port range.
            type: str
          protocol:
            description:
              - Protocol above IP layer.
            type: str
          tcp_flags:
            description:
              - TCP flags or logical combination of flags.
              - Flags supported by Hetzner are V(syn), V(fin), V(rst), V(psh) and V(urg).
              - They can be combined with V(|) (logical or) and V(&) (logical and).
              - See L(the documentation,https://wiki.hetzner.de/index.php/Robot_Firewall/en#Parameter) for more information.
            type: str
          action:
            description:
              - Action if rule matches.
            required: true
            type: str
            choices: [accept, discard]
      output:
        description:
          - Output firewall rules.
        type: list
        elements: dict
        version_added: 1.8.0
        suboptions:
          name:
            description:
              - Name of the firewall rule.
              - Note that Hetzner restricts the characters that can be used for rule names. At the moment, only letters C(a-z),
                C(A-Z), space, and the symbols C(.), C(-), C(+), C(_), and C(@) are allowed.
            type: str
          ip_version:
            description:
              - Internet protocol version.
              - Leave away to filter both protocols. Note that in that case, none of O(rules.output[].dst_ip), O(rules.output[].src_ip),
                or O(rules.output[].protocol) can be specified.
            type: str
          dst_ip:
            description:
              - Destination IP address or subnet address.
              - CIDR notation.
            type: str
          dst_port:
            description:
              - Destination port or port range.
            type: str
          src_ip:
            description:
              - Source IP address or subnet address.
              - CIDR notation.
            type: str
          src_port:
            description:
              - Source port or port range.
            type: str
          protocol:
            description:
              - Protocol above IP layer.
            type: str
          tcp_flags:
            description:
              - TCP flags or logical combination of flags.
              - Flags supported by Hetzner are V(syn), V(fin), V(rst), V(psh) and V(urg).
              - They can be combined with V(|) (logical or) and V(&) (logical and).
              - See L(the documentation,https://wiki.hetzner.de/index.php/Robot_Firewall/en#Parameter) for more information.
            type: str
          action:
            description:
              - Action if rule matches.
            required: true
            type: str
            choices: [accept, discard]
  update_timeout:
    description:
      - Timeout to use when configuring the firewall.
      - Note that the API call returns before the firewall has been successfully set up.
    type: int
    default: 30
  wait_for_configured:
    description:
      - Whether to wait until the firewall has been successfully configured before determining what to do, and before returning
        from the module.
      - The API returns status C(in progress) when the firewall is currently being configured. If this happens, the module
        will try again until the status changes to C(active) or C(disabled).
      - Please note that there is a request limit. If you have to do multiple updates, it can be better to disable waiting,
        and regularly use M(community.hrobot.firewall_info) to query status.
    type: bool
    default: true
  wait_delay:
    description:
      - Delay to wait (in seconds) before checking again whether the firewall has been configured.
    type: int
    default: 10
  timeout:
    description:
      - Timeout (in seconds) for waiting for firewall to be configured.
    type: int
    default: 180
"""

EXAMPLES = r"""
---
- name: Configure firewall for server with main IP 1.2.3.4
  community.hrobot.firewall:
    hetzner_user: foo
    hetzner_password: bar
    server_ip: 1.2.3.4
    state: present
    filter_ipv6: true
    allowlist_hos: true
    rules:
      input:
        - name: Allow ICMP protocol
          # This is needed so you can ping your server
          ip_version: ipv4
          protocol: icmp
          action: accept
          # Note that it is not possible to disable ICMP for IPv6
          # (https://robot.hetzner.com/doc/webservice/en.html#post-firewall-server-id)
        - name: Allow responses to incoming TCP connections
          protocol: tcp
          dst_port: '32768-65535'
          tcp_flags: ack
          action: accept
        - name: Allow restricted access from some known IPv4 addresses
          # Allow everything to ports 20-23 from 4.3.2.1/24 (IPv4 only)
          ip_version: ipv4
          src_ip: 4.3.2.1/24
          dst_port: '20-23'
          action: accept
        - name: Allow everything to port 443
          dst_port: '443'
          action: accept
        - name: Drop everything else
          action: discard
      output:
        - name: Accept everything
          action: accept
  register: result

- ansible.builtin.debug:
    msg: "{{ result }}"
"""

RETURN = r"""
firewall:
  description:
    - The firewall configuration.
  type: dict
  returned: success
  contains:
    port:
      description:
        - Switch port of firewall.
        - V(main) or V(kvm).
      type: str
      sample: main
    server_ip:
      description:
        - Server's main IP address.
      type: str
      sample: 1.2.3.4
    server_number:
      description:
        - Hetzner's internal server number.
      type: int
      sample: 12345
    status:
      description:
        - Status of the firewall.
        - V(active) or V(disabled).
        - Will be V(in process) if the firewall is currently updated, and O(wait_for_configured) is set to V(false) or O(timeout)
          to a too small value.
      type: str
      sample: active
    allowlist_hos:
      description:
        - Whether Hetzner services have access.
      type: bool
      sample: true
      version_added: 1.2.0
    whitelist_hos:
      description:
        - Whether Hetzner services have access.
        - Old name of return value V(allowlist_hos), will be removed eventually.
      type: bool
      sample: true
    rules:
      description:
        - Firewall rules.
      type: dict
      contains:
        input:
          description:
            - Input firewall rules.
          type: list
          elements: dict
          contains:
            name:
              description:
                - Name of the firewall rule.
              type: str
              sample: Allow HTTP access to server
            ip_version:
              description:
                - Internet protocol version.
                - No value means the rule applies both to IPv4 and IPv6.
              type: str
              sample: ipv4
            dst_ip:
              description:
                - Destination IP address or subnet address.
                - CIDR notation.
              type: str
              sample: 1.2.3.4/32
            dst_port:
              description:
                - Destination port or port range.
              type: str
              sample: "443"
            src_ip:
              description:
                - Source IP address or subnet address.
                - CIDR notation.
              type: str
              sample:
            src_port:
              description:
                - Source port or port range.
              type: str
              sample:
            protocol:
              description:
                - Protocol above IP layer.
              type: str
              sample: tcp
            tcp_flags:
              description:
                - TCP flags or logical combination of flags.
              type: str
              sample:
            action:
              description:
                - Action if rule matches.
                - V(accept) or V(discard).
              type: str
              sample: accept
              choices:
                - accept
                - discard
        output:
          description:
            - Output firewall rules.
          type: list
          elements: dict
          contains:
            name:
              description:
                - Name of the firewall rule.
              type: str
              sample: Allow HTTP access to server
            ip_version:
              description:
                - Internet protocol version.
                - No value means the rule applies both to IPv4 and IPv6.
              type: str
              sample:
            dst_ip:
              description:
                - Destination IP address or subnet address.
                - CIDR notation.
              type: str
              sample: 1.2.3.4/32
            dst_port:
              description:
                - Destination port or port range.
              type: str
              sample: "443"
            src_ip:
              description:
                - Source IP address or subnet address.
                - CIDR notation.
              type: str
              sample:
            src_port:
              description:
                - Source port or port range.
              type: str
              sample:
            protocol:
              description:
                - Protocol above IP layer.
              type: str
              sample: tcp
            tcp_flags:
              description:
                - TCP flags or logical combination of flags.
              type: str
              sample:
            action:
              description:
                - Action if rule matches.
                - V(accept) or V(discard).
              type: str
              sample: accept
              choices:
                - accept
                - discard
"""

import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible_collections.community.hrobot.plugins.module_utils.common import (
    CheckDoneTimeoutException,
)
from ansible_collections.community.hrobot.plugins.module_utils.robot import (
    ROBOT_DEFAULT_ARGUMENT_SPEC,
    BASE_URL,
    fetch_url_json,
    fetch_url_json_with_retries,
)
from ansible.module_utils.common.text.converters import to_native, to_text

try:
    import ipaddress
    HAS_IPADDRESS = True
    IPADDRESS_IMP_ERR = None
except ImportError as exc:
    IPADDRESS_IMP_ERR = traceback.format_exc()
    HAS_IPADDRESS = False

try:
    from urllib.parse import urlencode
except ImportError:
    # Python 2.x fallback:
    from urllib import urlencode


RULE_OPTION_NAMES = [
    'name', 'ip_version', 'dst_ip', 'dst_port', 'src_ip', 'src_port',
    'protocol', 'tcp_flags', 'action',
]

RULES = ['input', 'output']


def restrict_dict(dictionary, fields):
    result = dict()
    for k, v in dictionary.items():
        if k in fields:
            result[k] = v
    return result


def restrict_firewall_config(config):
    result = restrict_dict(config, ['port', 'status', 'filter_ipv6', 'whitelist_hos'])
    result['rules'] = dict()
    for ruleset in RULES:
        result['rules'][ruleset] = [
            restrict_dict(rule, RULE_OPTION_NAMES)
            for rule in config['rules'].get(ruleset) or []
        ]
    return result


def update(before, after, params, name, param_name=None):
    bv = before.get(name)
    after[name] = bv
    changed = False
    pv = params[param_name or name]
    if pv is not None:
        changed = pv != bv
        if changed:
            after[name] = pv
    return changed


def normalize_ip(ip, ip_version):
    if ip is None or ip_version is None:
        return ip
    if '/' in ip:
        ip, range = ip.split('/')
    else:
        ip, range = ip, ''  # pylint: disable=self-assigning-variable
    ip_addr = to_native(ipaddress.ip_address(to_text(ip)).compressed)
    if range == '':
        range = '32' if ip_version.lower() == 'ipv4' else '128'
    return ip_addr + '/' + range


def update_rules(before, after, params, ruleset):
    before_rules = before['rules'][ruleset]
    after_rules = after['rules'][ruleset]
    params_rules = params['rules'][ruleset]
    changed = len(before_rules) != len(params_rules)
    for no, rule in enumerate(params_rules):
        rule['src_ip'] = normalize_ip(rule['src_ip'], rule['ip_version'])
        rule['dst_ip'] = normalize_ip(rule['dst_ip'], rule['ip_version'])
        if no < len(before_rules):
            before_rule = before_rules[no]
            before_rule['src_ip'] = normalize_ip(before_rule['src_ip'], before_rule['ip_version'])
            before_rule['dst_ip'] = normalize_ip(before_rule['dst_ip'], before_rule['ip_version'])
            if before_rule != rule:
                changed = True
        after_rules.append(rule)
    return changed


def encode_rule(output, rulename, input):
    for i, rule in enumerate(input['rules'][rulename]):
        for k, v in rule.items():
            if v is not None:
                output['rules[{0}][{1}][{2}]'.format(rulename, i, k)] = v


def create_default_rules_object():
    rules = dict()
    for ruleset in RULES:
        rules[ruleset] = []
    return rules


def fix_naming(firewall_result):
    firewall_result = firewall_result.copy()
    firewall_result['allowlist_hos'] = firewall_result.get('whitelist_hos', False)
    return firewall_result


def firewall_configured(result, error):
    return result['firewall']['status'] != 'in process'


def main():
    argument_spec = dict(
        server_ip=dict(type='str'),
        server_number=dict(type='int'),
        port=dict(type='str', default='main', choices=['main', 'kvm']),
        filter_ipv6=dict(type='bool'),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        allowlist_hos=dict(type='bool', aliases=['whitelist_hos']),
        rules=dict(type='dict', options=dict(
            input=dict(type='list', elements='dict', options=dict(
                name=dict(type='str'),
                ip_version=dict(type='str'),
                dst_ip=dict(type='str'),
                dst_port=dict(type='str'),
                src_ip=dict(type='str'),
                src_port=dict(type='str'),
                protocol=dict(type='str'),
                tcp_flags=dict(type='str'),
                action=dict(type='str', required=True, choices=['accept', 'discard']),
            ), required_by=dict(dst_ip=['ip_version'], src_ip=['ip_version'], protocol=['ip_version'])),
            output=dict(type='list', elements='dict', options=dict(
                name=dict(type='str'),
                ip_version=dict(type='str'),
                dst_ip=dict(type='str'),
                dst_port=dict(type='str'),
                src_ip=dict(type='str'),
                src_port=dict(type='str'),
                protocol=dict(type='str'),
                tcp_flags=dict(type='str'),
                action=dict(type='str', required=True, choices=['accept', 'discard']),
            ), required_by=dict(dst_ip=['ip_version'], src_ip=['ip_version'], protocol=['ip_version'])),
        )),
        update_timeout=dict(type='int', default=30),
        wait_for_configured=dict(type='bool', default=True),
        wait_delay=dict(type='int', default=10),
        timeout=dict(type='int', default=180),
    )
    argument_spec.update(ROBOT_DEFAULT_ARGUMENT_SPEC)
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    if not HAS_IPADDRESS:
        module.fail_json(msg=missing_required_lib('ipaddress'), exception=IPADDRESS_IMP_ERR)

    # Sanitize input
    module.params['status'] = 'active' if (module.params['state'] == 'present') else 'disabled'
    if module.params['rules'] is None:
        module.params['rules'] = {}
    for chain in RULES:
        if module.params['rules'].get(chain) is None:
            module.params['rules'][chain] = []

    server_id = module.params['server_ip'] or module.params['server_number']

    # https://robot.your-server.de/doc/webservice/en.html#get-firewall-server-ip
    url = "{0}/firewall/{1}".format(BASE_URL, server_id)
    if module.params['wait_for_configured']:
        try:
            result, error = fetch_url_json_with_retries(
                module,
                url,
                check_done_callback=firewall_configured,
                check_done_delay=module.params['wait_delay'],
                check_done_timeout=module.params['timeout'],
            )
        except CheckDoneTimeoutException as dummy:
            module.fail_json(msg='Timeout while waiting for firewall to be configured.')
    else:
        result, error = fetch_url_json(module, url)
        if not firewall_configured(result, error):
            module.fail_json(msg='Firewall configuration cannot be read as it is not configured.')

    full_before = result['firewall']
    if not full_before.get('rules'):
        full_before['rules'] = create_default_rules_object()
    before = restrict_firewall_config(full_before)

    # Build wanted (after) state and compare
    after = dict(before)
    changed = False
    changed |= update(before, after, module.params, 'filter_ipv6')
    changed |= update(before, after, module.params, 'port')
    changed |= update(before, after, module.params, 'status')
    changed |= update(before, after, module.params, 'whitelist_hos', 'allowlist_hos')
    after['rules'] = create_default_rules_object()
    if module.params['status'] == 'active':
        for ruleset in RULES:
            changed |= update_rules(before, after, module.params, ruleset)

    # Update if different
    construct_result = True
    construct_status = None
    if changed and not module.check_mode:
        # https://robot.your-server.de/doc/webservice/en.html#post-firewall-server-ip
        url = "{0}/firewall/{1}".format(BASE_URL, server_id)
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        data = dict(after)
        data['filter_ipv6'] = str(data['filter_ipv6']).lower()
        data['whitelist_hos'] = str(data['whitelist_hos']).lower()
        del data['rules']
        for ruleset in RULES:
            encode_rule(data, ruleset, after)
        result, error = fetch_url_json(
            module,
            url,
            method='POST',
            timeout=module.params['update_timeout'],
            data=urlencode(data),
            headers=headers,
        )
        if module.params['wait_for_configured'] and not firewall_configured(result, error):
            try:
                result, error = fetch_url_json_with_retries(
                    module,
                    url,
                    check_done_callback=firewall_configured,
                    check_done_delay=module.params['wait_delay'],
                    check_done_timeout=module.params['timeout'],
                    skip_first=True,
                )
            except CheckDoneTimeoutException as e:
                result, error = e.result, e.error
                module.warn('Timeout while waiting for firewall to be configured.')

        full_after = result['firewall']
        if not full_after.get('rules'):
            full_after['rules'] = create_default_rules_object()
        construct_status = full_after['status']
        if construct_status != 'in process':
            # Only use result if configuration is done, so that diff will be ok
            after = restrict_firewall_config(full_after)
            construct_result = False

    if construct_result:
        # Construct result (used for check mode, and configuration still in process)
        full_after = dict(full_before)
        for k, v in after.items():
            if k != 'rules':
                full_after[k] = after[k]
        if construct_status is not None:
            # We want 'in process' here
            full_after['status'] = construct_status
        full_after['rules'] = dict()
        for ruleset in RULES:
            full_after['rules'][ruleset] = after['rules'][ruleset]

    module.exit_json(
        changed=changed,
        diff=dict(
            before=fix_naming(before),
            after=fix_naming(after),
        ),
        firewall=fix_naming(full_after),
    )


if __name__ == '__main__':  # pragma: no cover
    main()  # pragma: no cover
