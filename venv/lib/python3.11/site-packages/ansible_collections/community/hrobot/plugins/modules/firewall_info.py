#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2019 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: firewall_info
short_description: Manage Hetzner's dedicated server firewall
author:
  - Felix Fontein (@felixfontein)
description:
  - Manage Hetzner's dedicated server firewall.
seealso:
  - name: Firewall documentation
    description: Hetzner's documentation on the stateless firewall for dedicated servers.
    link: https://docs.hetzner.com/robot/dedicated-server/firewall/
  - module: community.hrobot.firewall
    description: Configure firewall.
extends_documentation_fragment:
  - community.hrobot.robot
  - community.hrobot.attributes
  - community.hrobot.attributes.actiongroup_robot
  - community.hrobot.attributes.idempotent_not_modify_state
  - community.hrobot.attributes.info_module

attributes:
  action_group:
    version_added: 1.6.0

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
  wait_for_configured:
    description:
      - Whether to wait until the firewall has been successfully configured before returning from the module.
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
- name: Get firewall configuration for server with main IP 1.2.3.4
  community.hrobot.firewall_info:
    hetzner_user: foo
    hetzner_password: bar
    server_ip: 1.2.3.4
  register: result

- ansible.builtin.debug:
    msg: "{{ result.firewall }}"
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
    filter_ipv6:
      description:
        - Whether the firewall rules apply to IPv6 as well or not.
      type: bool
      sample: false
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

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.hrobot.plugins.module_utils.common import (
    CheckDoneTimeoutException,
)
from ansible_collections.community.hrobot.plugins.module_utils.robot import (
    ROBOT_DEFAULT_ARGUMENT_SPEC,
    BASE_URL,
    fetch_url_json,
    fetch_url_json_with_retries,
)


def firewall_configured(result, error):
    return result['firewall']['status'] != 'in process'


def main():
    argument_spec = dict(
        server_ip=dict(type='str'),
        server_number=dict(type='int'),
        wait_for_configured=dict(type='bool', default=True),
        wait_delay=dict(type='int', default=10),
        timeout=dict(type='int', default=180),
    )
    argument_spec.update(ROBOT_DEFAULT_ARGUMENT_SPEC)
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

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

    firewall = result['firewall']
    firewall['allowlist_hos'] = firewall.get('whitelist_hos', False)
    if not firewall.get('rules'):
        firewall['rules'] = dict()
        for ruleset in ['input']:
            firewall['rules'][ruleset] = []

    module.exit_json(
        changed=False,
        firewall=firewall,
    )


if __name__ == '__main__':  # pragma: no cover
    main()  # pragma: no cover
