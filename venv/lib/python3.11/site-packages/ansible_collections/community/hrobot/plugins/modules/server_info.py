#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2019 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: server_info
short_description: Query information on one or more servers
version_added: 1.2.0
author:
  - Felix Fontein (@felixfontein)
description:
  - Query information on one or more servers.
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
  server_number:
    description:
      - Limit result list to server with this number.
    type: int
  server_name:
    description:
      - Limit result list to servers of this name.
    type: str
  full_info:
    description:
      - Whether to provide full information for every server.
      - Setting this to V(true) requires one REST call per server, which is slow and reduces your rate limit. Use with care.
      - When O(server_number) is specified, this option is always treated as having value V(true).
    type: bool
    default: false
"""

EXAMPLES = r"""
---
- name: Query a list of all servers
  community.hrobot.server_info:
    hetzner_user: foo
    hetzner_password: bar
  register: result

- name: Query a specific server
  community.hrobot.server_info:
    hetzner_user: foo
    hetzner_password: bar
    server_number: 23
  register: result

- name: Output data on specific server
  ansible.builtin.debug:
    msg: "Server name: {{ result.servers[0].server_name }}"
"""

RETURN = r"""
servers:
  description:
    - List of servers matching the provided options.
  returned: success
  type: list
  elements: dict
  contains:
    server_ip:
      description:
        - The server's main IP address.
      type: str
      sample: 123.123.123.123
      returned: success
    server_ipv6_net:
      description:
        - The server's main IPv6 network address.
      type: str
      sample: '2a01:f48:111:4221::'
      returned: success
    server_number:
      description:
        - The server's numeric ID.
      type: int
      sample: 321
      returned: success
    server_name:
      description:
        - The user-defined server's name.
      type: str
      sample: server1
      returned: success
    product:
      description:
        - The server product name.
      type: str
      sample: EQ 8
      returned: success
    dc:
      description:
        - The data center the server is located in.
      type: str
      sample: NBG1-DC1
      returned: success
    traffic:
      description:
        - Free traffic quota.
        - V(unlimited) in case of unlimited traffic.
      type: str
      sample: 5 TB
      returned: success
    status:
      description:
        - Server status.
      type: str
      choices:
        - ready
        - in process
      sample: ready
      returned: success
    cancelled:
      description:
        - Whether the server is cancelled.
      type: bool
      sample: false
      returned: success
    paid_until:
      description:
        - The date until the server has been paid.
      type: str
      sample: "2018-08-04"
      returned: success
    ip:
      description:
        - List of assigned single IP addresses.
      type: list
      elements: str
      sample:
        - 123.123.123.123
      returned: success
    subnet:
      description:
        - List of assigned subnets.
      type: list
      elements: dict
      sample:
        - ip: '2a01:4f8:111:4221::'
          mask: 64
      contains:
        ip:
          description:
            - The first IP in the subnet.
          type: str
          sample: '2a01:4f8:111:4221::'
        mask:
          description:
            - The masks bitlength.
          type: str
          sample: "64"
      returned: success
    reset:
      description:
        - Whether the server can be automatically reset.
      type: bool
      sample: true
      returned: when O(full_info=true)
    rescue:
      description:
        - Whether the rescue system is available.
      type: bool
      sample: false
      returned: when O(full_info=true)
    vnc:
      description:
        - Flag of VNC installation availability.
      type: bool
      sample: true
      returned: when O(full_info=true)
    windows:
      description:
        - Flag of Windows installation availability.
      type: bool
      sample: true
      returned: when O(full_info=true)
    plesk:
      description:
        - Flag of Plesk installation availability.
      type: bool
      sample: true
      returned: when O(full_info=true)
    cpanel:
      description:
        - Flag of cPanel installation availability.
      type: bool
      sample: true
      returned: when O(full_info=true)
    wol:
      description:
        - Flag of Wake On Lan availability.
      type: bool
      sample: true
      returned: when O(full_info=true)
    hot_swap:
      description:
        - Flag of Hot Swap availability.
      type: bool
      sample: true
      returned: when O(full_info=true)
    linked_storagebox:
      description:
        - Linked Storage Box ID.
      type: int
      sample: 12345
      returned: when O(full_info=true)
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.hrobot.plugins.module_utils.robot import (
    BASE_URL,
    ROBOT_DEFAULT_ARGUMENT_SPEC,
    fetch_url_json,
)


def main():
    argument_spec = dict(
        server_number=dict(type='int'),
        server_name=dict(type='str'),
        full_info=dict(type='bool', default=False),
    )
    argument_spec.update(ROBOT_DEFAULT_ARGUMENT_SPEC)
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    server_number = module.params['server_number']
    server_name = module.params['server_name']
    full_info = module.params['full_info']

    servers = []
    if server_number is not None:
        server_numbers = [server_number]
    else:
        url = "{0}/server".format(BASE_URL)
        result, error = fetch_url_json(module, url, accept_errors=['SERVER_NOT_FOUND'])
        server_numbers = []
        if not error:
            for entry in result:
                if server_name is not None:
                    if entry['server']['server_name'] != server_name:
                        continue
                if full_info:
                    server_numbers.append(entry['server']['server_number'])
                else:
                    servers.append(entry['server'])

    for server_number in server_numbers:
        url = "{0}/server/{1}".format(BASE_URL, server_number)
        result, error = fetch_url_json(module, url, accept_errors=['SERVER_NOT_FOUND'])
        if not error:
            if server_name is not None:
                if result['server']['server_name'] != server_name:
                    continue
            servers.append(result['server'])

    module.exit_json(
        changed=False,
        servers=servers,
    )


if __name__ == '__main__':  # pragma: no cover
    main()  # pragma: no cover
