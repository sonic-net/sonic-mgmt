#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2019 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: failover_ip_info
short_description: Retrieve information on Hetzner's failover IPs
author:
  - Felix Fontein (@felixfontein)
description:
  - Retrieve information on Hetzner's failover IPs.
seealso:
  - name: Failover IP documentation
    description: Hetzner's documentation on failover IPs.
    link: https://docs.hetzner.com/robot/dedicated-server/ip/failover/
  - module: community.hrobot.failover_ip
    description: Manage failover IPs.
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
  failover_ip:
    description: The failover IP address.
    type: str
    required: true
"""

EXAMPLES = r"""
---
- name: Get value of failover IP 1.2.3.4
  community.hrobot.failover_ip_info:
    hetzner_user: foo
    hetzner_password: bar
    failover_ip: 1.2.3.4
    value: 5.6.7.8
  register: result

- name: Print value of failover IP 1.2.3.4 in case it is routed
  ansible.builtin.debug:
    msg: "1.2.3.4 routes to {{ result.value }}"
  when: result.state == 'routed'
"""

RETURN = r"""
value:
  description:
    - The value of the failover IP.
    - Will be V(none) if the IP is unrouted.
  returned: success
  type: str
state:
  description:
    - Will be V(routed) or V(unrouted).
  returned: success
  type: str
failover_ip:
  description:
    - The failover IP.
  returned: success
  type: str
  sample: '1.2.3.4'
failover_netmask:
  description:
    - The netmask for the failover IP.
  returned: success
  type: str
  sample: '255.255.255.255'
server_ip:
  description:
    - The main IP of the server this failover IP is associated to.
    - This is I(not) the server the failover IP is routed to.
  returned: success
  type: str
server_number:
  description:
    - The number of the server this failover IP is associated to.
    - This is I(not) the server the failover IP is routed to.
  returned: success
  type: int
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.hrobot.plugins.module_utils.robot import (
    ROBOT_DEFAULT_ARGUMENT_SPEC,
)
from ansible_collections.community.hrobot.plugins.module_utils.failover import (
    get_failover_record,
    get_failover_state,
)


def main():
    argument_spec = dict(
        failover_ip=dict(type='str', required=True),
    )
    argument_spec.update(ROBOT_DEFAULT_ARGUMENT_SPEC)
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    failover = get_failover_record(module, module.params['failover_ip'])
    result = get_failover_state(failover['active_server_ip'])
    result['failover_ip'] = failover['ip']
    result['failover_netmask'] = failover['netmask']
    result['server_ip'] = failover['server_ip']
    result['server_number'] = failover['server_number']
    result['changed'] = False
    module.exit_json(**result)


if __name__ == '__main__':  # pragma: no cover
    main()  # pragma: no cover
