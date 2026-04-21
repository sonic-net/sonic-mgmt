#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2019 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: failover_ip
short_description: Manage Hetzner's failover IPs
author:
  - Felix Fontein (@felixfontein)
description:
  - Manage Hetzner's failover IPs.
seealso:
  - name: Failover IP documentation
    description: Hetzner's documentation on failover IPs.
    link: https://docs.hetzner.com/robot/dedicated-server/ip/failover/
  - module: community.hrobot.failover_ip_info
    description: Retrieve information on failover IPs.
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
  failover_ip:
    description: The failover IP address.
    type: str
    required: true
  state:
    description:
      - Defines whether the IP will be routed or not.
      - If set to V(routed), O(value) must be specified.
    type: str
    choices:
      - routed
      - unrouted
    default: routed
  value:
    description:
      - The new value for the failover IP address.
      - Required when setting O(state) to V(routed).
    type: str
  timeout:
    description:
      - Timeout to use when routing or unrouting the failover IP.
      - Note that the API call returns when the failover IP has been successfully routed to the new address, respectively
        successfully unrouted.
    type: int
    default: 180
"""

EXAMPLES = r"""
---
- name: Set value of failover IP 1.2.3.4 to 5.6.7.8
  community.hrobot.failover_ip:
    hetzner_user: foo
    hetzner_password: bar
    failover_ip: 1.2.3.4
    value: 5.6.7.8

- name: Set value of failover IP 1.2.3.4 to unrouted
  community.hrobot.failover_ip:
    hetzner_user: foo
    hetzner_password: bar
    failover_ip: 1.2.3.4
    state: unrouted
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
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.hrobot.plugins.module_utils.robot import (
    ROBOT_DEFAULT_ARGUMENT_SPEC,
)
from ansible_collections.community.hrobot.plugins.module_utils.failover import (
    get_failover,
    set_failover,
    get_failover_state,
)


def main():
    argument_spec = dict(
        failover_ip=dict(type='str', required=True),
        state=dict(type='str', default='routed', choices=['routed', 'unrouted']),
        value=dict(type='str'),
        timeout=dict(type='int', default=180),
    )
    argument_spec.update(ROBOT_DEFAULT_ARGUMENT_SPEC)
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=(
            ('state', 'routed', ['value']),
        ),
    )

    failover_ip = module.params['failover_ip']
    value = get_failover(module, failover_ip)
    changed = False
    before = get_failover_state(value)

    if module.params['state'] == 'routed':
        new_value = module.params['value']
    else:
        new_value = None

    if value != new_value:
        if module.check_mode:
            value = new_value
            changed = True
        else:
            value, changed = set_failover(module, failover_ip, new_value, timeout=module.params['timeout'])

    after = get_failover_state(value)
    module.exit_json(
        changed=changed,
        diff=dict(
            before=before,
            after=after,
        ),
        **after
    )


if __name__ == '__main__':  # pragma: no cover
    main()  # pragma: no cover
