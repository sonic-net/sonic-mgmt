#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2019 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: reset_info
short_description: Query information on the resetter of a dedicated server
version_added: 2.2.0
author:
  - Felix Fontein (@felixfontein)
description:
  - Query information on the resetter of a dedicated server.
seealso:
  - module: community.hrobot.reset
    description: Reset dedicated server.
extends_documentation_fragment:
  - community.hrobot.robot
  - community.hrobot.attributes
  - community.hrobot.attributes.actiongroup_robot
  - community.hrobot.attributes.idempotent_not_modify_state
  - community.hrobot.attributes.info_module

options:
  server_number:
    description:
      - The server number of the server to query its resetter.
    type: int
    required: true
"""

EXAMPLES = r"""
---
- name: Query resetter information for server 1234
  community.hrobot.reset_info:
    hetzner_user: foo
    hetzner_password: bar
    server_number: 1234
  register: result

- name: Show reset methods
  ansible.builtin.debug:
    msg: "{{ result.reset.type }}"
"""

RETURN = r"""
reset:
  description:
    - Information on the server's resetter.
  type: dict
  returned: success
  contains:
    server_ip:
      description:
        - The primary IPv4 address of the server.
      type: str
      returned: success
      sample: 123.123.123.123
    server_ipv6_net:
      description:
        - The primary IPv6 network of the server.
      type: str
      returned: success
      sample: "2a01:4f8:111:4221::"
    server_number:
      description:
        - The server's ID.
      type: int
      returned: success
      sample: 321
    type:
      description:
        - The reset types supported by the resetter.
        - "Can be used for the O(community.hrobot.reset#module:reset_type) option of the M(community.hrobot.reset) module."
      type: list
      elements: str
      returned: success
      sample: [software, hardware, manual]
      choices:
        - software
        - hardware
        - power
        - manual
    operating_status:
      description:
        - The server's operating status.
      type: str
      returned: success
      sample: not supported
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.hrobot.plugins.module_utils.robot import (
    BASE_URL,
    ROBOT_DEFAULT_ARGUMENT_SPEC,
    fetch_url_json,
)


def main():
    argument_spec = dict(
        server_number=dict(type='int', required=True),
    )
    argument_spec.update(ROBOT_DEFAULT_ARGUMENT_SPEC)
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    server_number = module.params['server_number']

    url = "{0}/reset/{1}".format(BASE_URL, server_number)
    result, error = fetch_url_json(module, url, accept_errors=['SERVER_NOT_FOUND', 'RESET_NOT_AVAILABLE'])
    if error == 'SERVER_NOT_FOUND':
        module.fail_json(msg='This server does not exist, or you do not have access rights for it')
    if error == 'RESET_NOT_AVAILABLE':
        module.fail_json(msg='The server has no reset option available')

    reset = dict(result['reset'])

    reset_types = reset.get('type')
    if isinstance(reset_types, list):
        translation = {
            'sw': 'software',
            'hw': 'hardware',
            'power': 'power',
            'man': 'manual',
        }
        reset['type'] = [translation.get(elt, elt) for elt in reset_types]

    module.exit_json(reset=reset, changed=True)


if __name__ == '__main__':  # pragma: no cover
    main()  # pragma: no cover
