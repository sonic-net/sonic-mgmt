#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2019 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: reverse_dns
short_description: Set or remove reverse DNS entry for IP
version_added: 1.2.0
author:
  - Felix Fontein (@felixfontein)
description:
  - Allows to set, update or remove a reverse DNS entry for an IP address.
extends_documentation_fragment:
  - community.hrobot.robot
  - community.hrobot.attributes
  - community.hrobot.attributes.actiongroup_robot
notes:
  - For the main IPv4 address of a server, deleting it actually sets it to a default hostname like C(static.X.Y.Z.W.clients.your-server.de).
    This substitution (delete is replaced by changing to this value) is done automatically by the API and results in the module
    not being idempotent in this case.
attributes:
  action_group:
    version_added: 1.6.0
  check_mode:
    support: full
  diff_mode:
    support: none
  idempotent:
    support: full

options:
  ip:
    description:
      - The IP address to set or remove a reverse DNS entry for.
    type: str
    required: true
  state:
    description:
      - Whether to set or update (V(present)) or delete (V(absent)) the reverse DNS entry for O(ip).
    type: str
    default: present
    choices:
      - present
      - absent
  value:
    description:
      - The reverse DNS entry for O(ip).
      - Required if O(state=present).
    type: str
"""

EXAMPLES = r"""
---
- name: Set reverse DNS entry for 1.2.3.4
  community.hrobot.reverse_dns:
    hetzner_user: foo
    hetzner_password: bar
    ip: 1.2.3.4
    value: foo.example.com

- name: Remove reverse DNS entry for 2a01:f48:111:4221::1
  community.hrobot.reverse_dns:
    hetzner_user: foo
    hetzner_password: bar
    ip: 2a01:f48:111:4221::1
    state: absent
"""

RETURN = r"""#"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.hrobot.plugins.module_utils.robot import (
    BASE_URL,
    ROBOT_DEFAULT_ARGUMENT_SPEC,
    fetch_url_json,
)

try:
    from urllib.parse import urlencode
except ImportError:
    # Python 2.x fallback:
    from urllib import urlencode


def main():
    argument_spec = dict(
        ip=dict(type='str', required=True),
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        value=dict(type='str'),
    )
    argument_spec.update(ROBOT_DEFAULT_ARGUMENT_SPEC)
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[('state', 'present', ['value'])],
    )

    ip = module.params['ip']
    state = module.params['state']
    value = module.params['value']

    url = "{0}/rdns/{1}".format(BASE_URL, ip)
    result, error = fetch_url_json(module, url, accept_errors=['IP_NOT_FOUND', 'RDNS_NOT_FOUND'])
    if error == 'RDNS_NOT_FOUND':
        current = None
    elif error:
        if error == 'IP_NOT_FOUND':
            module.fail_json(msg='The IP address was not found')
        raise AssertionError('Unexpected error {0}'.format(error))  # pragma: no cover
    else:
        current = result['rdns']['ptr']

    changed = False
    expected = value if state == 'present' else None

    if current != expected:
        changed = True
        if not module.check_mode:
            if expected is None:
                fetch_url_json(module, url, method='DELETE', allow_empty_result=True)
            else:
                headers = {'Content-type': 'application/x-www-form-urlencoded'}
                data = {'ptr': expected}
                fetch_url_json(module, url, data=urlencode(data), headers=headers, method='POST')

    module.exit_json(changed=changed)


if __name__ == '__main__':  # pragma: no cover
    main()  # pragma: no cover
