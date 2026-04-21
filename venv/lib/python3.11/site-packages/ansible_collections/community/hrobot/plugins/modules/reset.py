#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2019 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: reset
short_description: Reset a dedicated server
version_added: 1.2.0
author:
  - Felix Fontein (@felixfontein)
description:
  - Reset a dedicated server with a software or hardware reset, or by requesting a manual reset.
seealso:
  - module: community.hrobot.reset_info
    description: Retrieve information on resetter.
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
    support: none
  idempotent:
    support: none
    details:
      - This module performs an action on every invocation.

options:
  server_number:
    description:
      - The server number of the server to reset.
    type: int
    required: true
  reset_type:
    description:
      - How to reset the server.
      - V(software) is a software reset. This should be similar to pressing Ctrl+Alt+Del on the keyboard.
      - V(power) is a hardware reset similar to pressing the Power button. An ACPI signal is sent, and if the server is configured
        correctly, this will trigger a regular shutdown.
      - V(hardware) is a hardware reset similar to pressing the Restart button. The power is cycled for the server.
      - V(manual) is a manual reset. This requests a technician to manually do the shutdown while looking at the screen output.
        B(Be careful) and only use this when really necessary!
      - "Note that not every server supports every reset method! You can query the supported reset methods by using the
         RV(community.hrobot.reset_info#module:reset.type) return value of the M(community.hrobot.reset_info) module."
    type: str
    required: true
    choices:
      - software
      - hardware
      - power
      - manual
"""

EXAMPLES = r"""
---
- name: Send ACPI signal to server to request controlled shutdown
  community.hrobot.reset:
    hetzner_user: foo
    hetzner_password: bar
    server_number: 1234
    state: power

- name: Make sure that the server supports manual reset
  community.hrobot.reset:
    hetzner_user: foo
    hetzner_password: bar
    server_number: 1234
    reset_type: manual
  check_mode: true

- name: Request a manual reset (by a technican)
  community.hrobot.reset:
    hetzner_user: foo
    hetzner_password: bar
    server_number: 1234
    reset_type: manual
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
        server_number=dict(type='int', required=True),
        reset_type=dict(type='str', required=True, choices=['software', 'hardware', 'power', 'manual']),
    )
    argument_spec.update(ROBOT_DEFAULT_ARGUMENT_SPEC)
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    server_number = module.params['server_number']
    reset_type = {
        'software': 'sw',
        'hardware': 'hw',
        'power': 'power',
        'manual': 'man',
    }[module.params['reset_type']]

    if module.check_mode:
        url = "{0}/reset/{1}".format(BASE_URL, server_number)
        result, error = fetch_url_json(module, url, accept_errors=['SERVER_NOT_FOUND', 'RESET_NOT_AVAILABLE'])
        if not error and reset_type not in result['reset']['type']:
            module.fail_json(msg='The chosen reset method is not supported for this server')
    else:
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        data = dict(
            type=reset_type,
        )
        url = "{0}/reset/{1}".format(BASE_URL, server_number)
        result, error = fetch_url_json(
            module,
            url,
            data=urlencode(data),
            headers=headers,
            method='POST',
            accept_errors=['INVALID_INPUT', 'SERVER_NOT_FOUND', 'RESET_NOT_AVAILABLE', 'RESET_MANUAL_ACTIVE', 'RESET_FAILED'],
        )
        if error and error == 'INVALID_INPUT':
            module.fail_json(msg='The chosen reset method is not supported for this server')
    if error:
        if error == 'SERVER_NOT_FOUND':
            module.fail_json(msg='This server does not exist, or you do not have access rights for it')
        if error == 'RESET_NOT_AVAILABLE':
            module.fail_json(msg='The server has no reset option available')
        if error == 'RESET_MANUAL_ACTIVE':
            module.fail_json(msg='A manual reset is already running')
        if error == 'RESET_FAILED':
            module.fail_json(msg='The reset failed due to an internal error at Hetzner')
        raise AssertionError('Unexpected error {0}'.format(error))  # pragma: no cover

    module.exit_json(changed=True)


if __name__ == '__main__':  # pragma: no cover
    main()  # pragma: no cover
