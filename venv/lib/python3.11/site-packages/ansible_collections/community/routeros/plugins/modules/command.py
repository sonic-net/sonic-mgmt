#!/usr/bin/python

# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: command
author: "Egor Zaitsev (@heuels)"
short_description: Run commands on remote devices running MikroTik RouterOS
description:
  - Sends arbitrary commands to an RouterOS node and returns the results read from the device. This module includes an argument
    that will cause the module to wait for a specific condition before returning or timing out if the condition is not met.
  - The module always indicates a (changed) status. You can use R(the changed_when task property,override_the_changed_result)
    to determine whether a command task actually resulted in a change or not.
extends_documentation_fragment:
  - community.routeros.attributes
attributes:
  check_mode:
    support: none
    details:
      - Before community.routeros 3.0.0, the module claimed to support check mode. It simply executed the command in check
        mode.
  diff_mode:
    support: none
  platform:
    support: full
    platforms: RouterOS
  idempotent:
    support: N/A
    details:
      - Whether the executed command is idempotent depends on the command.
options:
  commands:
    description:
      - List of commands to send to the remote RouterOS device over the configured provider. The resulting output from the
        command is returned. If the O(wait_for) argument is provided, the module is not returned until the condition is satisfied
        or the number of retries has expired.
    required: true
    type: list
    elements: str
  wait_for:
    description:
      - List of conditions to evaluate against the output of the command. The task will wait for each condition to be true
        before moving forward. If the conditional is not true within the configured number of retries, the task fails. See
        examples.
    type: list
    elements: str
  match:
    description:
      - The O(match) argument is used in conjunction with the O(wait_for) argument to specify the match policy. Valid values
        are V(all) or V(any). If the value is set to V(all) then all conditionals in the wait_for must be satisfied. If the
        value is set to V(any) then only one of the values must be satisfied.
    default: all
    choices: ['any', 'all']
    type: str
  retries:
    description:
      - Specifies the number of retries a command should by tried before it is considered failed. The command is run on the
        target device every retry and evaluated against the O(wait_for) conditions.
    default: 10
    type: int
  interval:
    description:
      - Configures the interval in seconds to wait between retries of the command. If the command does not pass the specified
        conditions, the interval indicates how long to wait before trying the command again.
    default: 1
    type: int
seealso:
  - ref: ansible_collections.community.routeros.docsite.ssh-guide
    description: How to connect to RouterOS devices with SSH.
  - ref: ansible_collections.community.routeros.docsite.quoting
    description: How to quote and unquote commands and arguments.
"""

EXAMPLES = r"""
---
- name: Run command on remote devices
  community.routeros.command:
    commands: /system routerboard print

- name: Run command and check to see if output contains routeros
  community.routeros.command:
    commands: /system resource print
    wait_for: result[0] contains MikroTik

- name: Run multiple commands on remote nodes
  community.routeros.command:
    commands:
      - /system routerboard print
      - /system identity print

- name: Run multiple commands and evaluate the output
  community.routeros.command:
    commands:
      - /system routerboard print
      - /interface ethernet print
    wait_for:
      - result[0] contains x86
      - result[1] contains ether1
"""

RETURN = r"""
stdout:
  description: The set of responses from the commands.
  returned: always apart from low level errors (such as action plugin)
  type: list
  sample: ['...', '...']
stdout_lines:
  description: The value of stdout split into a list.
  returned: always apart from low level errors (such as action plugin)
  type: list
  sample: [['...', '...'], ['...'], ['...']]
failed_conditions:
  description: The list of conditionals that have failed.
  returned: failed
  type: list
  sample: ['...', '...']
"""

import sys
import time

from ansible_collections.community.routeros.plugins.module_utils.routeros import run_commands
from ansible_collections.community.routeros.plugins.module_utils.routeros import routeros_argument_spec
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.parsing import Conditional

if sys.version_info[0] == 2:
    string_types = (basestring,)  # noqa: F821, pylint: disable=undefined-variable
else:
    string_types = (str,)


def to_lines(stdout):
    for item in stdout:
        if isinstance(item, string_types):
            item = str(item).split('\n')
        yield item


def main():
    """main entry point for module execution
    """
    argument_spec = dict(
        commands=dict(type='list', elements='str', required=True),

        wait_for=dict(type='list', elements='str'),
        match=dict(type='str', default='all', choices=['all', 'any']),

        retries=dict(default=10, type='int'),
        interval=dict(default=1, type='int')
    )

    argument_spec.update(routeros_argument_spec)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=False)

    result = {'changed': False}

    wait_for = module.params['wait_for'] or list()
    conditionals = [Conditional(c) for c in wait_for]

    retries = module.params['retries']
    interval = module.params['interval']
    match = module.params['match']

    while retries > 0:
        responses = run_commands(module, module.params['commands'])

        for item in list(conditionals):
            if item(responses):
                if match == 'any':
                    conditionals = list()
                    break
                conditionals.remove(item)

        if not conditionals:
            break

        time.sleep(interval)
        retries -= 1

    if conditionals:
        failed_conditions = [item.raw for item in conditionals]
        msg = 'One or more conditional statements have not been satisfied'
        module.fail_json(msg=msg, failed_conditions=failed_conditions)

    result.update({
        'changed': True,
        'stdout': responses,
        'stdout_lines': list(to_lines(responses))
    })

    module.exit_json(**result)


if __name__ == '__main__':
    main()
