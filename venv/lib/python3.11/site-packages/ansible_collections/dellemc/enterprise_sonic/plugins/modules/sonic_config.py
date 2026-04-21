#!/usr/bin/python
#
# (c) 2024 Peter Sprygada, <psprygada@ansible.com>
# Copyright (c) 2025 Dell Inc.
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_config
version_added: 1.0.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
author: Abirami N (@abirami-n)
short_description: Manages configuration sections on devices running Enterprise SONiC
description:
  - Manages configuration sections of Enterprise SONiC Distribution
    by Dell Technologies. SONiC configurations use a simple block indent
    file syntax for segmenting configuration into sections. This module
    provides an implementation for working with SONiC configuration
    sections in a deterministic way.
options:
  lines:
    description:
      - The ordered set of commands that should be configured in the
        section. The commands must be the exact same commands as found
        in the device running-configuration. Be sure to note the configuration
        command syntax as some commands are automatically modified by the
        device configuration parser. This argument is mutually exclusive
        with I(src).
    type: list
    elements: str
    aliases: ['commands']
  parents:
    description:
      - The ordered set of parents that uniquely identify the section or hierarchy
        the commands should be checked against. If the parents argument
        is omitted, the commands are checked against the set of top
        level or global commands.
    type: list
    elements: str
  src:
    description:
      - Specifies the source path to the file that contains the configuration
        or configuration template to load. The path to the source file can
        either be the full path on the Ansible control host, or a relative
        path from the playbook or role root directory. This argument is
        mutually exclusive with I(lines).
    type: path
  before:
    description:
      - The ordered set of commands to push on to the command stack if
        a change needs to be made. This allows the playbook designer
        the opportunity to perform configuration commands prior to pushing
        any changes without affecting how the set of commands are matched
        against the system.
    type: list
    elements: str
  after:
    description:
      - The ordered set of commands to append to the end of the command
        stack if a change needs to be made. Just like with I(before), this
        allows the playbook designer to append a set of commands to be
        executed after the command set.
    type: list
    elements: str
  save:
    description:
      - The C(save) argument instructs the module to save the running-
        configuration to the startup-configuration at the conclusion of
        the module running. If check mode is specified, this argument
        is ignored.
    type: bool
    default: 'false'
  match:
    description:
      - Instructs the module on the way to perform the matching of
        the set of commands against the current device configuration.
        If match is set to I(line), commands are matched line by line.
        If match is set to I(strict), command lines are matched with respect
        to position. If match is set to I(exact), command lines
        must be an equal match. If match is set to I(none), the
        module does not attempt to compare the source configuration with
        the running-configuration on the remote device.
    type: str
    default: line
    choices: ['line', 'strict', 'exact', 'none']
  replace:
    description:
      - Instructs the module how to perform a configuration
        on the device. If the replace argument is set to I(line), then
        the modified lines are pushed to the device in configuration
        mode. If the replace argument is set to I(block), then the entire
        command block is pushed to the device in configuration mode if any
        line is not correct.
    type: str
    default: line
    choices: ['line', 'block']
  update:
    description:
      - The I(update) argument controls how the configuration statements
        are processed on the remote device. Valid choices for the I(update)
        argument are I(merge) and I(check). When you set this argument to
        I(merge), the configuration changes merge with the current
        device running-configuration. When you set this argument to I(check),
        the configuration updates are determined but not configured
        on the remote device.
    type: str
    default: merge
    choices: ['merge', 'check']
  config:
    description:
      - The module, by default, connects to the remote device and
        retrieves the current running-configuration to use as a base for
        comparing against the contents of source. There are times when
        it is not desirable to have the task get the current
        running-configuration for every task in a playbook. The I(config)
        argument allows the implementer to pass in the configuration to
        use as the base configuration for comparison.
    type: str
  backup:
    description:
      - This argument causes the module to create a full backup of
        the current C(running-configuration) from the remote device before any
        changes are made. If the C(backup_options) value is not given,
        the backup file is written to the C(backup) folder in the playbook
        root directory. If the directory does not exist, it is created.
    type: bool
    default: 'no'
  backup_options:
    description:
      - This is a dictionary object containing configurable options related to backup file path.
        The value of this option is read only when C(backup) is set to I(yes), if C(backup) is set
        to I(no) this option is ignored.
    suboptions:
      filename:
        description:
          - The filename to be used to store the backup configuration. If the filename
            is not given, it is generated based on the hostname, current time, and date
            in the format defined by <hostname>_config.<current-date>@<current-time>.
        type: str
      dir_path:
        description:
          - This option provides the path ending with directory name in which the backup
            configuration file is stored. If the directory does not exist it is first
            created, and the filename is either the value of C(filename) or default filename
            as described in C(filename) options description. If the path value is not given,
            an I(backup) directory is created in the current working directory
            and backup configuration is copied in C(filename) within the I(backup) directory.
        type: path
    type: dict
"""

EXAMPLES = """
- dellemc.enterprise_sonic.sonic_config:
    lines: ['username {{ user_name }} password {{ user_password }} role {{ user_role }}']

- dellemc.enterprise_sonic.sonic_config:
    lines:
      - description 'SONiC'
    parents: ['interface Eth1/10']

- dellemc.enterprise_sonic.sonic_config:
    lines:
      - seq 2 permit udp any any
      - seq 3 deny icmp any any
    parents: ['ip access-list test']
    before: ['no ip access-list test']
"""

RETURN = """
updates:
  description: The set of commands that is pushed to the remote device.
  returned: always
  type: list
  sample: ['username foo password foo role admin', 'router bgp 1', 'router-id 1.1.1.1']
commands:
  description: The set of commands that is pushed to the remote device.
  returned: always
  type: list
  sample: ['username foo password foo role admin', 'router bgp 1', 'router-id 1.1.1.1']
saved:
  description: Returns whether the configuration is saved to the startup
               configuration or not.
  returned: When not check_mode.
  type: bool
  sample: True
"""

from ansible.module_utils.connection import ConnectionError

from ansible.module_utils._text import to_text
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import get_config, get_sublevel_config
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import edit_config, run_commands
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import command_list_str_to_dict
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.config import NetworkConfig, dumps


def get_candidate(module):
    candidate = NetworkConfig(indent=1)
    if module.params['src']:
        candidate.load(module.params['src'])
    elif module.params['lines']:
        parents = module.params['parents'] or list()
        commands = module.params['lines'][0]
        if (isinstance(commands, dict)) and (isinstance((commands['command']), list)):
            candidate.add(commands['command'], parents=parents)
        elif (isinstance(commands, dict)) and (isinstance((commands['command']), str)):
            candidate.add([commands['command']], parents=parents)
        else:
            candidate.add(module.params['lines'], parents=parents)
    return candidate


def get_running_config(module):
    contents = module.params['config']
    if not contents:
        contents = get_config(module)
    return contents


def main():

    backup_spec = dict(
        filename=dict(),
        dir_path=dict(type='path')
    )

    argument_spec = dict(
        lines=dict(aliases=['commands'], type='list', elements="str"),
        parents=dict(type='list', elements="str"),

        src=dict(type='path'),

        before=dict(type='list', elements="str"),
        after=dict(type='list', elements="str"),
        save=dict(type='bool', default=False),
        match=dict(default='line',
                   choices=['line', 'strict', 'exact', 'none']),
        replace=dict(default='line', choices=['line', 'block']),

        update=dict(choices=['merge', 'check'], default='merge'),
        config=dict(),
        backup=dict(type='bool', default=False),
        backup_options=dict(type='dict', options=backup_spec)

    )

    mutually_exclusive = [('lines', 'src')]

    module = AnsibleModule(argument_spec=argument_spec,
                           mutually_exclusive=mutually_exclusive,
                           supports_check_mode=True)
    parents = module.params['parents'] or list()
    match = module.params['match']
    replace = module.params['replace']

    warnings = list()
#    check_args(module, warnings)

    result = dict(changed=False, saved=False, warnings=warnings)
    if module.params['backup']:
        if not module.check_mode:
            result['__backup__'] = get_config(module)

    commands = list()
    candidate = get_candidate(module)
    if any((module.params['lines'], module.params['src'])):
        if match != 'none':
            config = get_running_config(module)
            if parents:
                contents = get_sublevel_config(config, module)
                config = NetworkConfig(contents=contents, indent=1)
            else:
                config = NetworkConfig(contents=config, indent=1)
            configobjs = candidate.difference(config, match=match, replace=replace)
        else:

            configobjs = candidate.items
        if configobjs:
            commands = dumps(configobjs, 'commands')
            if ((isinstance((module.params['lines']), list)) and
                    (isinstance((module.params['lines'][0]), dict)) and
                    (set(['prompt', 'answer']).issubset(module.params['lines'][0]))):

                cmd = {'command': commands,
                       'prompt': module.params['lines'][0]['prompt'],
                       'answer': module.params['lines'][0]['answer']}
                commands = [cmd]
            else:
                commands = commands.split('\n')
                cmd_list_out = command_list_str_to_dict(module, warnings, commands)
                if cmd_list_out and cmd_list_out != []:
                    commands = cmd_list_out

            if module.params['before']:
                commands[:0] = module.params['before']

            if module.params['after']:
                commands.extend(module.params['after'])

            if not module.check_mode and module.params['update'] == 'merge':
                try:
                    edit_config(module, commands)
                except ConnectionError as exc:
                    module.fail_json(msg=to_text(exc))

            result['changed'] = True
            result['commands'] = commands
            result['updates'] = commands

    if module.params['save']:
        result['changed'] = True
        if not module.check_mode:
            cmd = {r'command': 'write memory'}
            run_commands(module, [cmd])
            result['saved'] = True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
