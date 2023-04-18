#!/usr/bin/python
#

from ansible.module_utils.aos.aos import check_args
from ansible.module_utils.aos.aos import aos_argument_spec
from ansible.module_utils.aos.aos import run_commands
from ansible.module_utils.aos.aos import get_config, load_config, get_connection
from ansible.module_utils.network.common.config import NetworkConfig, dumps
from ansible.module_utils.connection import ConnectionError
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text
ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
---
module: aos_config
short_description: Manage AOS configuration sections
description:
  - AOS configurations use a simple block indent file syntax
    for segmenting configuration into sections.  This module provides
    an implementation for working with AOS configuration sections in
    a deterministic way.
notes:
  - Tested against AOS 1.2.176.164
  - Abbreviated commands are NOT idempotent, see
    L(Network FAQ,../network/user_guide/faq.html#why-do-the-config-modules-always-return-changed-true-with-abbreviated-commands).   # noqa E501
options:
  lines:
    description:
      - The ordered set of commands that should be configured in the
        section.  The commands must be the exact same commands as found
        in the device running-config.  Be sure to note the configuration
        command syntax as some commands are automatically modified by the
        device config parser.
    aliases: ['commands']
  parents:
    description:
      - The ordered set of parents that uniquely identify the section or hierarchy
        the commands should be checked against.  If the parents argument
        is omitted, the commands are checked against the set of top
        level or global commands.
  src:
    description:
      - The I(src) argument provides a path to the configuration file
        to load into the remote system.  The path can either be a full
        system path to the configuration file if the value starts with /
        or relative to the root of the implemented role or playbook.
        This argument is mutually exclusive with the I(lines) and
        I(parents) arguments. It can be a Jinja2 template as well.
        src file must have same indentation as a live switch config.
        AOS device config has 1 spaces indentation.
  before:
    description:
      - The ordered set of commands to push on to the command stack if
        a change needs to be made.  This allows the playbook designer
        the opportunity to perform configuration commands prior to pushing
        any changes without affecting how the set of commands are matched
        against the system.
  after:
    description:
      - The ordered set of commands to append to the end of the command
        stack if a change needs to be made.  Just like with I(before) this
        allows the playbook designer to append a set of commands to be
        executed after the command set.
  match:
    description:
      - Instructs the module on the way to perform the matching of
        the set of commands against the current device config.  If
        match is set to I(line), commands are matched line by line.  If
        match is set to I(strict), command lines are matched with respect
        to position.  If match is set to I(exact), command lines
        must be an equal match.  Finally, if match is set to I(none), the
        module will not attempt to compare the source configuration with
        the running configuration on the remote device.
    default: line
    choices: ['line', 'strict', 'exact', 'none']
  replace:
    description:
      - Instructs the module on the way to perform the configuration
        on the device.  If the replace argument is set to I(line) then
        the modified lines are pushed to the device in configuration
        mode.  If the replace argument is set to I(block) then the entire
        command block is pushed to the device in configuration mode if any
        line is not correct.
    default: line
    choices: ['line', 'block', 'config']
  backup:
    description:
      - This argument will cause the module to create a full backup of
        the current C(running-config) from the remote device before any
        changes are made. If the C(backup_options) value is not given,
        the backup file is written to the C(backup) folder in the playbook
        root directory or role root directory, if playbook is part of an
        ansible role. If the directory does not exist, it is created.
    type: bool
    default: 'no'
  running_config:
    description:
      - The module, by default, will connect to the remote device and
        retrieve the current running-config to use as a base for comparing
        against the contents of source.  There are times when it is not
        desirable to have the task get the current running-config for
        every task in a playbook.  The I(running_config) argument allows the
        implementer to pass in the configuration to use as the base
        config for this module.
    type: str
    aliases: ['config']
  defaults:
    description:
      - The I(defaults) argument will influence how the running-config
        is collected from the device.  When the value is set to true,
        the command used to collect the running-config is append with
        the all keyword.  When the value is set to false, the command
        is issued without the all keyword
    type: bool
    default: 'no'
  save_when:
    description:
      - When changes are made to the device running-configuration, the
        changes are not copied to non-volatile storage by default.  Using
        this argument will change that before.  If the argument is set to
        I(always), then the running-config will always be copied to the
        startup-config and the I(modified) flag will always be set to
        True.  If the argument is set to I(modified), then the running-config
        will only be copied to the startup-config if it has changed since
        the last save to startup-config.  If the argument is set to
        I(never), the running-config will never be copied to the
        startup-config. If the argument is set to I(changed), then the running-config
        will only be copied to the startup-config if the task has made a change.
        I(changed) was added in Ansible 2.5.
    default: never
    choices: ['always', 'never', 'modified', 'changed']
  diff_against:
    description:
      - When using the C(ansible-playbook --diff) command line argument
        the module can generate diffs against different sources.
      - When this option is configure as I(startup), the module will return
        the diff of the running-config against the startup-config.
      - When this option is configured as I(intended), the module will
        return the diff of the running-config against the configuration
        provided in the C(intended_config) argument.
      - When this option is configured as I(running), the module will
        return the before and after diff of the running-config with respect
        to any changes made to the device configuration.
    default: startup
    choices: ['startup', 'running', 'intended']
  diff_ignore_lines:
    description:
      - Use this argument to specify one or more lines that should be
        ignored during the diff.  This is used for lines in the configuration
        that are automatically updated by the system.  This argument takes
        a list of regular expressions or exact line matches.
  intended_config:
    description:
      - The C(intended_config) provides the master configuration that
        the node should conform to and is used to check the final
        running-config against.   This argument will not modify any settings
        on the remote device and is strictly used to check the compliance
        of the current device's configuration against.  When specifying this
        argument, the task should also modify the C(diff_against) value and
        set it to I(intended).
    type: str
  backup_options:
    description:
      - This is a dict object containing configurable options related to backup file path.
        The value of this option is read only when C(backup) is set to I(yes), if C(backup) is set
        to I(no) this option will be silently ignored.
    suboptions:
      filename:
        description:
          - The filename to be used to store the backup configuration. If the the filename
            is not given it will be generated based on the hostname, current time and date
            in format defined by <hostname>_config.<current-date>@<current-time>
      dir_path:
        description:
          - This option provides the path ending with directory name in which the backup
            configuration file will be stored. If the directory does not exist it will be first
            created and the filename is either the value of C(filename) or default filename
            as described in C(filename) options description. If the path value is not given
            in that case a I(backup) directory will be created in the current working directory
            and backup configuration will be copied in C(filename) within I(backup) directory.
        type: path
    type: dict
"""

EXAMPLES = """
- name: configure top level settings
  aos_config:
    lines: hostname {{ inventory_hostname }}

- name: load an acl into the device
  aos_config:
    lines:
      - 10 permit ip host 192.0.2.1 any log
      - 20 permit ip host 192.0.2.2 any log
    parents: ip access-list test
    before: no ip access-list test
    replace: block

- name: load configuration from file
  aos_config:
    src: aos.cfg

- name: render a Jinja2 template onto a switch
  aos_config:
    backup: yes
    src: aos_template.j2

- name: diff the running config against a master config
  aos_config:
    diff_against: intended
    intended_config: "{{ lookup('file', 'master.cfg') }}"

- name: for idempotency, use full-form commands
  aos_config:
    lines:
      # - shut
      - shutdown
    # parents: int eth1
    parents: interface Ethernet1

- name: configurable backup path
  aos_config:
    src: aos_template.j2
    backup: yes
    backup_options:
      filename: backup.cfg
      dir_path: /home/user
"""

RETURN = """
commands:
  description: The set of commands that will be pushed to the remote device
  returned: always
  type: list
  sample: ['hostname switch01', 'interface Ethernet1', 'no shutdown']
updates:
  description: The set of commands that will be pushed to the remote device
  returned: always
  type: list
  sample: ['hostname switch01', 'interface Ethernet1', 'no shutdown']
backup_path:
  description: The full path to the backup file
  returned: when backup is yes
  type: str
  sample: /playbooks/ansible/backup/aos_config.2016-07-16@22:28:34
filename:
  description: The name of the backup file
  returned: when backup is yes and filename is not specified in backup options
  type: str
  sample: aos_config.2016-07-16@22:28:34
shortname:
  description: The full path to the backup file excluding the timestamp
  returned: when backup is yes and filename is not specified in backup options
  type: str
  sample: /playbooks/ansible/backup/aos_config
date:
  description: The date extracted from the backup file name
  returned: when backup is yes
  type: str
  sample: "2016-07-16"
time:
  description: The time extracted from the backup file name
  returned: when backup is yes
  type: str
  sample: "22:28:34"
"""

CFG_FILE_SUBCONFIG_INDENT = 1


def get_candidate(module):
    candidate = ''
    if module.params['src']:
        candidate = module.params['src']
    elif module.params['lines']:
        candidate_obj = NetworkConfig(indent=CFG_FILE_SUBCONFIG_INDENT)
        parents = module.params['parents'] or list()
        candidate_obj.add(module.params['lines'], parents=parents)
        candidate = dumps(candidate_obj, 'raw')
    return candidate


def get_running_config(module, config=None, flags=None):
    contents = module.params['running_config']
    if not contents:
        if config:
            contents = config
        else:
            contents = get_config(module, flags=flags)
    return contents


def save_config(module, result):
    result['changed'] = True
    if not module.check_mode:
        cmd = {'command': 'copy running-config startup-config', 'output': 'text'}
        run_commands(module, [cmd])
    else:
        module.warn('Skipping command `copy running-config startup-config` '
                    'due to check_mode.  Configuration not copied to '
                    'non-volatile storage')


def is_backup_requested(module):
    return module.params['backup'] or (module._diff and module.params['diff_against'] == 'running')


def prepare_commands(module, config_diff):
    commands = config_diff.split('\n')

    if module.params['before']:
        commands[:0] = module.params['before']

    if module.params['after']:
        commands.extend(module.params['after'])
    return commands


def compare_config(module, running):
    match = module.params['match']
    replace = module.params['replace']
    path = module.params['parents']

    candidate = get_candidate(module)
    connection = get_connection(module)
    diff_ignore_lines = module.params['diff_ignore_lines']

    try:
        response = connection.get_diff(candidate=candidate, running=running, diff_match=match,
                                       diff_ignore_lines=diff_ignore_lines, path=path, diff_replace=replace)
    except ConnectionError as exc:
        module.fail_json(msg=to_text(exc, errors='surrogate_then_replace'))

    return response['config_diff']


def is_config_store_requested(module):
    return module.params['save_when'] != 'never'


def store_config(module, result):
    if module.params['save_when'] == 'always':
        save_config(module, result)
    elif module.params['save_when'] == 'modified':
        diff_ignore_lines = module.params['diff_ignore_lines']
        output = run_commands(module, [{'command': 'show running-config', 'output': 'text'},
                                       {'command': 'show startup-config', 'output': 'text'}])

        running_config = NetworkConfig(
            indent=CFG_FILE_SUBCONFIG_INDENT, contents=output[0], ignore_lines=diff_ignore_lines)
        startup_config = NetworkConfig(
            indent=CFG_FILE_SUBCONFIG_INDENT, contents=output[1], ignore_lines=diff_ignore_lines)

        if running_config.sha1 != startup_config.sha1:
            save_config(module, result)

    elif module.params['save_when'] == 'changed' and result['changed']:
        save_config(module, result)


def find_diff(module, runn_config_before_changes):
    diff_ignore_lines = module.params['diff_ignore_lines']
    running_config = module.params['running_config']
    startup_config = None

    if not running_config:
        output = run_commands(
            module, {'command': 'show running-config', 'output': 'text'})
        contents = output[0]

    else:
        contents = running_config

    # recreate the object in order to process diff_ignore_lines
    running_config = NetworkConfig(
        indent=CFG_FILE_SUBCONFIG_INDENT, contents=contents, ignore_lines=diff_ignore_lines)

    if module.params['diff_against'] == 'running':
        if module.check_mode:
            module.warn(
                "unable to perform diff against running-config due to check mode")
            contents = None
        else:
            contents = runn_config_before_changes.config_text

    elif module.params['diff_against'] == 'startup':
        if not startup_config:
            output = run_commands(
                module, {'command': 'show startup-config', 'output': 'text'})
            contents = output[0]
        else:
            contents = startup_config.config_text

    elif module.params['diff_against'] == 'intended':
        contents = module.params['intended_config']
    result_diff = {}
    if contents is not None:
        base_config = NetworkConfig(
            indent=CFG_FILE_SUBCONFIG_INDENT, contents=contents, ignore_lines=diff_ignore_lines)

        if running_config.sha1 != base_config.sha1:
            if module.params['diff_against'] == 'intended':
                before = running_config
                after = base_config
            elif module.params['diff_against'] in ('startup', 'running'):
                before = base_config
                after = running_config
            result_diff = {
                'changed': True,
                'diff': {'before': str(before), 'after': str(after)}
            }
    return result_diff


def is_new_config_provided(module):
    return any((module.params['src'], module.params['lines']))


def apply_config(module, running_cfg):
    result = {}
    running = get_running_config(module, running_cfg)
    config_diff = compare_config(module, running)

    if config_diff:
        commands = prepare_commands(module, config_diff)

        result['commands'] = commands
        result['updates'] = commands

        replace = module.params['replace'] == 'config'
        commit = not module.check_mode
        response = load_config(
            module, commands, replace=replace, commit=commit)

        result['changed'] = True

        if 'session' in response:
            result['session'] = response['session']
    return result


def main():
    """ main entry point for module execution
    """
    backup_spec = dict(
        filename=dict(),
        dir_path=dict(type='path')
    )
    argument_spec = dict(
        src=dict(type='path'),

        lines=dict(aliases=['commands'], type='list'),
        parents=dict(type='list'),

        before=dict(type='list'),
        after=dict(type='list'),

        match=dict(default='line', choices=[
                   'line', 'strict', 'exact', 'none']),
        replace=dict(default='line', choices=['line', 'block', 'config']),

        defaults=dict(type='bool', default=False),
        backup=dict(type='bool', default=False),
        backup_options=dict(type='dict', options=backup_spec),

        save_when=dict(choices=['always', 'never',
                       'modified', 'changed'], default='never'),

        diff_against=dict(
            choices=['startup', 'intended', 'running'], default='running'),
        diff_ignore_lines=dict(type='list'),

        running_config=dict(aliases=['config']),
        intended_config=dict(),
    )

    argument_spec.update(aos_argument_spec)

    mutually_exclusive = [('lines', 'src'),
                          ('parents', 'src')]

    required_if = [('match', 'strict', ['lines']),
                   ('match', 'exact', ['lines']),
                   ('replace', 'block', ['lines']),
                   ('replace', 'config', ['src']),
                   ('diff_against', 'intended', ['intended_config'])]

    module = AnsibleModule(argument_spec=argument_spec,
                           mutually_exclusive=mutually_exclusive,
                           required_if=required_if,
                           supports_check_mode=False)

    warnings = list()
    check_args(module, warnings)

    result = {'changed': False}
    if warnings:
        result['warnings'] = warnings

    runnconfig_before_changes = None
    flags = ['all'] if module.params['defaults'] else []

    running_cfg = None
    if is_backup_requested(module):
        running_cfg = get_config(module, flags=flags)
        runnconfig_before_changes = NetworkConfig(
            indent=CFG_FILE_SUBCONFIG_INDENT, contents=running_cfg)
        if module.params['backup']:
            result['__backup__'] = running_cfg

    if is_new_config_provided(module):
        res = apply_config(module, running_cfg)
        result.update(res)

    if is_config_store_requested(module):
        store_config(module, result)

    # check if config difference output is requested
    if module._diff:
        diff = find_diff(module, runnconfig_before_changes)
        result.update(diff)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
