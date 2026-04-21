# Copyright (c) 2016 Red Hat Inc.
# Simplified BSD License (see LICENSES/BSD-2-Clause.txt or https://opensource.org/licenses/BSD-2-Clause)
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.basic import env_fallback
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import to_list, ComplexList
from ansible_collections.community.routeros.plugins.module_utils.version import LooseVersion
from ansible.module_utils.connection import Connection, ConnectionError

_DEVICE_CONFIGS = {}

routeros_provider_spec = {
    'host': dict(),
    'port': dict(type='int'),
    'username': dict(fallback=(env_fallback, ['ANSIBLE_NET_USERNAME'])),
    'password': dict(fallback=(env_fallback, ['ANSIBLE_NET_PASSWORD']), no_log=True),
    'ssh_keyfile': dict(fallback=(env_fallback, ['ANSIBLE_NET_SSH_KEYFILE']), type='path'),
    'timeout': dict(type='int')
}
routeros_argument_spec = {}


def get_provider_argspec():
    return routeros_provider_spec


def get_connection(module):
    if hasattr(module, '_routeros_connection'):
        return module._routeros_connection

    capabilities = get_capabilities(module)
    network_api = capabilities.get('network_api')
    if network_api == 'cliconf':
        module._routeros_connection = Connection(module._socket_path)
    else:
        module.fail_json(msg='Invalid connection type %s' % network_api)

    return module._routeros_connection


def get_capabilities(module):
    if hasattr(module, '_routeros_capabilities'):
        return module._routeros_capabilities

    try:
        capabilities = Connection(module._socket_path).get_capabilities()
        module._routeros_capabilities = json.loads(capabilities)
        return module._routeros_capabilities
    except ConnectionError as exc:
        module.fail_json(msg=to_native(exc, errors='surrogate_then_replace'))


def get_defaults_flag(module):
    connection = get_connection(module)

    try:
        out = connection.get('/system default-configuration print')
    except ConnectionError as exc:
        module.fail_json(msg=to_native(exc, errors='surrogate_then_replace'))

    out = to_native(out, errors='surrogate_then_replace')

    commands = set()
    for line in out.splitlines():
        if line.strip():
            commands.add(line.strip().split()[0])

    if 'all' in commands:
        return ['all']
    else:
        return ['full']


def get_config(module, flags=None):
    flag_str = ' '.join(to_list(flags))

    try:
        return _DEVICE_CONFIGS[flag_str]
    except KeyError:
        connection = get_connection(module)

        try:
            out = connection.get_config(flags=flags)
        except ConnectionError as exc:
            module.fail_json(msg=to_native(exc, errors='surrogate_then_replace'))

        cfg = to_native(out, errors='surrogate_then_replace').strip()
        _DEVICE_CONFIGS[flag_str] = cfg
        return cfg


def to_commands(module, commands):
    spec = {
        'command': dict(key=True),
        'prompt': dict(),
        'answer': dict()
    }
    transform = ComplexList(spec, module)
    return transform(commands)


def should_add_leading_space(module):
    """Determines whether adding a leading space to the command is needed
    to workaround prompt bug in 6.49 <= ROS < 7.2"""
    capabilities = get_capabilities(module)
    network_os_version = capabilities.get('device_info', {}).get('network_os_version')
    if network_os_version is None:
        return False
    return LooseVersion('6.49') <= LooseVersion(network_os_version) < LooseVersion('7.2')


def run_commands(module, commands, check_rc=True):
    responses = list()
    connection = get_connection(module)

    for cmd in to_list(commands):
        if isinstance(cmd, dict):
            command = cmd['command']
            prompt = cmd['prompt']
            answer = cmd['answer']
        else:
            command = cmd
            prompt = None
            answer = None

        if should_add_leading_space(module):
            command = " " + command

        try:
            out = connection.get(command, prompt, answer)
        except ConnectionError as exc:
            module.fail_json(msg=to_native(exc, errors='surrogate_then_replace'))

        try:
            out = to_native(out, errors='surrogate_or_strict')
        except UnicodeError:
            module.fail_json(
                msg=u'Failed to decode output from %s: %s' % (cmd, to_native(out)))

        responses.append(out)

    return responses


def load_config(module, commands):
    connection = get_connection(module)

    out = connection.edit_config(commands)
