# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# (c) 2016 Red Hat Inc.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
import re

from ansible.module_utils._text import to_text, to_native
from ansible.module_utils.basic import env_fallback
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import to_list, ComplexList
from ansible.module_utils.connection import Connection, ConnectionError

# copy of https://github.com/napalm-automation/napalm/blob/develop/napalm/base/canonical_map.py
from ansible_collections.community.ciscosmb.plugins.module_utils.ciscosmb_canonical_map import base_interfaces

_DEVICE_CONFIGS = {}

ciscosmb_provider_spec = {
    'host': dict(),
    'port': dict(type='int'),
    'username': dict(fallback=(env_fallback, ['ANSIBLE_NET_USERNAME'])),
    'password': dict(fallback=(env_fallback, ['ANSIBLE_NET_PASSWORD']), no_log=True),
    'ssh_keyfile': dict(fallback=(env_fallback, ['ANSIBLE_NET_SSH_KEYFILE']), type='path'),
    'timeout': dict(type='int')
}
ciscosmb_argument_spec = {}


def ciscosmb_split_to_tables(data):
    TABLE_HEADER = re.compile(r"^---+ +-+.*$")
    EMPTY_LINE = re.compile(r"^ *$")

    tables = dict()
    tableno = -1
    lineno = 0
    tabledataget = False

    for line in data.splitlines():
        if re.match(EMPTY_LINE, line):
            tabledataget = False
            continue

        if re.match(TABLE_HEADER, line):
            tableno += 1
            tabledataget = True
            lineno = 0
            tables[tableno] = dict()
            tables[tableno]["header"] = line
            tables[tableno]["data"] = dict()
            continue

        if tabledataget:
            tables[tableno]["data"][lineno] = line
            lineno += 1
            continue

    return tables


def ciscosmb_parse_table(table, allow_overflow=True, allow_empty_fields=None):

    if allow_empty_fields is None:
        allow_empty_fields = list()

    fields_end = __get_table_columns_end(table["header"])
    data = __get_table_data(
        table["data"], fields_end, allow_overflow, allow_empty_fields
    )

    return data


def __get_table_columns_end(headerline):
    """ fields length are diferent device to device, detect them on horizontal lin """
    fields_end = [m.start() for m in re.finditer("  *", headerline.strip())]
    # fields_position.insert(0,0)
    # fields_end.append(len(headerline))
    fields_end.append(10000)  # allow "long" last field

    return fields_end


def __line_to_fields(line, fields_end):
    """ dynamic fields lenghts """
    line_elems = {}
    index = 0
    f_start = 0
    for f_end in fields_end:
        line_elems[index] = line[f_start:f_end].strip()
        index += 1
        f_start = f_end

    return line_elems


def __get_table_data(
    tabledata, fields_end, allow_overflow=True, allow_empty_fields=None
):

    if allow_empty_fields is None:
        allow_empty_fields = list()
    data = dict()

    dataindex = 0
    for lineno in tabledata:
        owerflownfields = list()
        owerflow = False

        line = tabledata[lineno]
        line_elems = __line_to_fields(line, fields_end)

        if allow_overflow:
            # search for overflown fields
            for elemno in line_elems:
                if elemno not in allow_empty_fields and line_elems[elemno] == "":
                    owerflow = True
                else:
                    owerflownfields.append(elemno)

            if owerflow:
                # concat owerflown elements to previous data
                for fieldno in owerflownfields:
                    data[dataindex - 1][fieldno] += line_elems[fieldno]

            else:
                data[dataindex] = line_elems
                dataindex += 1
        else:
            data[dataindex] = line_elems
            dataindex += 1

    return data


def ciscosmb_merge_dicts(a, b, path=None):
    "merges b into a"
    if path is None:
        path = []

    # is b empty?
    if not bool(b):
        return a

    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                ciscosmb_merge_dicts(a[key], b[key], path + [str(key)])
            elif a[key] == b[key]:
                pass  # same leaf value
            else:
                raise Exception("Conflict at %s" % ".".join(path + [str(key)]))
        else:
            a[key] = b[key]
    return a


def interface_canonical_name(interface):
    iftype = interface.rstrip(r"/\0123456789. ")
    ifno = interface[len(iftype):].lstrip()

    if iftype in base_interfaces:
        iftype = base_interfaces[iftype]

    interface = iftype + str(ifno)

    return interface


def get_provider_argspec():
    return ciscosmb_provider_spec


def get_connection(module):
    if hasattr(module, '_ciscosmb_connection'):
        return module._ciscosmb_connection

    capabilities = get_capabilities(module)
    network_api = capabilities.get('network_api')
    if network_api == 'cliconf':
        module._ciscosmb_connection = Connection(module._socket_path)
    else:
        module.fail_json(msg='Invalid connection type %s' % network_api)

    return module._ciscosmb_connection


def get_capabilities(module):
    if hasattr(module, '_ciscosmb_capabilities'):
        return module._ciscosmb_capabilities

    try:
        capabilities = Connection(module._socket_path).get_capabilities()
        module._ciscosmb_capabilities = json.loads(capabilities)
        return module._ciscosmb_capabilities
    except ConnectionError as exc:
        module.fail_json(msg=to_native(exc, errors='surrogate_then_replace'))


def get_defaults_flag(module):
    connection = get_connection(module)

    try:
        out = connection.get('/system default-configuration print')
    except ConnectionError as exc:
        module.fail_json(msg=to_text(exc, errors='surrogate_then_replace'))

    out = to_text(out, errors='surrogate_then_replace')

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
            module.fail_json(msg=to_text(exc, errors='surrogate_then_replace'))

        cfg = to_text(out, errors='surrogate_then_replace').strip()
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

        try:
            out = connection.get(command, prompt, answer)
        except ConnectionError as exc:
            module.fail_json(msg=to_text(exc, errors='surrogate_then_replace'))

        try:
            out = to_text(out, errors='surrogate_or_strict')
        except UnicodeError:
            module.fail_json(
                msg=u'Failed to decode output from %s: %s' % (cmd, to_text(out)))

        responses.append(out)

    return responses
