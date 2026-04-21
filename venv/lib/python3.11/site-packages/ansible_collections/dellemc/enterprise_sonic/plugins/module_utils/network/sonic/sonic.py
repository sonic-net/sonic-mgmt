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

from ansible.module_utils._text import to_text
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
    ComplexList
)
from ansible.module_utils.connection import Connection, ConnectionError
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.config import NetworkConfig, ConfigLine

_DEVICE_CONFIGS = {}
STANDARD_ETH_REGEXP = r"(Eth\d+(/\d+)+)"


def get_connection(module):
    if hasattr(module, "_sonic_connection"):
        return module._sonic_connection

    capabilities = get_capabilities(module)
    network_api = capabilities.get("network_api")
    if network_api in ["cliconf", "sonic_rest"]:
        module._sonic_connection = Connection(module._socket_path)
    else:
        module.fail_json(msg="Invalid connection type %s" % network_api)

    return module._sonic_connection


def get_capabilities(module):
    if hasattr(module, "_sonic_capabilities"):
        return module._sonic_capabilities
    try:
        capabilities = Connection(module._socket_path).get_capabilities()
    except ConnectionError as exc:
        module.fail_json(msg=to_text(exc, errors="surrogate_then_replace"))
    module._sonic_capabilities = json.loads(capabilities)
    return module._sonic_capabilities


def get_config(module, flags=None):
    flags = to_list(flags)
    flag_str = " ".join(flags)

    try:
        return _DEVICE_CONFIGS[flag_str]
    except KeyError:
        connection = get_connection(module)
        try:
            out = connection.get_config(flags=flags)
        except ConnectionError as exc:
            module.fail_json(msg=to_text(exc, errors="surrogate_then_replace"))
        cfg = to_text(out, errors="surrogate_then_replace").strip()
        _DEVICE_CONFIGS[flag_str] = cfg
        return cfg


def get_sublevel_config(running_config, module):
    contents = list()
    current_config_contents = list()
    running_config = NetworkConfig(contents=running_config, indent=1)
    obj = running_config.get_object(module.params['parents'])
    if obj:
        contents = obj.children
    parents = module.params['parents']
    if parents[2:]:
        temp = 1
        for count, item in enumerate(parents[2:], start=2):
            item = ' ' * temp + item
            temp = temp + 1
            parents[count] = item
    contents[:0] = parents
    indent = 0
    for c in contents:
        if isinstance(c, str):
            if c in parents:
                current_config_contents.append(c.rjust(len(c) + indent, ' '))
            if c not in parents:
                c = ' ' * (len(parents) - 1) + c
                current_config_contents.append(c.rjust(len(c) + indent, ' '))
        if isinstance(c, ConfigLine):
            current_config_contents.append(c.raw)
        indent = 1
    sublevel_config = '\n'.join(current_config_contents)
    return sublevel_config


def run_commands(module, commands, check_rc=True):
    connection = get_connection(module)
    try:
        return connection.run_commands(commands=commands, check_rc=check_rc)
    except ConnectionError as exc:
        module.fail_json(msg=to_text(exc))


def edit_config(module, commands, skip_code=None, suppr_ntf_excp=True):
    connection = get_connection(module)

    # Start: This is to convert interface name from Eth1/1 to Eth1%2f1
    for request in commands:
        # This check is to differentiate between requests and commands
        if isinstance(request, dict):
            url = request.get("path", None)
            if url:
                request["path"] = update_url(url)
    # End
    if suppr_ntf_excp:
        # Default: not used for cliconf
        return connection.edit_config(commands)
    else:
        return connection.edit_config(commands, suppr_ntf_excp)


def edit_config_reboot(module, commands, skip_code=None):
    connection = get_connection(module)

    # Start: This is to convert interface name from Eth1/1 to Eth1%2f1
    for request in commands:
        # This check is to differentiate between REST API requests and CLI commands
        if isinstance(request, dict):
            url = request.get("path", None)
            if url:
                request["path"] = update_url(url)
    # End
    connection.edit_config_reboot(commands)


def update_url(url):
    match = re.findall(STANDARD_ETH_REGEXP, url)
    ret_url = url
    if match:
        for item in match:
            interface_name = item[0]
            update_interface_name = interface_name.replace("/", "%2f")
            ret_url = ret_url.replace(interface_name, update_interface_name)
    return ret_url


def to_request(module, requests):
    transform = ComplexList(dict(path=dict(key=True), method=dict(), data=dict(type='dict')), module)
    return transform(to_list(requests))
