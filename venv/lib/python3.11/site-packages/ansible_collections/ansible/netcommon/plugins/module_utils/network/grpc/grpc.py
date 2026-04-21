# (c) 2022 Red Hat, Inc.
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import json
import re

from ansible.module_utils.common.text.converters import to_text
from ansible.module_utils.connection import Connection


def get_connection(module):
    if hasattr(module, "_grpc_connection"):
        return module._grpc_connection

    capabilities = get_capabilities(module)
    network_api = capabilities.get("network_api")
    if network_api == "ansible.netcommon.grpc":
        module._grpc_connection = Connection(module._socket_path)
    else:
        module.fail_json(msg="Invalid connection type %s" % network_api)
    return module._grpc_connection


def get_capabilities(module):
    if hasattr(module, "_grpc_capabilities"):
        return module._grpc_capabilities

    module._grpc_capabilities = Connection(module._socket_path).get_capabilities()
    return module._grpc_capabilities


def get(module, section, data_type, check_rc=True):
    conn = get_connection(module)
    if data_type == "config":
        out = conn.get_config(section)
    else:
        out = conn.get(section)

    response = out.get("response")
    error = out.get("error")
    if error:
        if check_rc:
            module.fail_json(msg=to_text(out["error"], errors="surrogate_then_replace"))
        else:
            module.warn(to_text(out["error"], errors="surrogate_then_replace"))

    return response.strip(), error.strip()


def merge_config(module, section, check_rc=True):
    conn = get_connection(module)
    try:
        out = conn.merge_config(section)
        if out:
            err = json.loads(out)
            res = json.dumps(err, indent=4, separators=(",", ": "))
            module.fail_json(msg=to_text(res, errors="surrogate_then_replace"))
    except ValueError as err:
        if check_rc:
            module.fail_json(msg=to_text(out["error"], errors="surrogate_then_replace"))
        else:
            module.warn(to_text(out["error"], errors="surrogate_then_replace"))
        return err


def replace_config(module, section, check_rc=True):
    conn = get_connection(module)
    try:
        out = conn.replace_config(section)
        if out:
            err = json.loads(out)
            res = json.dumps(err, indent=4, separators=(",", ": "))
            module.fail_json(msg=to_text(res, errors="surrogate_then_replace"))
    except ValueError as err:
        if check_rc:
            module.fail_json(msg=to_text(out["error"], errors="surrogate_then_replace"))
        else:
            module.warn(to_text(out["error"], errors="surrogate_then_replace"))
        return err


def delete_config(module, section, check_rc=True):
    conn = get_connection(module)
    try:
        out = conn.delete_config(section)
        if out:
            err = json.loads(out)
            res = json.dumps(err, indent=4, separators=(",", ": "))
            module.fail_json(msg=to_text(res, errors="surrogate_then_replace"))
    except ValueError as err:
        if check_rc:
            module.fail_json(msg=to_text(out["error"], errors="surrogate_then_replace"))
        else:
            module.warn(to_text(out["error"], errors="surrogate_then_replace"))
        return err


def run_cli(module, command, display, check_rc=True):
    conn = get_connection(module)
    out = conn.run_cli(command, display)
    response = out.get("response")
    error = out.get("error")
    if error:
        if check_rc:
            module.fail_json(msg=to_text(out["error"], errors="surrogate_then_replace"))
        else:
            module.warn(to_text(out["error"], errors="surrogate_then_replace"))

    return response.strip(), error.strip()


def sanitize_content(data):
    out = re.sub(".*Last configuration change.*\n?", "", data)
    return out


def validate_config(module, config):
    output = ""
    params = list(config.keys())[0]
    if params:
        val = "{" + '"' + params + '": [null]}'
    response, err = get(module, val, "config")
    if response:
        output = json.loads(response)
    return output
