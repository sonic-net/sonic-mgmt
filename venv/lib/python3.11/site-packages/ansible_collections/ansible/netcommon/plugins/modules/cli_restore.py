#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2024, Ansible by Red Hat, inc
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
module: cli_restore
author: Sagar Paul (@KB-perByte)
short_description: Restore device configuration to network devices over network_cli
description:
- This module provides platform agnostic way of restore text based configuration to
  network devices over network_cli connection plugin.
- The module uses the platforms `config replace` commands to restore
  backup configuration that is already copied over to the appliance.
version_added: 6.1.0
extends_documentation_fragment:
- ansible.netcommon.network_agnostic
options:
  filename:
    description:
    - Filename of the backup file, present in the appliance where the restore operation
      is to be performed. Check appliance for the configuration backup file name.
    type: str
  path:
    description:
    - The location in the target appliance where the file containing the backup exists.
      The path and the filename together create the input to the config replace command,
    - For an IOSXE appliance the path pattern is flash://<filename>
    type: str
"""

EXAMPLES = """
- name: Restore IOS-XE configuration
  ansible.netcommon.cli_restore:
    filename: backupDday.cfg
    path: flash://

# Command fired
# -------------
# config replace flash://backupDday.cfg force

# Task Output
# -----------
#
# ok: [BATMON] => changed=false
#   __restore__: |-
#     The rollback configlet from the last pass is listed below:
#     ********
#     !List of Rollback Commands:
#     Building configuration...
#     Current configuration : 3781 bytes
#     end
#     ********
#
#
#     Rollback aborted after 5 passes
#     The following commands are failed to apply to the IOS image.
#     ********
#     Building configuration...
#     Current configuration : 3781 bytes
#     ********
#   invocation:
#     module_args:
#       filename: backupDday.cfg
"""

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_text
from ansible.module_utils.connection import Connection, ConnectionError


def validate_args(module, device_operations):
    """validate param if it is supported on the platform"""
    feature_list = []

    for feature in feature_list:
        if module.params[feature]:
            supports_feature = device_operations.get(f"supports_{feature}")
            if supports_feature is None:
                module.fail_json(
                    msg=f"This platform does not specify whether {feature} is supported or not. "
                    "Please report an issue against this platform's cliconf plugin."
                )
            elif not supports_feature:
                module.fail_json(msg=f"Option {feature} is not supported on this platform")


def main():
    """main entry point for execution"""
    argument_spec = dict(
        filename=dict(type="str"),
        path=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
    )

    result = {"changed": False}
    connection = Connection(module._socket_path)
    try:
        running = connection.restore(
            filename=module.params["filename"],
            path=module.params["path"],
        )
    except ConnectionError as exc:
        if exc.code == -32601:  # Method not found
            msg = "This platform is not supported with cli_restore. Please report an issue against this platform's cliconf plugin."
            module.fail_json(msg, code=exc.code)
        else:
            module.fail_json(msg=to_text(exc, errors="surrogate_then_replace").strip())
    result["__restore__"] = running
    module.exit_json(**result)


if __name__ == "__main__":
    main()
