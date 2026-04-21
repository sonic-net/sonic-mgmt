#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2018, Ansible by Red Hat, inc
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
module: cli_backup
author: Katherine Case (@Qalthos)
short_description: Back up device configuration from network devices over network_cli
description:
- This module provides platform agnostic way of backing up text based configuration from
  network devices over network_cli connection plugin.
version_added: 4.2.0
extends_documentation_fragment:
- ansible.netcommon.network_agnostic
options:
  defaults:
    description:
    - The I(defaults) argument will influence how the running-config is collected
      from the device.  When the value is set to true, the command used to collect
      the running-config is append with the all keyword.  When the value is set to
      false, the command is issued without the all keyword.
    default: no
    type: bool
  filename:
    description:
    - The filename to be used to store the backup configuration. If the filename
      is not given it will be generated based on the hostname, current time and
      date in format defined by <hostname>_config.<current-date>@<current-time>
    type: str
  dir_path:
    description:
    - This option provides the path ending with directory name in which the backup
      configuration file will be stored. If the directory does not exist it will
      be first created and the filename is either the value of C(filename) or
      default filename as described in C(filename) options description. If the
      path value is not given in that case a I(backup) directory will be created
      in the current working directory and backup configuration will be copied
      in C(filename) within I(backup) directory.
    type: path
"""

EXAMPLES = """
- name: configurable backup path
  ansible.netcommon.cli_backup:
    filename: backup.cfg
    dir_path: /home/user
"""

RETURN = """
backup_path:
  description: The full path to the backup file
  returned: always
  type: str
  sample: /playbooks/ansible/backup/hostname_config.2016-07-16@22:28:34
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection


def validate_args(module, device_operations):
    """validate param if it is supported on the platform"""
    feature_list = [
        "defaults",
    ]

    for feature in feature_list:
        if module.params[feature]:
            supports_feature = device_operations.get("supports_%s" % feature)
            if supports_feature is None:
                module.fail_json(
                    msg="This platform does not specify whether %s is supported or not. "
                    "Please report an issue against this platform's cliconf plugin." % feature
                )
            elif not supports_feature:
                module.fail_json(msg="Option %s is not supported on this platform" % feature)


def main():
    """main entry point for execution"""
    argument_spec = dict(
        defaults=dict(default=False, type="bool"),
        filename=dict(),
        dir_path=dict(type="path"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
    )

    result = {"changed": False}

    connection = Connection(module._socket_path)
    capabilities = module.from_json(connection.get_capabilities())

    if capabilities:
        device_operations = capabilities.get("device_operations", dict())
        validate_args(module, device_operations)
    else:
        device_operations = dict()

    if module.params["defaults"]:
        if "get_default_flag" in capabilities.get("rpc"):
            flags = connection.get_default_flag()
        else:
            flags = "all"
    else:
        flags = []

    running = connection.get_config(flags=flags)
    result["__backup__"] = running

    module.exit_json(**result)


if __name__ == "__main__":
    main()
