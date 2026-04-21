#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for vyos_hostname
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: vyos_hostname
version_added: 2.8.0
short_description: Manages hostname resource module
description: This module manages the hostname attribute of Vyos network devices
author: Gomathi Selvi Srinivasan (@GomathiselviS)
notes:
  - Tested against vyos 1.1.8
  - This module works with connection C(network_cli).
  - The Configuration defaults of the Vyos network devices
    are supposed to hinder idempotent behavior of plays
options:
  config:
    description: Hostname configuration.
    type: dict
    suboptions:
      hostname:
        description: set hostname for VYOS.
        type: str
  running_config:
    description:
    - This option is used only with state I(parsed).
    - The value of this option should be the output received from the vyos device by
      executing the command B("show configuration commands | grep host-name").
    - The state I(parsed) reads the configuration from C(running_config) option and
      transforms it into Ansible structured data as per the resource module's argspec
      and the value is then returned in the I(parsed) key within the result.
    type: str
  state:
    choices:
      - merged
      - replaced
      - overridden
      - deleted
      - gathered
      - parsed
      - rendered
    default: merged
    description:
      - The state the configuration should be left in
      - The states I(rendered), I(gathered) and I(parsed) does not perform any change
        on the device.
      - The state I(rendered) will transform the configuration in C(config) option to
        platform specific CLI commands which will be returned in the I(rendered) key
        within the result. For state I(rendered) active connection to remote host is
        not required.
      - The states I(merged), I(replaced) and I(overridden) have identical
        behaviour for this module.
      - The state I(gathered) will fetch the running configuration from device and transform
        it into structured data in the format as per the resource module argspec and
        the value is returned in the I(gathered) key within the result.
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into JSON format as per the resource module parameters and the
        value is returned in the I(parsed) key within the result. The value of C(running_config)
        option should be the same format as the output of command
        I(show configuration commands | grep host-name) executed on device. For state I(parsed) active
        connection to remote host is not required.
    type: str
"""

EXAMPLES = """
# Using merged
#
# Before state:
# -------------
# test#show configuration commands | grep host-name
# set system host-name 'vyostest'

- name: Apply the provided configuration
  vyos.vyos.vyos_hostname:
    config:
      hostname: vyos
    state: merged

# Commands Fired:
# ---------------
# "commands": [
#         "hostname vyos",
# ],
#
# After state:
# ------------
# test#show configuration commands | grep host-name
# set system host-name 'vyos'

# Using deleted
#
# Before state:
# -------------
# test#show configuration commands | grep host-name
# set system host-name 'vyos'
#
- name: Remove all existing configuration
  vyos.vyos.vyos_hostname:
    state: deleted

# Commands Fired:
# ---------------
# "commands": [
#     "no hostname vyosTest",
# ],
#
# After state:
# ------------
# test#show configuration commands | grep host-name

# Using overridden
#
# Before state:
# -------------
# test#show configuration commands | grep host-name
# set system host-name 'vyos'

- name: Override commands with provided configuration
  vyos.vyos.vyos_hostname:
    config:
      hostname: vyosTest
    state: overridden

# Commands Fired:
# ---------------
# "commands": [
#       "hostname vyosTest",
#     ],
#
# After state:
# ------------
# test#show configuration commands | grep host-name
# set system host-name 'vyosTest'

# Using replaced
#
# Before state:
# -------------
# test#show configuration commands | grep host-name
# set system host-name 'vyosTest'

- name: Replace commands with provided configuration
  vyos.vyos.vyos_hostname:
    config:
      hostname: vyos
    state: replaced

# After state:
# ------------
# test#show configuration commands | grep host-name
# set system host-name 'vyos'

# Using gathered
#
# Before state:
# -------------
# test#show configuration commands | grep host-name
# set system host-name 'vyos'

- name: Gather listed hostname config
  vyos.vyos.vyos_hostname:
    state: gathered

# Module Execution Result:
# ------------------------
#   "gathered": {
#      "hostname": "vyos"
#     },

# Using state: rendered
# Rendered play:
# --------------
- name: Render the commands for provided configuration
  vyos.vyos.vyos_hostname:
    config:
      hostname: vyosTest
    state: rendered
# Module Execution Result:
# ------------------------
# "rendered": [
#     "set system host-name vyosTest",
# ]

# Using state: parsed
# File: parsed.cfg
# ----------------
# set system host-name 'vyos'
# Parsed play:
# ------------
- name: Parse the provided configuration with the existing running configuration
  vyos.vyos.vyos_hostname:
    running_config: "{{ lookup('file', 'parsed.cfg') }}"
    state: parsed
# Module Execution Result:
# ------------------------
#  "parsed": {
#     "hostname": "vyos"
# }
"""

RETURN = """
before:
  description: The configuration prior to the module execution.
  returned: when I(state) is C(merged), C(replaced), C(overridden), C(deleted) or C(purged)
  type: dict
  sample: >
    This output will always be in the same format as the
    module argspec.
after:
  description: The resulting configuration after module execution.
  returned: when changed
  type: dict
  sample: >
    This output will always be in the same format as the
    module argspec.
commands:
  description: The set of commands pushed to the remote device.
  returned: when I(state) is C(merged), C(replaced), C(overridden), C(deleted) or C(purged)
  type: list
  sample:
    - sample command 1
    - sample command 2
    - sample command 3
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - sample command 1
    - sample command 2
    - sample command 3
gathered:
  description: Facts about the network resource gathered from the remote device as structured data.
  returned: when I(state) is C(gathered)
  type: list
  sample: >
    This output will always be in the same format as the
    module argspec.
parsed:
  description: The device native config provided in I(running_config) option parsed into structured data as per module argspec.
  returned: when I(state) is C(parsed)
  type: list
  sample: >
    This output will always be in the same format as the
    module argspec.
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.argspec.hostname.hostname import (
    HostnameArgs,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.config.hostname.hostname import (
    Hostname,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=HostnameArgs.argument_spec,
        mutually_exclusive=[["config", "running_config"]],
        required_if=[
            ["state", "merged", ["config"]],
            ["state", "replaced", ["config"]],
            ["state", "overridden", ["config"]],
            ["state", "rendered", ["config"]],
            ["state", "parsed", ["running_config"]],
        ],
        supports_check_mode=True,
    )

    result = Hostname(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
