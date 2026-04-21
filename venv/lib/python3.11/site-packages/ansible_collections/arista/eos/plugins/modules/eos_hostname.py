#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2022 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for eos_hostname
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: eos_hostname
short_description: Manages hostname resource module
description: This module configures and manages the attribute of  hostname on Arista
  EOS platforms.
version_added: 4.1.0
author: Gomathi Selvi Srinivasan (@GomathiselviS)
notes:
- Tested against Arista EOS 4.24.60M
- This module works with connection C(network_cli). See the L(EOS Platform Options,eos_platform_options).
options:
    config:
      description: A dictionary of hostname options
      type: dict
      suboptions:
        hostname:
          description:
          - The system's hostname
          type: str
    running_config:
      description:
      - This option is used only with state I(parsed).
      - The value of this option should be the output received from the EOS device by
        executing the command B(show running-config | section hostname).
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into Ansible structured data as per the resource module's argspec
        and the value is then returned in the I(parsed) key within the result.
      type: str
    state:
      description:
      - The state the configuration should be left in.
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
        I(show running-config | section ^hostname) executed on device. For state I(parsed) active
        connection to remote host is not required.
      type: str
      choices:
      - deleted
      - merged
      - overridden
      - replaced
      - gathered
      - rendered
      - parsed
      default: merged
"""

EXAMPLES = """

# Using state: merged
# Before state:
# -------------
# test#show running-config | section ^hostname
# hostname eos
# Merged play:
# ------------
- name: Apply the provided configuration
  arista.eos.eos_hostname:
    config:
      hostname: eos
    state: merged
# Commands Fired:
# ---------------
# "commands": [
#         "hostname eos",
# ],
# After state:
# ------------
# test#show running-config | section ^hostname
# hostname eos


# Using state: deleted
# Before state:
# -------------
# test#show running-config | section ^hostname
# hostname eosTest
# Deleted play:
# -------------
- name: Remove all existing configuration
  arista.eos.eos_hostname:
    state: deleted
# Commands Fired:
# ---------------
# "commands": [
#     "no hostname eosTest",
# ],
# After state:
# ------------
# test#show running-config | section ^hostname
# hostname eos


# Using state: overridden
# Before state:
# -------------
# test#show running-config | section ^hostname
# hostname eos
# Overridden play:
# ----------------
- name: Override commands with provided configuration
  arista.eos.eos_hostname:
    config:
      hostname: eosTest
    state: overridden
# Commands Fired:
# ---------------
# "commands": [
#       "hostname eosTest",
#     ],
# After state:
# ------------
# test#show running-config | section ^hostname
# hostname eosTest


# Using state: replaced
# Before state:
# -------------
# test#show running-config | section ^hostname
# hostname eosTest
# Replaced play:
# --------------
- name: Replace commands with provided configuration
  arista.eos.eos_hostname:
    config:
      hostname: eosTest
    state: replaced
# Commands Fired:
# ---------------
# "commands": [],
# After state:
# ------------
# test#show running-config | section ^hostname
# hostname eosTest

# Using state: gathered
# Before state:
# -------------
# test#show running-config | section ^hostname
# hostname eosTest
# Gathered play:
# --------------
- name: Gather listed hostname config
  arista.eos.eos_hostname:
    state: gathered
# Module Execution Result:
# ------------------------
#   "gathered": {
#      "hostname": "eosTest"
#     },

# Using state: rendered
# Rendered play:
# --------------
- name: Render the commands for provided configuration
  arista.eos.eos_hostname:
    config:
      hostname: eosTest
    state: rendered
# Module Execution Result:
# ------------------------
# "rendered": [
#     "hostname eosTest",
# ]

# Using state: parsed
# File: parsed.cfg
# ----------------
# hostname eosTest
# Parsed play:
# ------------
- name: Parse the provided configuration with the existing running configuration
  arista.eos.eos_hostname:
    running_config: "{{ lookup('file', 'parsed.cfg') }}"
    state: parsed
# Module Execution Result:
# ------------------------
#  "parsed": {
#     "hostname": "eosTest"
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
    - hostname eos
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - hostname eos
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
    - hostname eost_test
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - hostname eost_test
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

from ansible_collections.arista.eos.plugins.module_utils.network.eos.argspec.hostname.hostname import (
    HostnameArgs,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.config.hostname.hostname import (
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
