#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for eos_vrf_global
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: eos_vrf_global
short_description: Resource module to configure VRF definitions.
description: This module provides declarative management of VRF definitions on Arista EOS platforms.
version_added: 10.0.0
author: Ruchi Pakhle (@Ruchip16)
notes:
- Tested against Arista EOS 4.23.0F
- This module works with connection C(network_cli). See the L(EOS Platform Options,eos_platform_options).
options:
  config:
    description: A list of dictionaries containing device configurations for VRF definitions.
    type: list
    elements: dict
    suboptions:
      name:
        description: Name of the VRF Instance.
        type: str
        required: true
      description:
        description: A description for the VRF.
        type: str
      rd:
        description: BGP Route Distinguisher (RD).
        type: str
  running_config:
    description:
      - This option is used only with state I(parsed).
      - The value of this option should be the output received from the EOS device by
        executing the command B(show running-config vrf).
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into Ansible structured data as per the resource module's argspec
        and the value is then returned in the I(parsed) key within the result.
    type: str
  state:
    choices: [parsed, gathered, deleted, merged, replaced, rendered, overridden, purged]
    default: merged
    description:
      - The state the configuration should be left in
      - The states I(rendered), I(gathered) and I(parsed) does not perform any change
        on the device.
      - The state I(rendered) will transform the configuration in C(config) option to
        platform specific CLI commands which will be returned in the I(rendered) key
        within the result. For state I(rendered) active connection to remote host is
        not required.
      - The state I(gathered) will fetch the running configuration from device and transform
        it into structured data in the format as per the resource module argspec and
        the value is returned in the I(gathered) key within the result.
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into JSON format as per the resource module parameters and the
        value is returned in the I(parsed) key within the result. The value of C(running_config)
        option should be the same format as the output of command I(show running-config vrf).
        connection to remote host is not required.
    type: str
"""

EXAMPLES = """
# Using merged
#
# Before state:
# -------------
#
# test#show running-config | section ^vrf

- name: Merge provided configuration with device configuration
  arista.eos.eos_vrf_global:
    config:
      - name: VRF4
        description: VRF4 Description
        rd: "3:4"
    state: merged

# Task Output:
# ------------
#
# before: []
#
# commands:
# - vrf instance VRF4
# - description VRF4 Description
# - rd 3:4
#
# after:
# - name: VRF4
#   description: VRF4 Description
#   rd: "3:4"
#
# After state:
# ------------
#
# test#show running-config | section ^vrf
# vrf instance VRF4
#  description "VRF4 Description"
#  rd "3:4"

# Using replaced
#
# Before state:
# -------------
#
# test#show running-config | section ^vrf
# vrf instance VRF4
#  description "VRF4 Description"
#  rd "3:4"

- name: Replace the provided configuration with the existing running configuration
  arista.eos.eos_vrf_global:
    config:
      - name: VRF7
        description: VRF7 description
        rd: "67:9"
    state: replaced

# Task Output:
# ------------
#
# before:
# - name: VRF4
#   description: VRF4 Description
#   rd: "3:4"
#
# commands:
# - vrf instance VRF7
# - description VRF7 description
# - rd 6:9
#
# after:
#   - name: VRF4
#     description: VRF4 Description
#     rd: "3:4"
#   - name: VRF7
#     description: VRF7 description
#     rd: "6:9"
#
# After state:
# ------------
#
# test#show running-config | section ^vrf
# vrf instance VRF4
#  description VRF4 Description
#  rd 3:4
# !
# vrf instance VRF7
#  description VRF7 description
#  rd 6:9
#  !
# !

# Using overridden
#
# Before state:
# -------------
#
# test#show running-config | section ^vrf
# vrf instance VRF4
#  description VRF4 Description
#  rd 3:4
# !
# vrf instance VRF7
#  description VRF7 description
#  rd 6:9
#  !
# !

- name: Override the provided configuration with the existing running configuration
  arista.eos.eos_vrf_global:
    state: overridden
    config:
      - name: VRF6
        description: VRF6 Description
        rd: "9:8"

# Task Output:
# ------------
#
# before:
# - name: VRF4
#   description: VRF4 Description
#   rd: "3:4"
# - name: VRF7
#   description: VRF7 description
#   rd: "6:9"
#
# commands:
# - vrf instance VRF4
# - no description VRF4 Description
# - no rd 3:4
# - vrf instance VRF7
# - no description VRF7 description
# - no rd 67:9
# - vrf instance VRF6
# - description VRF6 Description
# - rd 9:8
#
# after:
# - name: VRF4
# - name: VRF6
#   description: VRF6 Description
#   rd: "9:8"
# - name: VRF7
#
# After state:
# -------------
# test#show running-config | section ^vrf
# vrf instance VRF4
# vrf instance VRF6
#  description VRF6 Description
#  rd 9:8
# vrf instance VRF7

# Using deleted
#
# Before state:
# -------------
#
# test#show running-config | section ^vrf
# vrf instance VRF4
# vrf instance VRF6
#  description VRF6 Description
#  rd 9:8
# vrf instance VRF7

- name: Delete the provided configuration
  arista.eos.eos_vrf_global:
    config:
    state: deleted

# Task Output:
# ------------
#
# before:
# - name: VRF4
# - name: VRF6
#   description: VRF6 Description
#   rd: "9:8"
# - name: VRF7

# commands:
# - vrf instance VRF4
# - vrf instance VRF6
# - no description VRF6 Description
# - no rd 9:8
# - vrf instance VRF7
#
# after:
# - name: VRF4
# - name: VRF6
# - name: VRF7
#
# After state:
# ------------
#
# test#show running-config | section ^vrf
# vrf instance VRF4
# vrf instance VRF6
# vrf instance VRF7

# Using purged
#
# Before state:
# -------------
#
# test#show running-config | section ^vrf
# vrf instance VRF4
# vrf instance VRF6
# vrf instance VRF7

- name: Purge all the configuration from the device
  arista.eos.eos_vrf_global:
    state: purged

# Task Output:
# ------------
#
# before:
# - name: VRF4
# - name: VRF6
# - name: VRF7
#
# commands:
# - no vrf instance VRF4
# - no vrf instance VRF6
# - no vrf instance VRF7
#
# after: []
#
# After state:
# -------------
# test#show running-config | section ^vrf
# -

# Using rendered
#
- name: Render provided configuration with device configuration
  arista.eos.eos_vrf_global:
    config:
      - name: VRF4
        description: VRF4 Description
        rd: "3:4"
    state: rendered

# Task Output:
# ------------
#
# rendered:
# - vrf instance VRF4
# - description VRF4 Description
# - rd 3:4

# Using gathered
#
# Before state:
# -------------
#
# test#show running-config | section ^vrf
# vrf instance VRF4
#  description "VRF4 Description"
#  rd "3:4"

- name: Gather existing running configuration
  arista.eos.eos_vrf_global:
    state: gathered

# Task Output:
# ------------
#
# gathered:
# - name: VRF4
#   description: VRF4 Description
#   rd: "3:4"

# Using parsed
#
# File: parsed.cfg
# ----------------
#
# vrf instance test
#  description "This is test VRF"
#  rd "testing"
#  !
# !
# vrf my_vrf
#  description "this is sample vrf for feature testing"
#  rd "2:3"
#  !
# !

- name: Parse the provided configuration
  arista.eos.eos_vrf_global:
    running_config: "{{ lookup('file', 'parsed.cfg') }}"
    state: parsed

# Task Output:
# ------------
#
# parsed:
# - description: This is test VRF
#   name: test
#   rd: testing
# - description: this is sample vrf for feature testing
#   name: my_vrf
#   rd: '2:3'
"""

RETURN = """
before:
  description: The configuration prior to the module execution.
  returned: when I(state) is C(merged), C(replaced), C(overridden), C(deleted) or C(purged)
  type: list
  sample: >
    The configuration returned will always be in the same format
    of the parameters above.
after:
  description: The resulting configuration after module execution.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
    of the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: when I(state) is C(merged), C(replaced), C(overridden), C(deleted) or C(purged)
  type: list
  sample:
    - vrf instance test
    - description "This is test VRF"
    - rd 3:4
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - vrf instance test
    - description "This is test VRF"
    - rd 3:4
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

from ansible_collections.arista.eos.plugins.module_utils.network.eos.argspec.vrf_global.vrf_global import (
    Vrf_globalArgs,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.config.vrf_global.vrf_global import (
    Vrf_global,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=Vrf_globalArgs.argument_spec,
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

    result = Vrf_global(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
