#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2022 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for nxos_hostname
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: nxos_hostname
short_description: Hostname resource module.
description:
- This module manages hostname configuration on devices running Cisco NX-OS.
version_added: 2.9.0
notes:
- Tested against NX-OS 9.3.6.
- This module works with connection C(network_cli) and C(httpapi).
author: Nilashish Chakraborty (@NilashishC)
options:
  running_config:
    description:
    - This option is used only with state I(parsed).
    - The value of this option should be the output received from the NX-OS device
      by executing the command B(show running-config | section hostname).
    - The state I(parsed) reads the configuration from C(running_config) option and
      transforms it into Ansible structured data as per the resource module's argspec
      and the value is then returned in the I(parsed) key within the result.
    type: str
  config:
    description: A dictionary of hostname configuration.
    type: dict
    suboptions:
      hostname:
        description: Hostname of the device.
        type: str
  state:
    description:
    - The state the configuration should be left in.
    - The states I(merged), I(replaced) and I(overridden) have identical
      behaviour for this module.
    - Refer to examples for more details.
    type: str
    choices:
    - merged
    - replaced
    - overridden
    - deleted
    - parsed
    - gathered
    - rendered
    default: merged
"""

EXAMPLES = """
# Using merged (replaced, overridden has the same behaviour)

# Before state:
# -------------
# nxos-9k-rdo# show running-config | section ^hostname
# nxos-9k-rdo#

- name: Merge the provided configuration with the existing running configuration
  cisco.nxos.nxos_hostname:
    config:
      hostname: NXOSv-9k

# Task output
# -------------
# before: {}
#
# commands:
#   - hostname NXOSv-9k
#
# after:
#   hostname: NXOSv-9k

# After state:
# ------------
# nxos-9k-rdo# show running-config | section ^hostname
# hostname NXOSv-9k
#

# Using deleted

# Before state:
# ------------
# nxos-9k-rdo# show running-config | section ^hostname
# hostname NXOSv-9k

- name: Delete hostname from running-config
  cisco.nxos.nxos_hostname:
    state: deleted

# Task output
# -------------
# before:
#   hostname: NXOSv-9k
#
# commands:
#   - no hostname NXOSv-9k
#
# after: {}

# Using gathered

- name: Gather hostname facts using gathered
  cisco.nxos.nxos_hostname:
    state: gathered

# Task output (redacted)
# -----------------------
#  gathered:
#    hostname: NXOSv-9k

# Using rendered

- name: Render platform specific configuration lines (without connecting to the device)
  cisco.nxos.nxos_hostname:
    config:
      hostname: NXOSv-9k

# Task Output (redacted)
# -----------------------
# rendered:
#   - hostname NXOSv-9k

# Using parsed

# parsed.cfg
# ------------
# hostname NXOSv-9k

- name: Parse externally provided hostname config
  cisco.nxos.nxos_hostname:
    running_config: "{{ lookup('file', 'parsed.cfg') }}"
    state: parsed

# Task output (redacted)
# -----------------------
# parsed:
#   hostname: NXOSv-9k
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
    - hostname switch01
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - hostname switch01
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

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.hostname.hostname import (
    HostnameArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.config.hostname.hostname import (
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
