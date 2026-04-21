#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for iosxr_vrf_interfaces
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: iosxr_vrf_interfaces
short_description: Resource module to configure VRF interfaces.
description: This module configures and manages the VRF configuration in interface on IOS XR platforms.
version_added: 10.3.0
author: Sagar Paul (@KB-perByte)
notes:
  - Tested against Cisco IOS-XR 7.2.2.
  - This module works with connection C(network_cli).
options:
  config:
    description: A list of VRF interfaces options.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Full name of the interface excluding any logical unit number,
            i.e. GigabitEthernet0/0/0/1.
        type: str
        required: true
      vrf_name:
        description:
          - Vrf that is to be added to the interface.
        type: str
  running_config:
    description:
      - This option is used only with state I(parsed).
      - The value of this option should be the output received from the IOS
        device by executing the command B(sh running-config interface).
      - The state I(parsed) reads the configuration from C(running_config)
        option and transforms it into Ansible structured data as per the
        resource module's argspec and the value is then returned in the
        I(parsed) key within the result.
    type: str
  state:
    description:
      - The state the configuration should be left in
      - The states I(rendered), I(gathered) and I(parsed) does not perform any
        change on the device.
      - The state I(rendered) will transform the configuration in C(config)
        option to platform specific CLI commands which will be returned in the
        I(rendered) key within the result. For state I(rendered) active
        connection to remote host is not required.
      - The state I(gathered) will fetch the running configuration from device
        and transform it into structured data in the format as per the resource
        module argspec and the value is returned in the I(gathered) key within
        the result.
      - The state I(parsed) reads the configuration from C(running_config)
        option and transforms it into JSON format as per the resource module
        parameters and the value is returned in the I(parsed) key within the
        result. The value of C(running_config) option should be the same format
        as the output of command I(show running-config | include ip route|ipv6
        route) executed on device. For state I(parsed) active connection to
        remote host is not required.
    type: str
    choices:
      - merged
      - replaced
      - overridden
      - deleted
      - gathered
      - rendered
      - parsed
    default: merged
"""

EXAMPLES = """
# Using merged

# Before state:
# -------------
#
# viosxr#show running-config interfaces
# interface MgmtEth0/RP0/CPU0/0
#  ipv4 address dhcp
# !
# interface GigabitEthernet0/0/0/0
#  description this is interface0
#  cdp
# !
# interface GigabitEthernet0/0/0/1
#  shutdown
# !
# interface GigabitEthernet0/0/0/2
#  shutdown
# !

- name: Simple merge selective
  cisco.iosxr.iosxr_vrf_interfaces:
    state: merged
    config:
      - name: MgmtEth0/RP0/CPU0/0
      - name: GigabitEthernet0/0/0/0
      - name: GigabitEthernet0/0/0/1
        vrf_name: vrf_C
      - name: GigabitEthernet0/0/0/2
        vrf_name: vrf_D

# Task Output
# -----------
#
# before:
#   - name: MgmtEth0/RP0/CPU0/0
#   - name: GigabitEthernet0/0/0/0
#   - name: GigabitEthernet0/0/0/1
#   - name: GigabitEthernet0/0/0/2
# commands:
#   - interface GigabitEthernet0/0/0/1
#   - vrf vrf_C
#   - interface GigabitEthernet0/0/0/2
#   - vrf vrf_D
# after:
#   - name: MgmtEth0/RP0/CPU0/0
#   - name: GigabitEthernet0/0/0/0
#   - name: GigabitEthernet0/0/0/1
#     vrf_name: vrf_C
#   - name: GigabitEthernet0/0/0/2
#     vrf_name: vrf_D

# After state:
# -------------
#
# viosxr#show running-config interfaces
# interface MgmtEth0/RP0/CPU0/0
#  ipv4 address dhcp
# !
# interface GigabitEthernet0/0/0/0
#  description this is interface0
#  cdp
# !
# interface GigabitEthernet0/0/0/1
#  vrf vrf_C
#  shutdown
# !
# interface GigabitEthernet0/0/0/2
#  vrf vrf_D
#  shutdown
# !

# Using replaced

# Before state:
# -------------
#
# viosxr#show running-config interfaces
# interface MgmtEth0/RP0/CPU0/0
#  ipv4 address dhcp
# !
# interface GigabitEthernet0/0/0/0
#  description this is interface0
#  cdp
# !
# interface GigabitEthernet0/0/0/1
#  vrf vrf_C
#  shutdown
# !
# interface GigabitEthernet0/0/0/2
#  vrf vrf_D
#  shutdown
# !

- name: Simple replaced selective
  cisco.iosxr.iosxr_vrf_interfaces:
    state: replaced
    config:
      - name: MgmtEth0/RP0/CPU0/0
      - name: GigabitEthernet0/0/0/0
      - name: GigabitEthernet0/0/0/1
        vrf_name: vrf_E
      - name: GigabitEthernet0/0/0/2
        vrf_name: vrf_D

# Task Output
# -----------
#
# before:
#   - name: MgmtEth0/RP0/CPU0/0
#   - name: GigabitEthernet0/0/0/0
#   - name: GigabitEthernet0/0/0/1
#     vrf_name: vrf_C
#   - name: GigabitEthernet0/0/0/2
#     vrf_name: vrf_D
# commands:
#   - interface GigabitEthernet0/0/0/1
#   - vrf vrf_E
# after:
#   - name: MgmtEth0/RP0/CPU0/0
#   - name: GigabitEthernet0/0/0/0
#   - name: GigabitEthernet0/0/0/1
#     vrf_name: vrf_E
#   - name: GigabitEthernet0/0/0/2
#     vrf_name: vrf_D

# After state:
# -------------
#
# viosxr#show running-config interfaces
# interface MgmtEth0/RP0/CPU0/0
#  ipv4 address dhcp
# !
# interface GigabitEthernet0/0/0/0
#  description this is interface0
#  cdp
# !
# interface GigabitEthernet0/0/0/1
#  vrf vrf_E
#  shutdown
# !
# interface GigabitEthernet0/0/0/2
#  vrf vrf_D
#  shutdown
# !

# Using overridden

# Before state:
# -------------
#
# viosxr#show running-config interfaces
# interface MgmtEth0/RP0/CPU0/0
#  ipv4 address dhcp
# !
# interface GigabitEthernet0/0/0/0
#  description this is interface0
#  cdp
# !
# interface GigabitEthernet0/0/0/1
#  vrf vrf_C
#  shutdown
# !
# interface GigabitEthernet0/0/0/2
#  vrf vrf_D
#  shutdown
# !

- name: Simple overridden selective
  cisco.iosxr.iosxr_vrf_interfaces:
    state: overridden
    config:
      - name: MgmtEth0/RP0/CPU0/0
      - name: GigabitEthernet0/0/0/0
      - name: GigabitEthernet0/0/0/1
        vrf_name: vrf_E

# Task Output
# -----------
#
# before:
#   - name: MgmtEth0/RP0/CPU0/0
#   - name: GigabitEthernet0/0/0/0
#   - name: GigabitEthernet0/0/0/1
#     vrf_name: vrf_C
#   - name: GigabitEthernet0/0/0/2
#     vrf_name: vrf_D
# commands:
#   - interface GigabitEthernet0/0/0/1
#   - vrf vrf_E
#   - interface GigabitEthernet0/0/0/2
#   - no vrf vrf_E
# after:
#   - name: MgmtEth0/RP0/CPU0/0
#   - name: GigabitEthernet0/0/0/0
#   - name: GigabitEthernet0/0/0/1
#     vrf_name: vrf_E
#   - name: GigabitEthernet0/0/0/2

# After state:
# -------------
#
# viosxr#show running-config interfaces
# interface MgmtEth0/RP0/CPU0/0
#  ipv4 address dhcp
# !
# interface GigabitEthernet0/0/0/0
#  description this is interface0
#  cdp
# !
# interface GigabitEthernet0/0/0/1
#  vrf vrf_E
#  shutdown
# !
# interface GigabitEthernet0/0/0/2
#  shutdown
# !

# Using deleted

# Before state:
# -------------
#
# viosxr#show running-config interfaces
# interface MgmtEth0/RP0/CPU0/0
#  ipv4 address dhcp
# !
# interface GigabitEthernet0/0/0/0
#  description this is interface0
#  cdp
# !
# interface GigabitEthernet0/0/0/1
#  vrf vrf_E
#  shutdown
# !
# interface GigabitEthernet0/0/0/2
#  vrf vrf_D
#  shutdown
# !

- name: Simple deleted selective
  cisco.iosxr.iosxr_vrf_interfaces:
    state: deleted
    config:
      - name: GigabitEthernet0/0/0/1
        vrf_name: vrf_E

# Task Output
# -----------
#
# before:
#   - name: MgmtEth0/RP0/CPU0/0
#   - name: GigabitEthernet0/0/0/0
#   - name: GigabitEthernet0/0/0/1
#     vrf_name: vrf_E
#   - name: GigabitEthernet0/0/0/2
#     vrf_name: vrf_D
# commands:
#   - interface GigabitEthernet0/0/0/1
#   - no vrf vrf_E
# after:
#   - name: MgmtEth0/RP0/CPU0/0
#   - name: GigabitEthernet0/0/0/0
#   - name: GigabitEthernet0/0/0/1
#   - name: GigabitEthernet0/0/0/2
#     vrf_name: vrf_D

# After state:
# -------------
#
# viosxr#show running-config interfaces
# interface MgmtEth0/RP0/CPU0/0
#  ipv4 address dhcp
# !
# interface GigabitEthernet0/0/0/0
#  description this is interface0
#  cdp
# !
# interface GigabitEthernet0/0/0/1
#  shutdown
# !
# interface GigabitEthernet0/0/0/2
#  vrf vrf_D
#  shutdown
# !

# Using gathered

# Before state:
# -------------
#
# viosxr#show running-config interfaces
# interface MgmtEth0/RP0/CPU0/0
#  ipv4 address dhcp
# !
# interface GigabitEthernet0/0/0/0
#  description this is interface0
#  cdp
# !
# interface GigabitEthernet0/0/0/1
#  vrf vrf_C
#  shutdown
# !
# interface GigabitEthernet0/0/0/2
#  vrf vrf_D
#  shutdown
# !

- name: Simple gathered selective
  cisco.iosxr.iosxr_vrf_interfaces:
    state: gathered

# Task Output
# -----------
#
# gathered:
#   - name: MgmtEth0/RP0/CPU0/0
#   - name: GigabitEthernet0/0/0/0
#   - name: GigabitEthernet0/0/0/1
#     vrf_name: vrf_C
#   - name: GigabitEthernet0/0/0/2
#     vrf_name: vrf_D

# Using rendered

# Before state:
# -------------
#
# viosxr#show running-config interfaces
# interface MgmtEth0/RP0/CPU0/0
#  ipv4 address dhcp
# !
# interface GigabitEthernet0/0/0/0
#  description this is interface0
#  cdp
# !
# interface GigabitEthernet0/0/0/1
#  vrf vrf_C
#  shutdown
# !
# interface GigabitEthernet0/0/0/2
#  vrf vrf_D
#  shutdown
# !

- name: Simple rendered selective
  cisco.iosxr.iosxr_vrf_interfaces:
    state: rendered

# Task Output
# -----------
#
# commands:
#   - interface GigabitEthernet0/0/0/1
#   - vrf vrf_C
#   - interface GigabitEthernet0/0/0/2
#   - vrf vrf_D
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
    - interface GigabitEthernet0/0/0/1
    - no vrf test_vrf1
    - vrf test_vrf2
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - interface GigabitEthernet0/0/0/1
    - no vrf test_vrf1
    - vrf test_vrf2
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

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.vrf_interfaces.vrf_interfaces import (
    Vrf_interfacesArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.config.vrf_interfaces.vrf_interfaces import (
    Vrf_interfaces,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=Vrf_interfacesArgs.argument_spec,
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

    result = Vrf_interfaces(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
