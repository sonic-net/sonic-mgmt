#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for nxos_vrf_interfaces
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: nxos_vrf_interfaces
short_description: Resource module to configure VRF interfaces.
description: This module configures and manages the VRF configuration on interfaces on NX-OS platforms.
version_added: 9.3.0
author: Ruchi Pakhle (@Ruchip16)
notes:
  - Tested against Cisco NX-OS.
  - This module works with connection C(network_cli).
options:
  config:
    description: A list of interface VRF configurations.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Full name of the interface excluding any logical unit number,
            i.e. Ethernet1/1.
        type: str
        required: true
      vrf_name:
        description:
          - Name of the VRF to be configured on the interface.
          - When configured, applies 'vrf member <vrf_name>' under the interface.
        type: str
  running_config:
    description:
      - This option is used only with state I(parsed).
      - The value of this option should be the output received from the NX-OS
        device by executing the command B(show running-config interface).
      - The state I(parsed) reads the configuration from C(running_config)
        option and transforms it into Ansible structured data as per the
        resource module's argspec and the value is then returned in the
        I(parsed) key within the result.
    type: str
  state:
    description:
      - The state the configuration should be left in
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
# nxos#show running-config interface
# interface Ethernet1/1
#  no switchport
# interface Ethernet1/2
#  description test
#  no switchport
#  no shutdown
# interface Ethernet1/3
# interface Ethernet1/4
#  no switchport
#  speed 1000
#  no shutdown

- name: Merge provided configuration with device configuration
  cisco.nxos.nxos_vrf_interfaces:
    config:
      - name: Ethernet1/1
      - name: Ethernet1/2
        vrf_name: test
      - name: Ethernet1/3
      - name:Ethernet1/4
    state: merged

# Task Output:
# ------------
#
# before:
#   - name: "Ethernet1/1"
#   - name: "Ethernet1/2"
#   - name: "Ethernet1/3"
#   - name: "Ethernet1/4"
#
# commands:
#   - interface Ethernet1/2
#   - vrf member test
#
# after:
#   - name: "Ethernet1/1"
#   - name: "Ethernet1/2"
#     vrf_name: "test2"
#   - name: "Ethernet1/3"
#   - name: "Ethernet1/4"

# After state:
# ------------
#
# nxos#show running-config interface
# interface Ethernet1/1
#  no ip address
# interface Ethernet1/2
#  vrf member test
#  no ip address
#  shutdown
#  negotiation auto
# interface Ethernet1/3
#  no ip address
#  negotiation auto
# interfaceEthernet1/4
#  no ip address
#  shutdown
#  negotiation auto

# Using overridden

# Before state:
# -------------
#
# nxos#show running-config interface
# interface Ethernet1/1
#  no ip address
# interface Ethernet1/1
#  ip address dhcp
#  negotiation auto
# interface Ethernet1/2
#  vrf member vrf_B
#  no ip address
#  shutdown
#  negotiation auto
# interface Ethernet1/3
#  no ip address
#  negotiation auto
# interface Ethernet1/4
#  no ip address
#  shutdown
#  negotiation auto

- name: Override device configuration with provided configuration
  cisco.nxos.nxos_vrf_interfaces:
    config:
      - name: Ethernet1/1
      - name: Ethernet1/2
      - name: Ethernet1/3
      - name: Ethernet1/4
    state: overridden

# Task Output:
# ------------
#
# before:
#   - name: "Ethernet1/1"
#   - name: "Ethernet1/2"
#     vrf_name: "vrf_B"
#   - name: "Ethernet1/3"
#   - name: "Ethernet1/4"
#
# commands:
#   - interface Ethernet1/2
#   - no vrf member vrf_B
#
# after:
#   - name: "Ethernet1/1"
#   - name: "Ethernet1/2"
#   - name: "Ethernet1/3"
#   - name: "Ethernet1/4"

# After state:
# ------------
#
# nxos#show running-config interface
# interface Ethernet1/1
#  no ip address
# interface Ethernet1/2
#  no ip address
#  shutdown
#  negotiation auto
# interface Ethernet1/3
#  no ip address
#  negotiation auto
# interface Ethernet1/4
#  no ip address
#  shutdown
#  negotiation auto

# Using gathered

# Before state:
# -------------
#
# nxos#show running-config interface
# interface Ethernet1/1
#  no ip address
# interface Ethernet1/2
#  vrf member vrf_B
#  no ip address
#  shutdown
#  negotiation auto
# interface Ethernet1/3
#  no ip address
#  negotiation auto
# interfaceEthernet1/4
#  no ip address
#  shutdown
#  negotiation auto

- name: Gather listed VRF interfaces
  cisco.nxos.nxos_vrf_interfaces:
    state: gathered

# Task Output:
# ------------
#
# gathered:
#   - name: "Ethernet1/1"
#   - name: "Ethernet1/2"
#     vrf_name: "vrf_B"
#   - name: "Ethernet1/3"

# Using rendered

- name: Render VRF configuration
  cisco.nxos.nxos_vrf_interfaces:
    config:
      - name: Ethernet1/1
      - name: Ethernet1/2
        vrf_name: test
      - name: Ethernet1/3
      - name: Ethernet1/4
    state: rendered

# Task Output:
# ------------
#
# rendered:
#   - interface Ethernet1/2
#   - vrf member test

# Using parsed

# File: parsed.cfg
# ---------------
#
# interface Ethernet1/2
#   no switchport
#   vrf member VRF1
# interface Ethernet1/6
#   no switchport
#   speed 1000
#   vrf member TEST_VRF

- name: Parse configuration from device running config
  cisco.nxos.nxos_vrf_interfaces:
    running_config: "{{ lookup('file', 'parsed.cfg') }}"
    state: parsed

# Task Output:
# ------------
#
# parsed:
#   - name: "Ethernet1/2"
#     vrf_name: "VRF1"
#   - name: "Ethernet1/6"
#     vrf_name: "TEST_VRF"

# Using replaced

# Before state:
# -------------
#
# nxos#show running-config interface
# interface Ethernet1/1
#  no ip address
# interface Ethernet1/2
#  vrf member vrf_B
#  no ip address
#  shutdown
# interface Ethernet1/3
#  no ip address
# interfaceEthernet1/4
#  vrf member vrf_C
#  no ip address
#  shutdown

- name: Replace device configuration of listed VRF interfaces with provided configuration
  cisco.nxos.nxos_vrf_interfaces:
    config:
      - name: Ethernet1/1
        vrf_name: test
      - name: Ethernet1/2
        vrf_name: vrf_E
    state: replaced

# Task Output:
# ------------
#
# before:
#   - name: "Ethernet1/1"
#     vrf_name: "vrf_A"
#   - name: "Ethernet1/2"
#     vrf_name: "vrf_B"
#   - name: "Ethernet1/3"
#   - name: "Ethernet1/4"
#     vrf_name: "vrf_C"
#
# commands:
#   - interface Ethernet1/1
#   - no vrf member vrf_A
#   - vrf member test
#   - interface Ethernet1/2
#   - no vrf member vrf_B
#   - vrf member vrf_E
#
# after:
#   - name: "Ethernet1/1"
#     vrf_name: "test"
#   - name: "Ethernet1/2"
#     vrf_name: "vrf_E"
#   - name: "Ethernet1/3"
#   - name: "Ethernet1/4"
#     vrf_name: "vrf_C"

# Using deleted

# Before state:
# -------------
#
# nxos#show running-config interface
# interface Ethernet1/1
#  vrf member vrf_A
#  ip address dhcp
# interface Ethernet1/2
#  vrf member vrf_B
#  no ip address
#  shutdown
# interface Ethernet1/3
#  no ip address
# interfaceEthernet1/4
#  vrf member vrf_C
#  no ip address
#  shutdown

- name: Delete VRF configuration of specified interfaces
  cisco.nxos.nxos_vrf_interfaces:
    config:
      - name: Ethernet1/1
      - name: Ethernet1/2
    state: deleted

# Task Output:
# ------------
#
# before:
#   - name: "Ethernet1/1"
#     vrf_name: "vrf_A"
#   - name: "Ethernet1/2"
#     vrf_name: "vrf_B"
#   - name: "Ethernet1/3"
#   - name: "Ethernet1/4"
#     vrf_name: "vrf_C"
#
# commands:
#   - interface Ethernet1/1
#   - no vrf member vrf_A
#   - interface Ethernet1/2
#   - no vrf member vrf_B
#
# after:
#   - name: "Ethernet1/1"
#   - name: "Ethernet1/1"
#   - name: "Ethernet1/2"
#   - name: "Ethernet1/3"
#   - name: "Ethernet1/4"
#     vrf_name: "vrf_C"

# After state:
# ------------
#
# nxos#show running-config interface
# interface Ethernet1/1
#  ip address dhcp
# interface Ethernet1/2
#  no ip address
#  shutdown
# interface Ethernet1/3
#  no ip address
# interfaceEthernet1/4
#  vrf member vrf_C
#  no ip address
#  shutdown
"""

RETURN = """
before:
  description: The configuration prior to the module execution.
  returned: when I(state) is C(merged), C(replaced), C(overridden), C(deleted)
  type: list
  sample: >
    [
        {
            "name": "Ethernet1/1"
        },
        {
            "name": "Ethernet1/2",
            "vrf_name": "test"
        },
        {
            "name": "Ethernet1/3"
        },
        {
            "name": "Ethernet1/4"
        }
    ]

after:
  description: The resulting configuration after module execution.
  returned: when changed
  type: list
  sample: >
    [
        {
            "name": "Ethernet1/1"
        },
        {
            "name": "Ethernet1/2",
            "vrf_name": "test"
        },
        {
            "name": "Ethernet1/3"
        },
        {
            "name": "Ethernet1/4"
        }
    ]

commands:
  description: The set of commands pushed to the remote device.
  returned: when I(state) is C(merged), C(replaced), C(overridden), C(deleted)
  type: list
  sample:
    - "interface Ethernet1/2"
    - "vrf member test"
    - "no vrf member vrf_B"

rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - "interface Ethernet1/1"
    - "vrf member vrf_C"
    - "interface Ethernet1/2"
    - "vrf member test"

gathered:
  description: Facts about the network resource gathered from the remote device as structured data.
  returned: when I(state) is C(gathered)
  type: list
  sample: >
    [
        {
            "name": "Ethernet1/1"
        },
        {
            "name": "Ethernet1/2",
            "vrf_name": "vrf_B"
        },
        {
            "name": "Ethernet1/3"
        },
        {
            "name": "Ethernet1/4"
        }
    ]

parsed:
  description: The device native config provided in I(running_config) option parsed into structured data as per module argspec.
  returned: when I(state) is C(parsed)
  type: list
  sample: >
    [
        {
            "name": "Ethernet1/1",
            "vrf_name": "vrf_C"
        },
        {
            "name": "Ethernet1/2",
            "vrf_name": "test"
        },
        {
            "name": "Ethernet1/3"
        },
        {
            "name": "Ethernet1/4"
        }
    ]
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.vrf_interfaces.vrf_interfaces import (
    Vrf_interfacesArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.config.vrf_interfaces.vrf_interfaces import (
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
