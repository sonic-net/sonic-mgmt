#!/usr/bin/python
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

GENERATOR_VERSION = "1.0"


DOCUMENTATION = """
module: iosxr_l2_interfaces
short_description: Resource Module to configure L2 interfaces.
description: This module manages the Layer-2 interface attributes on Cisco IOS-XR
  devices.
version_added: 1.0.0
author:
- Sumit Jaiswal (@justjais)
- Rohit Thakur (@rohitthakur2590)
notes:
- This module works with connection C(network_cli). See L(the IOS-XR Platform Options,../network/user_guide/platform_iosxr.html).
options:
  config:
    description: A dictionary of Layer-2 interface options
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - Full name of the interface/sub-interface excluding any logical unit number,
          e.g. GigabitEthernet0/0/0/1 or GigabitEthernet0/0/0/1.100.
        type: str
        required: true
      native_vlan:
        description:
        - Configure a native VLAN ID for the trunk
        type: int
      l2transport:
        description:
        - Switchport mode access command to configure the interface as a layer 2 access
        type: bool
      l2protocol:
        description:
        - Configures Layer 2 protocol tunneling and protocol data unit (PDU) filtering
          on an interface.
        type: list
        elements: dict
        suboptions:
          cdp:
            description:
            - Cisco Discovery Protocol (CDP) tunneling and data unit parameters.
            choices:
            - drop
            - forward
            - tunnel
            type: str
          pvst:
            description:
            - Configures the per-VLAN Spanning Tree Protocol (PVST) tunneling and
              data unit parameters.
            choices:
            - drop
            - forward
            - tunnel
            type: str
          stp:
            description:
            - Spanning Tree Protocol (STP) tunneling and data unit parameters.
            choices:
            - drop
            - forward
            - tunnel
            type: str
          vtp:
            description:
            - VLAN Trunk Protocol (VTP) tunneling and data unit parameters.
            choices:
            - drop
            - forward
            - tunnel
            type: str
          cpsv:
            description:
              - CDP, PVST+, STP, and VTP protocols.
            choices:
            - drop
            - reverse-tunnel
            - tunnel
            type: str
      encapsulation:
        description: Specify which packets will be matched by this sub-interface.
        type: dict
        suboptions:
          dot1q:
            type: int
            description: IEEE 802.1Q VLAN-tagged packets.
          second_dot1q:
            type: int
            description: IEEE 802.1Q VLAN-tagged packets.
      q_vlan:
        description:
        - 802.1Q VLAN configuration. Note that it can accept either 2 VLAN IDs when
          configuring Q-in-Q VLAN, or it will accept 1 VLAN ID and 'any' as input
          list when configuring Q-in-any vlan as input. Note, that this option is
          valid only with respect to Sub-Interface and is not valid when configuring
          for Interface.
        - This option is DEPRECATED and replaced with qvlan,
          this attribute will be removed after 2026-06-01.
        type: list
        elements: int
      qvlan:
        description:
        - 802.1Q VLAN configuration. Note that it can accept either 2 VLAN IDs when
          configuring Q-in-Q VLAN, or it will accept 1 VLAN ID and 'any' as input
          list when configuring Q-in-any vlan as input. Note, that this option is
          valid only with respect to Sub-Interface and is not valid when configuring
          for Interface.
        type: list
        elements: str
      propagate:
        description:
        - Propagate Layer 2 transport events. Note that it will work only when the
          I(l2tranport) option is set to TRUE
        type: bool
  running_config:
    description:
    - This option is used only with state I(parsed).
    - The value of this option should be the output received from the IOS-XR device
      by executing the command B(show running-config interface).
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
    - rendered
    - gathered
    - parsed
    default: merged
    description:
    - The state of the configuration after module completion
    type: str
"""

EXAMPLES = """
# Using merged
#
# Before state:
# -------------
#
# viosxr#show running-config interface
# interface GigabitEthernet0/0/0/3
#  description Ansible Network
#  vrf custB
#  ipv4 address 10.10.0.2 255.255.255.0
#  duplex half
#  shutdown
# !
# interface GigabitEthernet0/0/0/4
#  description Test description
# !

- name: Merge provided configuration with device configuration
  cisco.iosxr.iosxr_l2_interfaces:
    config:
      - name: GigabitEthernet0/0/0/3
        native_vlan: 20
      - name: GigabitEthernet0/0/0/4
        native_vlan: 40
        l2transport: true
        l2protocol:
          - stp: tunnel
      - name: GigabitEthernet0/0/0/3.900
        l2transport: true
        q_vlan:
          - 20
          - 40
    state: merged


# After state:
# ------------
#
# viosxr#show running-config interface
# interface GigabitEthernet0/0/0/3
#  description Ansible Network
#  vrf custB
#  ipv4 address 10.10.0.2 255.255.255.0
#  duplex half
#  shutdown
#  dot1q native vlan 20
# !
# interface GigabitEthernet0/0/0/4
# description Test description
#  dot1q native vlan 10
#  l2transport
#   l2protocol stp tunnel
#  !
# !
# interface GigabitEthernet0/0/0/3.900 l2transport
#  dot1q vlan 20 40
# !

# Using replaced
#
# Before state:
# -------------
#
# viosxr#show running-config interface
# interface GigabitEthernet0/0/0/3
#  description Ansible Network
#  vrf custB
#  ipv4 address 10.10.0.2 255.255.255.0
#  duplex half
#  shutdown
#  dot1q native vlan 20
# !
# interface GigabitEthernet0/0/0/4
# description Test description
#  dot1q native vlan 10
#  l2transport
#   l2protocol stp tunnel
#  !
# !
# interface GigabitEthernet0/0/0/3.900 l2transport
#  dot1q vlan 20 40
# !

- name: >-
    Replaces device configuration of listed interfaces with provided
    configuration
  cisco.iosxr.iosxr_l2_interfaces:
    config:
      - name: GigabitEthernet0/0/0/4
        native_vlan: 40
        l2transport: true
        l2protocol:
          - stp: forward
      - name: GigabitEthernet0/0/0/3.900
        q_vlan:
          - 20
          - any
    state: replaced


# After state:
# -------------
#
# viosxr#show running-config interface
# interface GigabitEthernet0/0/0/3
#  description Ansible Network
#  vrf custB
#  ipv4 address 10.10.0.2 255.255.255.0
#  duplex half
#  shutdown
#  dot1q native vlan 20
# !
# interface GigabitEthernet0/0/0/4
# description Test description
#  dot1q native vlan 40
#  l2transport
#   l2protocol stp forward
#  !
# !
# interface GigabitEthernet0/0/0/3.900 l2transport
#  dot1q vlan 20 any
# !

# Using overridden
#
# Before state:
# -------------
#
# viosxr#show running-config interface
# interface GigabitEthernet0/0/0/3
#  description Ansible Network
#  vrf custB
#  ipv4 address 10.10.0.2 255.255.255.0
#  duplex half
#  shutdown
#  dot1q native vlan 20
# !
# interface GigabitEthernet0/0/0/4
# description Test description
#  dot1q native vlan 10
#  l2transport
#   l2protocol stp tunnel
#  !
# !
# interface GigabitEthernet0/0/0/3.900 l2transport
#  dot1q vlan 20 40
# !

- name: Override device configuration of all interfaces with provided configuration
  cisco.iosxr.iosxr_l2_interfaces:
    config:
      - name: GigabitEthernet0/0/0/4
        native_vlan: 40
        l2transport: true
        l2protocol:
          - stp: forward
      - name: GigabitEthernet0/0/0/3.900
        q_vlan:
          - 20
          - any
    state: overridden


# After state:
# -------------
#
# viosxr#show running-config interface
# interface GigabitEthernet0/0/0/3
#  description Ansible Network
#  vrf custB
#  ipv4 address 10.10.0.2 255.255.255.0
#  duplex half
#  shutdown
# !
# interface GigabitEthernet0/0/0/4
# description Test description
#  dot1q native vlan 40
#  l2transport
#   l2protocol stp forward
#  !
# !
# interface GigabitEthernet0/0/0/3.900
#  dot1q vlan 20 any
# !

# Using deleted
#
# Before state:
# -------------
#
# viosxr#show running-config interface
# interface GigabitEthernet0/0/0/3
#  description Ansible Network
#  vrf custB
#  ipv4 address 10.10.0.2 255.255.255.0
#  duplex half
#  shutdown
#  dot1q native vlan 20
# !
# interface GigabitEthernet0/0/0/4
#  description Test description
#  dot1q native vlan 10
#  l2transport
#   l2protocol stp tunnel
#  !
# !
#

- name: "Delete L2 attributes of given interfaces (Note: This won't delete the interface itself)"
  cisco.iosxr.iosxr_l2_interfaces:
    config:
      - name: GigabitEthernet0/0/0/4
    state: deleted

# After state:
# ------------
#
# viosxr#show running-config interface
# interface GigabitEthernet0/0/0/3
#  description Ansible Network
#  vrf custB
#  ipv4 address 10.10.0.2 255.255.255.0
#  duplex half
#  shutdown
#  dot1q native vlan 20
# !
# interface GigabitEthernet0/0/0/4
#  description Test description
# !

# Using Deleted without any config passed
# "(NOTE: This will delete all of configured resource module attributes from each configured interface)"
#
# Before state:
# -------------
#
# viosxr#show running-config interface
# interface GigabitEthernet0/0/0/3
#  description Ansible Network
#  vrf custB
#  ipv4 address 10.10.0.2 255.255.255.0
#  duplex half
#  shutdown
#  dot1q native vlan 20
# !
# interface GigabitEthernet0/0/0/4
#  description Test description
#  dot1q native vlan 10
#  l2transport
#   l2protocol stp tunnel
#  !
# !

- name: "Delete L2 attributes of all interfaces (Note: This won't delete the interface itself)"
  cisco.iosxr.iosxr_l2_interfaces:
    state: deleted

# After state:
# ------------
#
# viosxr#show running-config interface
# interface GigabitEthernet0/0/0/3
#  description Ansible Network
#  vrf custB
#  ipv4 address 10.10.0.2 255.255.255.0
#  duplex half
#  shutdown
# !
# interface GigabitEthernet0/0/0/4
#  description Test description
# !


# Using parsed
# parsed.cfg
# ------------
#
# interface Loopback888
#  description test for ansible
#  shutdown
# !
# interface MgmtEth0/0/CPU0/0
#  ipv4 address 10.8.38.70 255.255.255.0
# !
# interface GigabitEthernet0/0/0/0
#  description Configured and Merged by Ansible-Network
#  mtu 110
#  ipv4 address 172.31.1.1 255.255.255.0
#  duplex half
# !
# interface GigabitEthernet0/0/0/1
#  dot1q native vlan 10
#  l2transport
#   l2protocol cdp forward
#   l2protocol pvst tunnel
#   propagate remote-status
#  !
# !
# interface GigabitEthernet0/0/0/3
#  shutdown
# !
# interface GigabitEthernet0/0/0/3.900
#  encapsulation dot1q 20 second-dot1q 40
# !
# interface GigabitEthernet0/0/0/4
#  shutdown
#  dot1q native vlan 40
# !
- name: Convert L2 interfaces config to argspec without connecting to the appliance
  cisco.iosxr.iosxr_l2_interfaces:
    running_config: "{{ lookup('file', './parsed.cfg') }}"
    state: parsed
# Task Output (redacted)
# -----------------------
# "parsed": [
#         {
#             "name": "GigabitEthernet0/0/0/0"
#         },
#         {
#             "l2protocol": [
#                 {
#                     "cdp": "forward"
#                 },
#                 {
#                     "pvst": "tunnel"
#                 }
#             ],
#             "l2transport": true,
#             "name": "GigabitEthernet0/0/0/1",
#             "native_vlan": 10,
#             "propagate": true
#         },
#         {
#             "name": "GigabitEthernet0/0/0/3"
#         },
#         {
#             "name": "GigabitEthernet0/0/0/3.900",
#             "q_vlan": [
#                 20,
#                 40
#             ]
#         },
#         {
#             "name": "GigabitEthernet0/0/0/4",
#             "native_vlan": 40
#         }
#     ]


# Using rendered
- name: Render platform specific commands from task input using rendered state
  cisco.iosxr.iosxr_l2_interfaces:
    config:
      - name: GigabitEthernet0/0/0/1
        native_vlan: 10
        l2transport: true
        l2protocol:
          - pvst: tunnel
          - cdp: forward
        propagate: true
      - name: GigabitEthernet0/0/0/3.900
        q_vlan:
          - 20
          - 40
      - name: GigabitEthernet0/0/0/4
        native_vlan: 40
    state: rendered

# Task Output (redacted)
# -----------------------
# "rendered": [
#         "interface GigabitEthernet0/0/0/1",
#         "dot1q native vlan 10",
#         "l2transport l2protocol pvst tunnel",
#         "l2transport l2protocol cdp forward",
#         "l2transport propagate remote-status",
#         "interface GigabitEthernet0/0/0/3.900",
#         "dot1q vlan 20 40",
#         "interface GigabitEthernet0/0/0/4",
#         "dot1q native vlan 40"
#     ]


# Using gathered
# Before state:
# ------------
#
# RP/0/0/CPU0:an-iosxr-02#show running-config  interface
# interface Loopback888
#  description test for ansible
#  shutdown
# !
# interface MgmtEth0/0/CPU0/0
#  ipv4 address 10.8.38.70 255.255.255.0
# !
# interface GigabitEthernet0/0/0/0
#  description Configured and Merged by Ansible-Network
#  mtu 110
#  ipv4 address 172.31.1.1 255.255.255.0
#  duplex half
# !
# interface GigabitEthernet0/0/0/1
#  dot1q native vlan 10
#  l2transport
#   l2protocol cdp forward
#   l2protocol pvst tunnel
#   propagate remote-status
#  !
# !
# interface GigabitEthernet0/0/0/3
#  shutdown
# !
# interface GigabitEthernet0/0/0/3.900
#  encapsulation dot1q 20 second-dot1q 40
# !
# interface GigabitEthernet0/0/0/4
#  shutdown
#  dot1q native vlan 40
# !
- name: Gather IOSXR l2 interfaces as in given arguments
  cisco.iosxr.iosxr_l2_interfaces:
    config:
    state: gathered
# Task Output (redacted)
# -----------------------
#
# "gathered": [
#         {
#             "name": "GigabitEthernet0/0/0/0"
#         },
#         {
#             "l2protocol": [
#                 {
#                     "cdp": "forward"
#                 },
#                 {
#                     "pvst": "tunnel"
#                 }
#             ],
#             "l2transport": true,
#             "name": "GigabitEthernet0/0/0/1",
#             "native_vlan": 10,
#             "propagate": true
#         },
#         {
#             "name": "GigabitEthernet0/0/0/3"
#         },
#         {
#             "name": "GigabitEthernet0/0/0/3.900",
#             "q_vlan": [
#                 20,
#                 40
#             ]
#         },
#         {
#             "name": "GigabitEthernet0/0/0/4",
#             "native_vlan": 40
#         }
#     ]
# After state:
# ------------
#
# RP/0/0/CPU0:an-iosxr-02#show running-config  interface
# interface Loopback888
#  description test for ansible
#  shutdown
# !
# interface MgmtEth0/0/CPU0/0
#  ipv4 address 10.8.38.70 255.255.255.0
# !
# interface GigabitEthernet0/0/0/0
#  description Configured and Merged by Ansible-Network
#  mtu 110
#  ipv4 address 172.31.1.1 255.255.255.0
#  duplex half
# !
# interface GigabitEthernet0/0/0/1
#  dot1q native vlan 10
#  l2transport
#   l2protocol cdp forward
#   l2protocol pvst tunnel
#   propagate remote-status
#  !
# !
# interface GigabitEthernet0/0/0/3
#  shutdown
# !
# interface GigabitEthernet0/0/0/3.900
#  encapsulation dot1q 20 second-dot1q 40
# !
# interface GigabitEthernet0/0/0/4
#  shutdown
#  dot1q native vlan 40
# !
"""

RETURN = """
before:
  description: The configuration as structured data prior to module invocation.
  returned: always
  type: list
  sample: The configuration returned will always be in the same format of the parameters above.
after:
  description: The configuration as structured data after module completion.
  returned: when changed
  type: list
  sample: The configuration returned will always be in the same format of the parameters above.
commands:
  description: The set of commands pushed to the remote device
  returned: always
  type: list
  sample: ['interface GigabitEthernet0/0/0/2', 'l2transport l2protocol pvst tunnel']
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.l2_interfaces.l2_interfaces import (
    L2_InterfacesArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.config.l2_interfaces.l2_interfaces import (
    L2_Interfaces,
)


def main():
    """
    Main entry point for module execution
    :returns: the result form module invocation
    """
    required_if = [
        ("state", "merged", ("config",)),
        ("state", "replaced", ("config",)),
        ("state", "rendered", ("config",)),
        ("state", "overridden", ("config",)),
        ("state", "parsed", ("running_config",)),
    ]
    mutually_exclusive = [("config", "running_config")]
    module = AnsibleModule(
        argument_spec=L2_InterfacesArgs.argument_spec,
        required_if=required_if,
        supports_check_mode=True,
        mutually_exclusive=mutually_exclusive,
    )

    result = L2_Interfaces(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
