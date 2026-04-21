#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for nxos_l3_interfaces
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: nxos_l3_interfaces
short_description: L3 interfaces resource module
description: This module manages Layer-3 interfaces attributes of NX-OS Interfaces.
version_added: 1.0.0
author:
  - Trishna Guha (@trishnaguha)
  - Nikhil Bhasin (@nickbhasin)
notes:
- Tested against NXOS 7.3.(0)D1(1) on VIRL
- Unsupported for Cisco MDS
options:
  config:
    description: A dictionary of Layer-3 interface options
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - Full name of L3 interface, i.e. Ethernet1/1.
        type: str
        required: true
      mac_address:
        description: >-
          Manually set interface MAC address or extract the MAC address (3) from the
          IPv6 address configured on the interface.
        type: str
      bandwidth:
        description: Manually set the bandwidth
        type: dict
        suboptions:
          kilobits:
            description: Bandwidth in kilobits
            type: int
          inherit:
            description: Specify that bandwidth is inherited
            type: bool
      dot1q:
        description:
        - Configures IEEE 802.1Q VLAN encapsulation on a subinterface.
        type: int
      evpn_multisite_tracking:
        description:
        -  VxLAN evpn multisite Interface tracking. Supported only on selected model.
        type: str
        version_added: 1.1.0
        choices:
        - fabric-tracking
        - dci-tracking
      ipv6_redirects:
            description:
            - Enables/disables ipv6 redirects.
            type: bool
      ipv6_unreachables:
            description:
            - Enables/disables ip redirects.
            type: bool
      redirects:
            description:
            - Enables/disables ipv4 redirects.
            type: bool
      unreachables:
            description:
            - Enables/disables ip redirects.
            type: bool
      proxy_arp:
            description: Configure proxy ARP.
            type: bool
      port_unreachable:
        description: Enable sending ICMP port-unreachable.
        type: bool
      verify:
        description: Configure Unicast Reverse Path Forwarding or IP Source Guard.
        type: dict
        suboptions:
          unicast:
            description: Unicast Reverse Path Forwarding.
            type: dict
            suboptions:
              source:
                description: Validation of source address.
                type: dict
                suboptions:
                  reachable_via:
                    description: Specify reachability check to apply to the source address.
                    type: dict
                    suboptions:
                      mode:
                        description: Source is reachable via any/rx interface.
                        type: str
                      allow_default:
                        description: Loose Default Route Unicast Reverse Path Forwarding.
                        type: bool
      ipv6_verify:
        description: Unicast Reverse Path Forwarding.
        type: dict
        suboptions:
          unicast:
            description: Unicast Reverse Path Forwarding.
            type: dict
            suboptions:
              source:
                description: Validation of source address.
                type: dict
                suboptions:
                  reachable_via:
                    description: Specify reachability check to apply to the source address.
                    type: dict
                    suboptions:
                      mode:
                        description: Source is reachable via any/rx interface.
                        type: str
                      allow_default:
                        description: Loose Default Route Unicast Reverse Path Forwarding.
                        type: bool
      dhcp:
        description: Configure DHCP snooping or relay
        type: dict
        suboptions:
          ipv4:
            description: DHCP snooping for ipv4
            type: dict
            suboptions:
              option82:
                description: DHCP option82.
                type: dict
                suboptions:
                  suboption:
                    description: DHCP option82.
                    type: dict
                    suboptions:
                      circuit_id:
                        description: DHCP option82 suboption circuit-id string configuration.
                        type: str
              smart_relay:
                description: Configure DHCP smart relay on interface.
                type: bool
              relay:
                description: Configure relay agent.
                type: dict
                suboptions:
                  information:
                    description: Relay agent information option.
                    type: dict
                    suboptions:
                      trusted:
                        description: Enable relay trust on this interface.
                        type: bool
                  subnet_selection:
                    description: Configure gateway address for DHCP relay
                    type: dict
                    suboptions:
                      subnet_ip:
                        description: IP address
                        type: str
                  source_interface:
                    description: Configure gateway address for DHCP relay
                    type: dict
                    suboptions:
                      interface_type:
                        description: Type of interface
                        type: str
                      interface_id:
                        description: Interface ID
                        type: str
                  address:
                    description: List of ipv4 relay addresses
                    type: list
                    elements: dict
                    suboptions:
                      relay_ip:
                        description: IP address
                        type: str
                      vrf_name:
                        description: Helper address VRF membership
                        type: str
          ipv6:
            description: DHCP snooping for ipv6
            type: dict
            suboptions:
              smart_relay:
                description: Configure DHCP smart relay on interface.
                type: bool
              relay:
                description: Configure relay agent.
                type: dict
                suboptions:
                  source_interface:
                    description: Configure source interface for DHCPv6 relay.
                    type: dict
                    suboptions:
                      interface_type:
                        description: Type of interface
                        type: str
                      interface_id:
                        description: Interface ID
                        type: str
                  address:
                    description: Configure DHCPv6 server relay address
                    type: list
                    elements: dict
                    suboptions:
                      relay_ip:
                        description: IP address
                        type: str
                      vrf_name:
                        description: Helper address VRF membership
                        type: str
                      interface_type:
                        description: Type of interface
                        type: str
                      interface_id:
                        description: Interface ID
                        type: str
      ipv4:
        description: IPv4 address and attributes of the L3 interface.
        type: list
        elements: dict
        suboptions:
          address:
            description:
            - IPV4 address of the L3 interface.
            type: str
          tag:
            description:
            - URIB route tag value for local/direct routes.
            type: int
          secondary:
            description:
            - A boolean attribute to manage addition of secondary IP address.
            type: bool
          ip_network_mask:
                description: IP prefix and network mask length in format x.x.x.x/m or IP network mask in format m.m.m.m
                type: str
          route_preference:
                description: URIB route preference for local/direct routes
                type: int
      ipv6:
        description: IPv6 address and attributes of the L3 interface.
        type: list
        elements: dict
        suboptions:
          address:
            description: IPV6 address of the L3 interface.
            type: str
          tag:
            description: URIB route tag value for local/direct routes.
            type: int
          aggregate_prefix_length:
            description: Prefix-Length for AM Route Aggregation
            type: int
          anycast:
            description: Configure IPv6 anycast address on interface
            type: bool
          eui64:
            description: Configure Extended Unique Identifier for the low-order 64 bits
            type: bool
          route_preference:
            description: URIB route preference for local/direct routes
            type: int
          use_bia:
            description: Use BIA
            type: bool
  running_config:
    description:
      - This option is used only with state I(parsed).
      - >-
        The value of this option should be the output received from the IOS
        device by executing the command B(show running-config | section
        ^interface).
      - >-
        The state I(parsed) reads the configuration from C(running_config)
        option and transforms it into Ansible structured data as per the
        resource module's argspec and the value is then returned in the
        I(parsed) key within the result.
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
      - The state the configuration should be left in
      - >-
        The states I(rendered), I(gathered) and I(parsed) does not perform any
        change on the device.
      - >-
        The state I(rendered) will transform the configuration in C(config)
        option to platform specific CLI commands which will be returned in the
        I(rendered) key within the result. For state I(rendered) active
        connection to remote host is not required.
      - >-
        The state I(gathered) will fetch the running configuration from device
        and transform it into structured data in the format as per the resource
        module argspec and the value is returned in the I(gathered) key within
        the result.
      - >-
        The state I(parsed) reads the configuration from C(running_config)
        option and transforms it into JSON format as per the resource module
        parameters and the value is returned in the I(parsed) key within the
        result. The value of C(running_config) option should be the same format
        as the output of command I(show running-config | section ^interface)
        executed on device. For state I(parsed) active connection to remote host
        is not required.
    type: str
"""

EXAMPLES = """
# Using merged

# Before state:
# -------------
#
# router# show running-config | section interface
# interface Ethernet1/1
# interface Ethernet1/2

- name: Merge provided configuration with device configuration.
  cisco.nxos.nxos_l3_interfaces:
    config:
      - name: Ethernet1/1
        mac_address: 0011.2233.4455
        ipv4:
          verify:
            unicast:
              source:
                reachable_via:
                  mode: any
                  allow_default: true
          dhcp:
            relay:
              address:
                - relay_ip: 11.0.0.1
                  vrf_name: abc
      - name: Ethernet1/2
        ipv6:
          addresses:
            - ipv6_address: 2001:db8::1/32
              route_preference: 70
              tag: 97
          dhcp:
            relay:
              address:
                - relay_ip: 2001:db8::1:abcd
    state: merged

# Task Output
# -----------
#
# before:
# - name: Ethernet1/1
# - name: Ethernet1/2
# commands:
# - interface Ethernet1/1
# - mac-address 0011.2233.4455
# - ip verify unicast source reachable-via any allow-default
# - ip dhcp relay address 11.0.0.1 use-vrf abc
# - interface Ethernet1/2
# - ipv6 address 2001:db8::1/32 route-preference 70 tag 97
# - ipv6 dhcp relay address 2001:db8::1:abcd
# after:
# - name: Ethernet1/1
#   mac_address: 0011.2233.4455
#   ipv4:
#     verify:
#       unicast:
#         source:
#           reachable_via:
#             mode: any
#             allow_default: true
#     dhcp:
#       relay:
#         address:
#           - relay_ip: 11.0.0.1
#             vrf_name: abc
# - name: Ethernet1/2
#   ipv6:
#     addresses:
#       - ipv6_address: 2001:db8::1/32
#         route_preference: 70
#         tag: 97
#     dhcp:
#       relay:
#         address:
#           - relay_ip: 2001:db8::1:abcd

# After state:
# ------------
#
# router# show running-config | section interface
# interface Ethernet1/1
#  mac-address 0011.2233.4455
#  ip verify unicast source reachable-via any allow-default
#  ip dhcp relay address 11.0.0.1 use-vrf abc
# interface Ethernet1/2
#  ipv6 address 2001:db8::1/32 route-preference 70 tag 97
#  ipv6 dhcp relay address 2001:db8::1:abcd


# Using replaced

# Before state:
# -------------
#
# router# show running-config | section interface
# interface Ethernet 1/1
#  mac-address 00:11:22:33:44:55
#  ip verify unicast source reachable-via any allow-default
#  ip dhcp relay address 11.0.0.1 use-vrf abc
# interface Ethernet 1/2
#  ipv6 dhcp relay address 2001:0db8::1:abcd
#  ipv6 address 2001:db8::1/32 route-preference 70 tag 97

- name: Replace device configuration of specified L3 interfaces with provided configuration.
  cisco.nxos.nxos_l3_interfaces:
    config:
      - name: Ethernet1/2
        mac_address: 0011.2233.4456
        ipv6:
          addresses:
            - ipv6_address: 2001:db8::1/32
              route_preference: 200
              tag: 22
          dhcp:
            relay:
              address:
                - relay_ip: 2001:db8::1:abcd
    state: replaced

# Task Output
# -----------
#
# before:
# - name: Ethernet1/1
#   mac_address: 0011.2233.4455
#   ipv4:
#     verify:
#       unicast:
#         source:
#           reachable_via:
#             mode: any
#             allow_default: true
#     dhcp:
#       relay:
#         address:
#           - relay_ip: 11.0.0.1
#             vrf_name: abc
# - name: Ethernet1/2
#   ipv6:
#     addresses:
#       - ipv6_address: 2001:db8::1/32
#         route_preference: 70
#         tag: 97
#     dhcp:
#       relay:
#         address:
#           - relay_ip: 2001:db8::1:abcd
# commands:
# - interface Ethernet1/2
# - no ipv6 address 2001:db8::1/32 route-preference 70 tag 97
# - ipv6 address 2001:db8::1/32 route-preference 200 tag 22
# - mac-address 0011.2233.4456
# after:
# - name: Ethernet1/1
#   mac_address: 0011.2233.4455
#   ipv4:
#     verify:
#       unicast:
#         source:
#           reachable_via:
#             mode: any
#             allow_default: true
#     dhcp:
#       relay:
#         address:
#           - relay_ip: 11.0.0.1
#             vrf_name: abc
# - name: Ethernet1/2
#   mac_address: 0011.2233.4456
#   ipv6:
#     addresses:
#       - ipv6_address: 2001:db8::1/32
#         route_preference: 200
#         tag: 22
#     dhcp:
#       relay:
#         address:
#           - relay_ip: 2001:db8::1:abcd

# After state:
# ------------
#
# router# show running-config | section interface
# interface Ethernet1/1
#  mac-address 0011.2233.4455
#  ip verify unicast source reachable-via any allow-default
#  ip dhcp relay address 11.0.0.1 use-vrf abc
# interface Ethernet1/2
#  mac-address 0011.2233.4456
#  ipv6 address 2001:db8::1/32 route-preference 200 tag 22
#  ipv6 dhcp relay address 2001:db8::1:abcd

# Using overridden

# Before state:
# -------------
#
# router# show running-config | section interface
# interface Ethernet 1/1
#  mac-address 00:11:22:33:44:55
#  ip verify unicast source reachable-via any allow-default
#  ip dhcp relay address 11.0.0.1 use-vrf abc
# interface Ethernet 1/2
#  ipv6 dhcp relay address 2001:0db8::1:abcd
#  ipv6 address 2001:db8::1/32 route-preference 70 tag 97

- name: Override device configuration with provided configuration.
  cisco.nxos.nxos_l3_interfaces:
    config:
      - name: Ethernet1/1
        mac_address: 0011.2233.4455
        ipv4:
          verify:
            unicast:
              source:
                reachable_via:
                  mode: any
                  allow_default: true
    state: overridden

# Task Output
# -----------
#
# before:
# before:
# - name: Ethernet1/1
#   mac_address: 0011.2233.4455
#   ipv4:
#     verify:
#       unicast:
#         source:
#           reachable_via:
#             mode: any
#             allow_default: true
#     dhcp:
#       relay:
#         address:
#           - relay_ip: 11.0.0.1
#             vrf_name: abc
# - name: Ethernet1/2
#   ipv6:
#     addresses:
#       - ipv6_address: 2001:db8::1/32
#         route_preference: 70
#         tag: 97
#     dhcp:
#       relay:
#         address:
#           - relay_ip: 2001:db8::1:abcd
# commands:
# - interface Ethernet1/1
# - no ip dhcp relay address 11.0.0.1 use-vrf abc
# - interface Ethernet1/2
# - no ipv6 address 2001:db8::1/32 route-preference 70 tag 97
# - no ipv6 dhcp relay address 2001:db8::1:abcd
# after:
# - name: Ethernet1/1
#   mac_address: 0011.2233.4455
#   ipv4:
#     verify:
#       unicast:
#         source:
#           reachable_via:
#             mode: any
#             allow_default: true
# - name: Ethernet1/2

# After state:
# ------------
#
# router# show running-config | section interface
# interface Ethernet1/1
#  mac-address 0011.2233.4455
#  ip verify unicast source reachable-via any allow-default

# Using deleted

# Before state:
# -------------
#
# router# show running-config | section interface
# interface Ethernet 1/1
#  mac-address 00:11:22:33:44:55
#  ip verify unicast source reachable-via any allow-default
#  ip dhcp relay address 11.0.0.1 use-vrf abc
# interface Ethernet 1/2
#  ipv6 dhcp relay address 2001:0db8::1:abcd
#  ipv6 address 2001:db8::1/32 route-preference 70 tag 97

- name: Delete L3 attributes of given interfaces (This won't delete the interface
    itself).
  cisco.nxos.nxos_l3_interfaces:
    config:
      - name: Ethernet1/1
      - name: Ethernet1/2
    state: deleted

# Task Output
# -----------
#
# before:
# - name: Ethernet1/1
#   mac_address: 0011.2233.4455
#   ipv4:
#     verify:
#       unicast:
#         source:
#           reachable_via:
#             mode: any
#             allow_default: true
#     dhcp:
#       relay:
#         address:
#           - relay_ip: 11.0.0.1
#             vrf_name: abc
# - name: Ethernet1/2
#   ipv6:
#     addresses:
#       - ipv6_address: 2001:db8::1/32
#         route_preference: 70
#         tag: 97
#     dhcp:
#       relay:
#         address:
#           - relay_ip: 2001:db8::1:abcd
# commands:
# - interface Ethernet1/1
# - no mac-address 0011.2233.4455
# - no ip verify unicast source reachable-via any allow-default
# - no ip dhcp relay address 11.0.0.1 use-vrf abc
# - interface Ethernet1/2
# - no ipv6 address 2001:db8::1/32 route-preference 70 tag 97
# - no ipv6 dhcp relay address 2001:db8::1:abcd
# after:
# - name: Ethernet1/1
# - name: Ethernet1/2

# After state:
# ------------
#
# router# show running-config | section interface
# interface Ethernet1/1
# interface Ethernet1/2

# Using rendered

- name: Use rendered state to convert task input to device specific commands
  cisco.nxos.nxos_l3_interfaces:
    config:
      - name: Ethernet1/1
        mac_address: 0011.2233.4455
        ipv4:
          verify:
            unicast:
              source:
                reachable_via:
                  mode: any
                  allow_default: true
          dhcp:
            relay:
              address:
                - relay_ip: 11.0.0.1
                  vrf_name: abc
      - name: Ethernet1/2
        ipv6:
          addresses:
            - ipv6_address: 2001:db8::1/32
              route_preference: 70
              tag: 97
          dhcp:
            relay:
              address:
                - relay_ip: 2001:db8::1:abcd
    state: rendered

# Task Output
# -----------
#
# rendered:
# - interface Ethernet1/1
# - mac-address 0011.2233.4455
# - ip verify unicast source reachable-via any allow-default
# - ip dhcp relay address 11.0.0.1 use-vrf abc
# - interface Ethernet1/2
# - ipv6 address 2001:db8::1/32 route-preference 70 tag 97
# - ipv6 dhcp relay address 2001:db8::1:abcd

# Using parsed

# parsed.cfg
# ----------
#
# interface Ethernet1/1
#  mac-address 0011.2233.4455
#  ip verify unicast source reachable-via any allow-default
#  ip dhcp relay address 11.0.0.1 use-vrf abc
# interface Ethernet1/2
#  ipv6 address 2001:db8::1/32 route-preference 70 tag 97
#  ipv6 dhcp relay address 2001:db8::1:abcd

- name: Use parsed state to convert externally supplied config to structured format
  cisco.nxos.nxos_l3_interfaces:
    running_config: "{{ lookup('file', 'parsed.cfg') }}"
    state: parsed

# Task output
# -----------
#
# parsed:
#   - name: Ethernet1/1
#     mac_address: 0011.2233.4455
#     ipv4:
#       verify:
#         unicast:
#           source:
#             reachable_via:
#               mode: any
#               allow_default: true
#       dhcp:
#         relay:
#           address:
#             - relay_ip: 11.0.0.1
#               vrf_name: abc
#   - name: Ethernet1/2
#     ipv6:
#       addresses:
#         - ipv6_address: 2001:db8::1/32
#           route_preference: 70
#           tag: 97
#       dhcp:
#         relay:
#           address:
#             - relay_ip: 2001:db8::1:abcd

# Using gathered

# Before state:
# -------------
#
# interface Ethernet 1/1
#  mac-address 00:11:22:33:44:55
#  ip verify unicast source reachable-via any allow-default
#  ip dhcp relay address 11.0.0.1 use-vrf abc
# interface Ethernet 1/2
#  ipv6 dhcp relay address 2001:0db8::1:abcd
#  ipv6 address 2001:db8::1/32 route-preference 70 tag 97

- name: Gather l3_interfaces facts from the device using nxos_l3_interfaces
  cisco.nxos.nxos_l3_interfaces:
    state: gathered

# Task output
# -----------
#
# gathered:
#   - name: Ethernet1/1
#     mac_address: 0011.2233.4455
#     ipv4:
#       verify:
#         unicast:
#           source:
#             reachable_via:
#               mode: any
#               allow_default: true
#       dhcp:
#         relay:
#           address:
#             - relay_ip: 11.0.0.1
#               vrf_name: abc
#   - name: Ethernet1/2
#     ipv6:
#       addresses:
#         - ipv6_address: 2001:db8::1/32
#           route_preference: 70
#           tag: 97
#       dhcp:
#         relay:
#           address:
#             - relay_ip: 2001:db8::1:abcd
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
    - ip dhcp relay address 11.0.0.1 use-vrf abc
    - ipv6 address 2001:db8::1/32 route-preference 70 tag 97
    - ipv6 dhcp relay address 2001:db8::1:abcd
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - ip dhcp relay address 11.0.0.1 use-vrf abc
    - ipv6 address 2001:db8::1/32 route-preference 70 tag 97
    - ipv6 dhcp relay address 2001:db8::1:abcd
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

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.l3_interfaces.l3_interfaces import (
    L3_interfacesArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.config.l3_interfaces.l3_interfaces import (
    L3_interfaces,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=L3_interfacesArgs.argument_spec,
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

    result = L3_interfaces(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
