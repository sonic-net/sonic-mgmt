#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for nxos_static_routes
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: nxos_static_routes
short_description: Static routes resource module
description: This module configures and manages the attributes of static routes on
  Cisco NX-OS platforms.
version_added: 1.0.0
author:
  - Adharsh Srivats Rangarajan (@adharshsrivatsr)
  - Sagar Paul (@KB-perByte)
notes:
- Tested against Nexus 9300v running NX-OS 9.3.6 on CML.
- Unsupported for Cisco MDS
- When a route is configured for a non-existent VRF, the VRF is created and the route
  is added to it.
- When deleting routes for a VRF, all routes inside the VRF are deleted, but the VRF
  is not deleted.
options:
  running_config:
    description:
    - This option is used only with state I(parsed).
    - The value of this option should be the output received from the NX-OS device
      by executing the following commands in order B(show running-config | include
      '^ip(v6)* route') and B(show running-config | section '^vrf context').
    - The state I(parsed) reads the configuration from C(running_config) option and
      transforms it into Ansible structured data as per the resource module's argspec
      and the value is then returned in the I(parsed) key within the result.
    type: str
  config:
    description:
    - A list of configurations for static routes
    type: list
    elements: dict
    suboptions:
      vrf:
        description:
        - The VRF to which the static route(s) belong
        type: str
      address_families:
        description: A dictionary specifying the address family to which the static
          route(s) belong.
        type: list
        elements: dict
        suboptions:
          afi:
            description:
            - Specifies the top level address family indicator.
            type: str
            choices: [ipv4, ipv6]
            required: true
          routes:
            description: A dictionary that specifies the static route configurations
            elements: dict
            type: list
            suboptions:
              dest:
                description:
                - Destination prefix of static route
                - The address format is <ipv4/v6 address>/<mask>
                - The mask is number in range 0-32 for IPv4 and in range 0-128 for
                  IPv6
                type: str
                required: true
              next_hops:
                description:
                - Details of route to be taken
                type: list
                elements: dict
                suboptions:
                  forward_router_address:
                    description:
                    - IP address of the next hop router
                    type: str
                    # required: True
                  interface:
                    description:
                    - Outgoing interface to take. For anything except 'Null0', then
                      next hop IP address should also be configured.
                    type: str
                  admin_distance:
                    description:
                    - Preference or administrative distance of route (range 1-255)
                    type: int
                  route_name:
                    description:
                    - Name of the static route
                    type: str
                  tag:
                    description:
                    - Route tag value (numeric)
                    type: int
                  track:
                    description:
                    - Track value (range 1 - 512). Track must already be configured
                      on the device before adding the route.
                    type: int
                  dest_vrf:
                    description:
                    - VRF of the destination
                    type: str
  state:
    description:
    - The state the configuration should be left in
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
# Using deleted - delete all

# Before state:
# -------------
#
# switch# show running-config | include '^ip(v6)* route'
# ip route 192.0.2.32/28 192.0.2.12 name new_route
# ip route 192.0.2.26/24 192.0.2.13 tag 12
# switch# show running-config | section '^vrf context'

- name: Delete all routes
  cisco.nxos.nxos_static_routes:
    state: deleted

# Task Output
# -----------
#
# before:
#   - address_families:
#       - afi: ipv4
#         routes:
#           - dest: 192.0.2.0/24
#             next_hops:
#               - forward_router_address: 192.0.2.13
#                 tag: 12
#           - dest: 192.0.2.32/28
#             next_hops:
#               - forward_router_address: 192.0.2.12
#                 route_name: new_route
# commands:
# - no ip route 192.0.2.0/24 192.0.2.13 tag 12
# - no ip route 192.0.2.32/28 192.0.2.12 name new_route
# after: []

# After state:
# ------------
# switch# show running-config | include '^ip(v6)* route'
# switch# show running-config | section '^vrf context'

# Using deleted - vrf based

# Before state:
# ------------
#
# switch# show running-config | include '^ip(v6)* route'
# ip route 192.0.2.16/28 192.0.2.24 name new_route
# ip route 192.0.2.80/28 192.0.2.26 tag 12
# switch# show running-config | section '^vrf context'
# vrf context trial_vrf
# ip route 192.0.2.64/28 192.0.2.22 tag 4
# ip route 192.0.2.64/28 192.0.2.23 name merged_route 1
# ipv6 route 2200:10::/36 2048:ae12::1 vrf dest 5

- name: Delete routes based on VRF
  cisco.nxos.nxos_static_routes:
    config:
      - vrf: trial_vrf
    state: deleted

# Task Output
# -----------
#
# before:
#   - address_families:
#       - afi: ipv4
#         routes:
#           - dest: 192.0.2.64/28
#             next_hops:
#               - forward_router_address: 192.0.2.22
#                 tag: 4
#               - admin_distance: 1
#                 forward_router_address: 192.0.2.23
#                 route_name: merged_route
#       - afi: ipv6
#         routes:
#           - dest: '2200:10::/36'
#             next_hops:
#               - admin_distance: 5
#                 dest_vrf: dest
#                 forward_router_address: '2048:ae12::1'
#     vrf: trial_vrf
#   - address_families:
#       - afi: ipv4
#         routes:
#           - dest: 192.0.2.16/28
#             next_hops:
#               - forward_router_address: 192.0.2.24
#                 route_name: new_route
#           - dest: 192.0.2.80/28
#             next_hops:
#               - forward_router_address: 192.0.2.26
#                 tag: 12
# commands:
# - vrf context trial_vrf
# - no ip route 192.0.2.64/28 192.0.2.22 tag 4
# - no ip route 192.0.2.64/28 192.0.2.23 name merged_route 1
# - no ipv6 route 2200:10::/36 2048:ae12::1 vrf dest 5
# after:
#   - address_families:
#       - afi: ipv4
#         routes:
#           - dest: 192.0.2.16/28
#             next_hops:
#               - forward_router_address: 192.0.2.24
#                 route_name: new_route
#           - dest: 192.0.2.80/28
#             next_hops:
#               - forward_router_address: 192.0.2.26
#                 tag: 12

# After state:
# -----------
#
# switch# show running-config | include '^ip(v6)* route'
# ip route 192.0.2.16/28 192.0.2.24 name new_route
# ip route 192.0.2.80/28 192.0.2.26 tag 12
# switch# show running-config | section '^vrf context'
# vrf context trial_vrf

# Using deleted - afi based

# Before state:
# ------------
#
# switch# show running-config | include '^ip(v6)* route'
# ip route 192.0.2.16/28 192.0.2.24 name new_route
# ip route 192.0.2.80/28 192.0.2.26 tag 12
# switch# show running-config | section '^vrf context'
# vrf context trial_vrf
# ip route 192.0.2.64/28 192.0.2.22 tag 4
# ip route 192.0.2.64/28 192.0.2.23 name merged_route 1
# ipv6 route 2200:10::/36 2048:ae12::1 vrf dest 5

- name: Delete routes based on AFI in a VRF
  cisco.nxos.nxos_static_routes:
    config:
      - vrf: trial_vrf
        address_families:
          - afi: ipv4
    state: deleted

# Task Output
# -----------
#
# before:
#   - address_families:
#       - afi: ipv4
#         routes:
#           - dest: 192.0.2.64/28
#             next_hops:
#               - forward_router_address: 192.0.2.22
#                 tag: 4
#               - admin_distance: 1
#                 forward_router_address: 192.0.2.23
#                 route_name: merged_route
#       - afi: ipv6
#         routes:
#           - dest: '2200:10::/36'
#             next_hops:
#               - admin_distance: 5
#                 dest_vrf: dest
#                 forward_router_address: '2048:ae12::1'
#     vrf: trial_vrf
#   - address_families:
#       - afi: ipv4
#         routes:
#           - dest: 192.0.2.16/28
#             next_hops:
#               - forward_router_address: 192.0.2.24
#                 route_name: new_route
#           - dest: 192.0.2.80/28
#             next_hops:
#               - forward_router_address: 192.0.2.26
#                 tag: 12
# commands:
# - vrf context trial_vrf
# - no ip route 192.0.2.64/28 192.0.2.22 tag 4
# - no ip route 192.0.2.64/28 192.0.2.23 name merged_route 1
# after:
#   - address_families:
#       - afi: ipv6
#         routes:
#           - dest: '2200:10::/36'
#             next_hops:
#               - admin_distance: 5
#                 dest_vrf: dest
#                 forward_router_address: '2048:ae12::1'
#     vrf: trial_vrf
#   - address_families:
#       - afi: ipv4
#         routes:
#           - dest: 192.0.2.16/28
#             next_hops:
#               - forward_router_address: 192.0.2.24
#                 route_name: new_route
#           - dest: 192.0.2.80/28
#             next_hops:
#               - forward_router_address: 192.0.2.26
#                 tag: 12

# After state:
# -----------
#
# switch# show running-config | include '^ip(v6)* route'
# ip route 192.0.2.16/28 192.0.2.24 name new_route
# ip route 192.0.2.80/28 192.0.2.26 tag 12
# switch# show running-config | section '^vrf context'
# vrf context trial_vrf
# ipv6 route 2200:10::/36 2048:ae12::1 vrf dest 5

# Using merged

# Before state:
# -------------
# switch# show running-config | include '^ip(v6)* route'
# switch# show running-config | section '^vrf context'

- name: Merge new static route configuration
  cisco.nxos.nxos_static_routes:
    config:
      - vrf: trial_vrf
        address_families:
          - afi: ipv4
            routes:
              - dest: 192.0.2.64/24
                next_hops:
                  - forward_router_address: 192.0.2.22
                    tag: 4
                    admin_distance: 2
      - address_families:
          - afi: ipv4
            routes:
              - dest: 192.0.2.16/24
                next_hops:
                  - forward_router_address: 192.0.2.24
                    route_name: new_route
          - afi: ipv6
            routes:
              - dest: '2001:db8::/64'
                next_hops:
                  - interface: eth1/3
                    forward_router_address: '2001:db8::12'
    state: merged

# Task Output
# -----------
#
# before:[]
# commands:
# - vrf context trial_vrf
# - ip route 192.0.2.64/24 192.0.2.22 tag 4 2
# - ip route 192.0.2.16/24 192.0.2.24 name new_route
# - ipv6 route 2001:db8::/64 Ethernet1/3 2001:db8::12
# after:
#     - vrf: trial_vrf
#       address_families:
#       - afi: ipv4
#         routes:
#         - dest: 192.0.2.64/24
#           next_hops:
#           - forward_router_address: 192.0.2.22
#             tag: 4
#             admin_distance: 2
#     - address_families:
#       - afi: ipv4
#         routes:
#         - dest: 192.0.2.16/24
#           next_hops:
#           - forward_router_address: 192.0.2.24
#             route_name: new_route
#       - afi: ipv6
#         routes:
#         - dest: 2001:db8::/64
#           next_hops:
#           - interface: eth1/3
#             forward_router_address: 2

# After state:
# ------------
#
# switch# show running-config | include '^ip(v6)* route'
# ip route 192.0.2.16/24 192.0.2.24 name new_route
# ipv6 route 2001:db8::/64 Ethernet1/3 2001:db8::12
# switch# show running-config | section '^vrf context'
# vrf context trial_vrf
#   ip route 192.0.2.0/24 192.0.2.22 tag 4 2

# Using overridden

# Before state:
# -------------
#
# switch# show running-config | include '^ip(v6)* route'
# ip route 192.0.2.16/28 192.0.2.24 name new_route
# ip route 192.0.2.80/28 192.0.2.26 tag 12
# switch# show running-config | section '^vrf context'
# vrf context trial_vrf
# ip route 192.0.2.64/28 192.0.2.22 tag 4
# ip route 192.0.2.64/28 192.0.2.23 name merged_route 1

- name: Overridden existing static route configuration with new configuration
  cisco.nxos.nxos_static_routes:
    config:
      - vrf: trial_vrf
        address_families:
          - afi: ipv4
            routes:
              - dest: 192.0.2.16/28
                next_hops:
                  - forward_router_address: 192.0.2.23
                    route_name: overridden_route1
                    admin_distance: 3
                  - forward_router_address: 192.0.2.45
                    route_name: overridden_route2
                    dest_vrf: destinationVRF
                    interface: Ethernet1/2
    state: overridden

# Task Output
# -----------
#
# before:
#   - address_families:
#       - afi: ipv4
#         routes:
#           - dest: 192.0.2.64/28
#             next_hops:
#               - forward_router_address: 192.0.2.22
#                 tag: 4
#               - admin_distance: 1
#                 forward_router_address: 192.0.2.23
#                 route_name: merged_route
#     vrf: trial_vrf
#   - address_families:
#       - afi: ipv4
#         routes:
#           - dest: 192.0.2.16/28
#             next_hops:
#               - forward_router_address: 192.0.2.24
#                 route_name: new_route
#           - dest: 192.0.2.80/28
#             next_hops:
#               - forward_router_address: 192.0.2.26
#                 tag: 12
# commands:
# - no ip route 192.0.2.16/28 192.0.2.24 name new_route
# - no ip route 192.0.2.80/28 192.0.2.26 tag 12
# - vrf context trial_vrf
# - no ip route 192.0.2.64/28 192.0.2.22 tag 4
# - no ip route 192.0.2.64/28 192.0.2.23 name merged_route 1
# - ip route 192.0.2.16/28 192.0.2.23 name overridden_route1 3
# - ip route 192.0.2.16/28 Ethernet1/2 192.0.2.45 vrf destinationVRF name overridden_route2
# after:
#   - address_families:
#       - afi: ipv4
#         routes:
#           - dest: 192.0.2.16/28
#             next_hops:
#               - admin_distance: 3
#                 forward_router_address: 192.0.2.23
#                 route_name: overridden_route1
#               - dest_vrf: destinationVRF
#                 forward_router_address: 192.0.2.45
#                 interface: Ethernet1/2
#                 route_name: overridden_route2
#    vrf: trial_vrf

# After state:
# ------------
#
# switch# show running-config | include '^ip(v6)* route'
# switch# show running-config | section '^vrf context'
# vrf context trial_vrf
#   ip route 192.0.2.16/28 192.0.2.23 name overridden_route1 3
#   ip route 192.0.2.16/28 Ethernet1/2 192.0.2.45 vrf destinationVRF name overridden_route2

# Using replaced

# Before state:
# ------------
#
# switch# show running-config | include '^ip(v6)* route'
# ip route 192.0.2.16/28 192.0.2.24 name new_route
# ip route 192.0.2.80/28 192.0.2.26 tag 12
# switch# show running-config | section '^vrf context'
# vrf context trial_vrf
# ip route 192.0.2.64/28 192.0.2.22 tag 4
# ip route 192.0.2.64/28 192.0.2.23 name merged_route 1

- name: Replaced the existing static configuration of a prefix with new configuration
  cisco.nxos.nxos_static_routes:
    config:
      - address_families:
          - afi: ipv4
            routes:
              - dest: 192.0.2.16/28
                next_hops:
                  - forward_router_address: 192.0.2.23
                    route_name: replaced_route1
                    admin_distance: 3
                  - forward_router_address: 192.0.2.45
                    route_name: replaced_route2
                    dest_vrf: destinationVRF
                    interface: Ethernet1/2
    state: replaced

# Task Output
# -----------
#
# before:
#   - address_families:
#       - afi: ipv4
#         routes:
#           - dest: 192.0.2.64/28
#             next_hops:
#               - forward_router_address: 192.0.2.22
#                 tag: 4
#               - admin_distance: 1
#                 forward_router_address: 192.0.2.23
#                 route_name: merged_route
#     vrf: trial_vrf
#   - address_families:
#       - afi: ipv4
#         routes:
#           - dest: 192.0.2.16/28
#             next_hops:
#               - forward_router_address: 192.0.2.24
#                 route_name: new_route
#           - dest: 192.0.2.80/28
#             next_hops:
#               - forward_router_address: 192.0.2.26
#                 tag: 12
# commands:
# - no ip route 192.0.2.16/28 192.0.2.24 name new_route
# - ip route 192.0.2.16/28 192.0.2.23 name replaced_route1 3
# - ip route 192.0.2.16/28 Ethernet1/2 192.0.2.45 vrf destinationVRF name replaced_route2
# after:
#   - address_families:
#       - afi: ipv4
#         routes:
#           - dest: 192.0.2.64/28
#             next_hops:
#               - forward_router_address: 192.0.2.22
#                 tag: 4
#               - admin_distance: 1
#                 forward_router_address: 192.0.2.23
#                 route_name: merged_route
#     vrf: trial_vrf
#   - address_families:
#       - afi: ipv4
#         routes:
#           - dest: 192.0.2.16/28
#             next_hops:
#               - admin_distance: 3
#                 forward_router_address: 192.0.2.23
#                 route_name: replaced_route1
#               - dest_vrf: destinationVRF
#                 forward_router_address: 192.0.2.45
#                 interface: Ethernet1/2
#                 route_name: replaced_route2
#           - dest: 192.0.2.80/28
#             next_hops:
#               - forward_router_address: 192.0.2.26
#                 tag: 12

# After state:
# ------------
#
# switch# show running-config | include '^ip(v6)* route'
# ip route 192.0.2.16/28 192.0.2.23 name replaced_route1 3
# ip route 192.0.2.16/28 Ethernet1/2 192.0.2.45 vrf destinationVRF name replaced_route2
# ip route 192.0.2.80/28 192.0.2.26 tag 12
# switch# show running-config | section '^vrf context'
# vrf context trial_vrf
# ip route 192.0.2.64/28 192.0.2.22 tag 4
# ip route 192.0.2.64/28 192.0.2.23 name merged_route 1


# Using gathered

# Before state:
# -------------
#
# switch# show running-config | include '^ip(v6)* route'
# ipv6 route 2001:db8:12::/32  2001:db8::12
# switch# show running-config | section '^vrf context'
# vrf context Test
#    ip route 192.0.2.48/28 192.0.2.13
#    ip route 192.0.2.48/28 192.0.2.14 5

- name: Gather the existing configuration
  cisco.nxos.nxos_static_routes:
    state: gathered

# Task Output
# -----------
#
# gathered:
#     - vrf: Test
#       address_families:
#         - afi: ipv4
#           routes:
#             - dest: 192.0.2.48/28
#               next_hops:
#                 - forward_router_address: 192.0.2.13
#
#                 - forward_router_address: 192.0.2.14
#                   admin_distance: 5
#
#     - address_families:
#         - afi: ipv6
#           routes:
#             - dest: 2001:db8:12::/32
#               next_hops:
#                 - forward_router_address: 2001:db8::12


# Using rendered

- name: Render required configuration to be pushed to the device
  cisco.nxos.nxos_static_routes:
    config:
      - address_families:
          - afi: ipv4
            routes:
              - dest: 192.0.2.48/28
                next_hops:
                  - forward_router_address: 192.0.2.13
          - afi: ipv6
            routes:
              - dest: 2001:db8::/64
                next_hops:
                  - interface: eth1/3
                    forward_router_address: 2001:db8::12
    state: rendered

# Task Output
# -----------
#
# rendered:
#   vrf context default
#   ip route 192.0.2.48/28 192.0.2.13
#   ipv6 route 2001:db8::/64 Ethernet1/3 2001:db8::12

# Using parsed

- name: Parse the config to structured data
  cisco.nxos.nxos_static_routes:
    state: parsed
    running_config: |
      ipv6 route 2002:db8:12::/32 2002:db8:12::1
      vrf context Test
        ip route 192.0.2.48/28 192.0.2.13
        ip route 192.0.2.48/28 192.0.2.14 5

# Task Output
# -----------
#
# parsed:
#     - vrf: Test
#       address_families:
#         - afi: ipv4
#           routes:
#             - dest: 192.0.2.48/28
#               next_hops:
#                 - forward_router_address: 192.0.2.13
#                 - forward_router_address: 192.0.2.14
#                   admin_distance: 5
#     - address_families:
#         - afi: ipv6
#           routes:
#             - dest: 2002:db8:12::/32
#               next_hops:
#                 - forward_router_address: 2002:db8:12::1
"""

RETURN = """
before:
  description: The configuration prior to the module execution.
  returned: when I(state) is C(merged), C(replaced), C(overridden), C(deleted) or C(purged)
  type: list
  sample: >
    This output will always be in the same format as the
    module argspec.
after:
  description: The resulting configuration after module execution.
  returned: when changed
  type: list
  sample: >
    This output will always be in the same format as the
    module argspec.
commands:
  description: The set of commands pushed to the remote device.
  returned: when I(state) is C(merged), C(replaced), C(overridden), C(deleted) or C(purged)
  type: list
  sample:
    - ip route 192.0.2.16/28 192.0.2.24 name new_route
    - vrf context trial_vrf
    - ip route 192.0.2.16/28 192.0.2.23 name overridden_route1 3
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - ip route 192.0.2.16/28 192.0.2.24 name new_route
    - vrf context trial_vrf
    - ip route 192.0.2.16/28 192.0.2.23 name overridden_route1 3
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

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.static_routes.static_routes import (
    Static_routesArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.config.static_routes.static_routes import (
    Static_routes,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """

    module = AnsibleModule(
        argument_spec=Static_routesArgs.argument_spec,
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

    result = Static_routes(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
