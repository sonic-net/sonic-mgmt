#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for nxos_bgp_neighbor_address_family
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: nxos_bgp_neighbor_address_family
short_description: BGP Neighbor Address Family resource module.
description:
- This module manages BGP Neighbor Address Family configuration on devices running Cisco NX-OS.
version_added: 2.0.0
notes:
- Tested against NX-OS 9.3.6.
- Unsupported for Cisco MDS
- For managing BGP address family configurations please use
  the M(cisco.nxos.nxos_bgp_address_family) module.
- This module works with connection C(network_cli) and C(httpapi).
author: Nilashish Chakraborty (@NilashishC)
options:
  running_config:
    description:
    - This option is used only with state I(parsed).
    - The value of this option should be the output received from the NX-OS device
      by executing the command B(show running-config | section '^router bgp').
    - The state I(parsed) reads the configuration from C(running_config) option and
      transforms it into Ansible structured data as per the resource module's argspec
      and the value is then returned in the I(parsed) key within the result.
    type: str
  config:
    description: BGP Neighbor AF configuration.
    type: dict
    suboptions:
      as_number:
        description: Autonomous System Number of the router.
        type: str
      neighbors: &nbr
        description: A list of BGP Neighbor AF configuration.
        type: list
        elements: dict
        suboptions:
          neighbor_address:
            description: IP/IPv6 address of the neighbor.
            type: str
            required: true
          address_family:
            description: BGP Neighbor Address Family related configurations.
            type: list
            elements: dict
            suboptions:
              afi:
                description: Address Family indicator.
                type: str
                choices: ["ipv4", "ipv6", "link-state", "vpnv4", "vpnv6", "l2vpn"]
                required: true
              safi:
                description: Sub Address Family indicator.
                type: str
                choices: ["unicast", "multicast", "mvpn", "evpn"]
              advertise_map:
                description: Specify route-map for conditional advertisement.
                type: dict
                suboptions:
                  route_map:
                    description: Route-map name.
                    type: str
                    required: true
                  exist_map:
                    description: Condition route-map to advertise only when prefix in condition exists.
                    type: str
                  non_exist_map:
                    description: Condition route-map to advertise only when prefix in condition does not exist.
                    type: str
              advertisement_interval:
                description: Minimum interval between sending BGP routing updates.
                type: int
              allowas_in:
                description: Accept as-path with my AS present in it.
                type: dict
                suboptions:
                  set:
                    description: Activate allowas-in property.
                    type: bool
                  max_occurences:
                    description: Number of occurrences of AS number, default is 3.
                    type: int
              as_override:
                description: Override matching AS-number while sending update.
                type: bool
              capability:
                description: Advertise capability to the peer.
                type: dict
                suboptions:
                  additional_paths:
                    description: Additional paths capability.
                    type: dict
                    suboptions:
                      receive:
                        description: Additional paths Receive capability.
                        type: str
                        choices: ["enable", "disable"]
                      send:
                        description: Additional paths Send capability.
                        type: str
                        choices: ["enable", "disable"]
              default_originate:
                description: Originate a default toward this peer.
                type: dict
                suboptions:
                  set:
                    description: Set default-originate attribute.
                    type: bool
                  route_map:
                    description: Route-map to specify criteria for originating default.
                    type: str
              disable_peer_as_check:
                description: Disable checking of peer AS-number while advertising.
                type: bool
              filter_list:
                description: Name of filter-list.
                type: dict
                suboptions:
                  inbound:
                    description: Apply policy to incoming routes.
                    type: str
                  outbound:
                    description: Apply policy to outgoing routes.
                    type: str
              inherit:
                description: Inherit a template.
                type: dict
                suboptions:
                  template:
                    description: Template name.
                    type: str
                  sequence:
                    description: Sequence number.
                    type: int
              maximum_prefix:
                description: Maximum number of prefixes from this neighbor.
                type: dict
                suboptions:
                  max_prefix_limit:
                    description: Maximum prefix limit.
                    type: int
                  generate_warning_threshold:
                    description: Threshold percentage at which to generate a warning.
                    type: int
                  restart_interval:
                    description: Restart bgp connection after limit is exceeded.
                    type: int
                  warning_only:
                    description: Only give a warning message when limit is exceeded.
                    type: bool
              next_hop_self:
                description: Set our address as nexthop (non-reflected).
                type: dict
                suboptions:
                  set:
                    description: Set next-hop-self attribute.
                    type: bool
                  all_routes:
                    description: Set our address as nexthop for all routes.
                    type: bool
              next_hop_third_party:
                description: Compute a third-party nexthop if possible.
                type: bool
              prefix_list:
                description: Apply prefix-list.
                type: dict
                suboptions:
                  inbound:
                    description: Apply policy to incoming routes.
                    type: str
                  outbound:
                    description: Apply policy to outgoing routes.
                    type: str
              rewrite_evpn_rt_asn:
                description: Auto generate RTs for EBGP neighbor.
                type: bool
              rewrite_rt_asn:
                description: Auto generate RTs for EBGP neighbor.
                type: bool
              route_map:
                description: Apply route-map to neighbor.
                type: dict
                suboptions:
                  inbound:
                    description: Apply policy to incoming routes.
                    type: str
                  outbound:
                    description: Apply policy to outgoing routes.
                    type: str
              route_reflector_client:
                description: Configure a neighbor as Route reflector client.
                type: bool
              send_community:
                description: Send Community attribute to this neighbor.
                type: dict
                suboptions:
                  set:
                    description: Set send-community attribute.
                    type: bool
                  extended:
                    description: Send Extended Community attribute.
                    type: bool
                  standard:
                    description: Send Standard Community attribute.
                    type: bool
                  both:
                    description: Send Standard and Extended Community attributes.
                    type: bool
              soft_reconfiguration_inbound:
                description: Soft reconfiguration.
                type: dict
                suboptions:
                  set:
                    description: Set soft-reconfiguration inbound attribute.
                    type: bool
                  always:
                    description: Always perform inbound soft reconfiguration.
                    type: bool
              soo:
                description: Specify Site-of-origin extcommunity.
                type: str
              suppress_inactive:
                description: Advertise only active routes to peer.
                type: bool
              unsuppress_map:
                description: Route-map to selectively unsuppress suppressed routes.
                type: str
              weight:
                description: Set default weight for routes from this neighbor.
                type: int
      vrfs:
        description: Virtual Router Context.
        type: list
        elements: dict
        suboptions:
          vrf:
            description: VRF name.
            type: str
          neighbors: *nbr
  state:
    description:
    - The state the configuration should be left in.
    - State I(deleted) only removes BGP attributes that this modules
      manages and does not negate the BGP process completely.
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
# Using merged

# Before state:
# -------------
# Nexus9000v# show running-config | section "^router bgp"
# Nexus9000v#

- name: Merge the provided configuration with the existing running configuration
  cisco.nxos.nxos_bgp_neighbor_address_family: &id001
    config:
      as_number: 65536
      neighbors:
        - neighbor_address: 192.0.2.32
          address_family:
            - afi: ipv4
              safi: unicast
              maximum_prefix:
                max_prefix_limit: 20
                generate_warning_threshold: 75
              weight: 100
              prefix_list:
                inbound: rmap1
                outbound: rmap2
            - afi: ipv6
              safi: unicast
        - neighbor_address: 192.0.2.33
          address_family:
            - afi: ipv4
              safi: multicast
              inherit:
                template: BasePolicy
                sequence: 200
      vrfs:
        - vrf: site-1
          neighbors:
            - neighbor_address: 203.0.113.1
              address_family:
                - afi: ipv4
                  safi: unicast
                  suppress_inactive: true
                  next_hop_self:
                    set: true
            - neighbor_address: 203.0.113.2
              address_family:
                - afi: ipv6
                  safi: unicast
                - afi: ipv4
                  safi: multicast
                  send_community:
                    set: true

# Task output:
# ------------
#  before: {}
#
#  commands:
#  - router bgp 65536
#  - neighbor 192.0.2.32
#  - address-family ipv4 unicast
#  - maximum-prefix 20 75
#  - weight 100
#  - prefix-list rmap1 in
#  - prefix-list rmap2 out
#  - address-family ipv6 unicast
#  - neighbor 192.0.2.33
#  - address-family ipv4 multicast
#  - inherit peer-policy BasePolicy 200
#  - vrf site-1
#  - neighbor 203.0.113.1
#  - address-family ipv4 unicast
#  - suppress-inactive
#  - next-hop-self
#  - neighbor 203.0.113.2
#  - address-family ipv6 unicast
#  - address-family ipv4 multicast
#  - send-community
#
#  after:
#    as_number: "65536"
#    neighbors:
#      - neighbor_address: 192.0.2.32
#        address_family:
#          - afi: ipv4
#            safi: unicast
#            maximum_prefix:
#              max_prefix_limit: 20
#              generate_warning_threshold: 75
#            weight: 100
#            prefix_list:
#              inbound: rmap1
#              outbound: rmap2
#          - afi: ipv6
#            safi: unicast
#      - neighbor_address: 192.0.2.33
#        address_family:
#          - afi: ipv4
#            safi: multicast
#            inherit:
#              template: BasePolicy
#              sequence: 200
#    vrfs:
#      - vrf: site-1
#        neighbors:
#          - neighbor_address: 203.0.113.1
#            address_family:
#              - afi: ipv4
#                safi: unicast
#                suppress_inactive: true
#                next_hop_self:
#                  set: true
#          - neighbor_address: 203.0.113.2
#            address_family:
#              - afi: ipv4
#                safi: multicast
#                send_community:
#                  set: true
#              - afi: ipv6
#                safi: unicast

# After state:
# ------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65536
#   neighbor 192.0.2.32
#     address-family ipv4 unicast
#       maximum-prefix 20 75
#       weight 100
#       prefix-list rmap1 in
#       prefix-list rmap2 out
#     address-family ipv6 unicast
#   neighbor 192.0.2.33
#     address-family ipv4 multicast
#       inherit peer-policy BasePolicy 200
#   vrf site-1
#     neighbor 203.0.113.1
#       address-family ipv4 unicast
#         suppress-inactive
#         next-hop-self
#     neighbor 203.0.113.2
#       address-family ipv4 multicast
#         send-community
#       address-family ipv6 unicast
#

# Using replaced

# Before state:
# -------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65536
#   neighbor 192.0.2.32
#     address-family ipv4 unicast
#       maximum-prefix 20 75
#       weight 100
#       prefix-list rmap1 in
#       prefix-list rmap2 out
#     address-family ipv6 unicast
#   neighbor 192.0.2.33
#     address-family ipv4 multicast
#       inherit peer-policy BasePolicy 200
#   vrf site-1
#     neighbor 203.0.113.1
#       address-family ipv4 unicast
#         suppress-inactive
#         next-hop-self
#     neighbor 203.0.113.2
#       address-family ipv4 multicast
#         send-community
#       address-family ipv6 unicast
#

- name: Replace specified neighbor AFs with given configuration
  cisco.nxos.nxos_bgp_neighbor_address_family: &replaced
    config:
      as_number: 65536
      neighbors:
        - neighbor_address: 192.0.2.32
          address_family:
            - afi: ipv4
              safi: unicast
              weight: 110
            - afi: ipv6
              safi: unicast
        - neighbor_address: 192.0.2.33
          address_family:
            - afi: ipv4
              safi: multicast
              inherit:
                template: BasePolicy
                sequence: 200
      vrfs:
        - vrf: site-1
          neighbors:
            - neighbor_address: 203.0.113.1
              address_family:
                - afi: ipv4
                  safi: unicast
            - neighbor_address: 203.0.113.2
              address_family:
                - afi: ipv6
                  safi: unicast
                - afi: ipv4
                  safi: multicast
                  send_community:
                    set: true
    state: replaced

# Task output:
# ------------
#  before:
#    as_number: "65536"
#    neighbors:
#      - neighbor_address: 192.0.2.32
#        address_family:
#          - afi: ipv4
#            safi: unicast
#            maximum_prefix:
#              max_prefix_limit: 20
#              generate_warning_threshold: 75
#            weight: 100
#            prefix_list:
#              inbound: rmap1
#              outbound: rmap2
#          - afi: ipv6
#            safi: unicast
#      - neighbor_address: 192.0.2.33
#        address_family:
#          - afi: ipv4
#            safi: multicast
#            inherit:
#              template: BasePolicy
#              sequence: 200
#    vrfs:
#      - vrf: site-1
#        neighbors:
#          - neighbor_address: 203.0.113.1
#            address_family:
#              - afi: ipv4
#                safi: unicast
#                suppress_inactive: true
#                next_hop_self:
#                  set: true
#          - neighbor_address: 203.0.113.2
#            address_family:
#              - afi: ipv4
#                safi: multicast
#                send_community:
#                  set: true
#              - afi: ipv6
#                safi: unicast
#
#  commands:
#    - router bgp 65536
#    - neighbor 192.0.2.32
#    - address-family ipv4 unicast
#    - no maximum-prefix 20 75
#    - weight 110
#    - no prefix-list rmap1 in
#    - no prefix-list rmap2 out
#    - vrf site-1
#    - neighbor 203.0.113.1
#    - address-family ipv4 unicast
#    - no suppress-inactive
#    - no next-hop-self
#
#  after:
#    as_number: "65536"
#    neighbors:
#      - neighbor_address: 192.0.2.32
#        address_family:
#          - afi: ipv4
#            safi: unicast
#            weight: 110
#          - afi: ipv6
#            safi: unicast
#      - neighbor_address: 192.0.2.33
#        address_family:
#          - afi: ipv4
#            safi: multicast
#            inherit:
#              template: BasePolicy
#              sequence: 200
#    vrfs:
#      - vrf: site-1
#        neighbors:
#          - neighbor_address: 203.0.113.1
#            address_family:
#              - afi: ipv4
#                safi: unicast
#          - neighbor_address: 203.0.113.2
#            address_family:
#              - afi: ipv4
#                safi: multicast
#                send_community:
#                  set: true
#              - afi: ipv6
#                safi: unicast

# After state:
# ------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65536
#   neighbor 192.0.2.32
#     address-family ipv4 unicast
#       weight 110
#     address-family ipv6 unicast
#   neighbor 192.0.2.33
#     address-family ipv4 multicast
#       inherit peer-policy BasePolicy 200
#   vrf site-1
#     neighbor 203.0.113.1
#       address-family ipv4 unicast
#     neighbor 203.0.113.2
#       address-family ipv4 multicast
#         send-community
#       address-family ipv6 unicast
#

# Using overridden

# Before state:
# -------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65536
#   neighbor 192.0.2.32
#     address-family ipv4 unicast
#       maximum-prefix 20 75
#       weight 100
#       prefix-list rmap1 in
#       prefix-list rmap2 out
#     address-family ipv6 unicast
#   neighbor 192.0.2.33
#     address-family ipv4 multicast
#       inherit peer-policy BasePolicy 200
#   vrf site-1
#     neighbor 203.0.113.1
#       address-family ipv4 unicast
#         suppress-inactive
#         next-hop-self
#     neighbor 203.0.113.2
#       address-family ipv4 multicast
#         send-community
#       address-family ipv6 unicast
#

- name: Override all BGP AF configuration with provided configuration
  cisco.nxos.nxos_bgp_neighbor_address_family:
    config:
      as_number: 65536
      neighbors:
        - neighbor_address: 192.0.2.32
          address_family:
            - afi: ipv4
              safi: unicast
      vrfs:
        - vrf: site-1
          neighbors:
            - neighbor_address: 203.0.113.1
              address_family:
                - afi: ipv4
                  safi: unicast
                  suppress_inactive: true
                  next_hop_self:
                    set: true
    state: overridden

# Task output:
# ------------
#  before:
#    as_number: "65536"
#    neighbors:
#      - neighbor_address: 192.0.2.32
#        address_family:
#          - afi: ipv4
#            safi: unicast
#            maximum_prefix:
#              max_prefix_limit: 20
#              generate_warning_threshold: 75
#            weight: 100
#            prefix_list:
#              inbound: rmap1
#              outbound: rmap2
#          - afi: ipv6
#            safi: unicast
#      - neighbor_address: 192.0.2.33
#        address_family:
#          - afi: ipv4
#            safi: multicast
#            inherit:
#              template: BasePolicy
#              sequence: 200
#    vrfs:
#      - vrf: site-1
#        neighbors:
#          - neighbor_address: 203.0.113.1
#            address_family:
#              - afi: ipv4
#                safi: unicast
#                suppress_inactive: true
#                next_hop_self:
#                  set: true
#          - neighbor_address: 203.0.113.2
#            address_family:
#              - afi: ipv4
#                safi: multicast
#                send_community:
#                  set: true
#              - afi: ipv6
#                safi: unicast
#
#  commands:
#    - router bgp 65536
#    - neighbor 192.0.2.32
#    - address-family ipv4 unicast
#    - no maximum-prefix 20 75
#    - no weight 100
#    - no prefix-list rmap1 in
#    - no prefix-list rmap2 out
#    - no address-family ipv6 unicast
#    - neighbor 192.0.2.33
#    - no address-family ipv4 multicast
#    - vrf site-1
#    - neighbor 203.0.113.2
#    - no address-family ipv4 multicast
#    - no address-family ipv6 unicast
#
#  after:
#    as_number: "65536"
#    neighbors:
#      - neighbor_address: 192.0.2.32
#        address_family:
#          - afi: ipv4
#            safi: unicast
#    vrfs:
#      - vrf: site-1
#        neighbors:
#          - neighbor_address: 203.0.113.1
#            address_family:
#              - afi: ipv4
#                safi: unicast
#                suppress_inactive: true
#                next_hop_self:
#                  set: true

# After state:
# ------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65536
#   neighbor 192.0.2.32
#     address-family ipv4 unicast
#   vrf site-1
#     neighbor 203.0.113.1
#       address-family ipv4 unicast
#         suppress-inactive
#         next-hop-self

# Using deleted to remove specified neighbor AFs

# Before state:
# -------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65536
#   neighbor 192.0.2.32
#     address-family ipv4 unicast
#       maximum-prefix 20 75
#       weight 100
#       prefix-list rmap1 in
#       prefix-list rmap2 out
#     address-family ipv6 unicast
#   neighbor 192.0.2.33
#     address-family ipv4 multicast
#       inherit peer-policy BasePolicy 200
#   vrf site-1
#     neighbor 203.0.113.1
#       address-family ipv4 unicast
#         suppress-inactive
#         next-hop-self
#     neighbor 203.0.113.2
#       address-family ipv4 multicast
#         send-community
#       address-family ipv6 unicast
#

- name: Delete BGP configs handled by this module
  cisco.nxos.nxos_bgp_neighbor_address_family:
    config:
      as_number: 65536
      neighbors:
        - neighbor_address: 192.0.2.32
          address_family:
            - afi: ipv4
              safi: unicast
      vrfs:
        - vrf: site-1
          neighbors:
            - neighbor_address: 203.0.113.2
              address_family:
                - afi: ipv6
                  safi: unicast
    state: deleted

# Task output:
# ------------
#  before:
#    as_number: "65536"
#    neighbors:
#      - neighbor_address: 192.0.2.32
#        address_family:
#          - afi: ipv4
#            safi: unicast
#            maximum_prefix:
#              max_prefix_limit: 20
#              generate_warning_threshold: 75
#            weight: 100
#            prefix_list:
#              inbound: rmap1
#              outbound: rmap2
#          - afi: ipv6
#            safi: unicast
#      - neighbor_address: 192.0.2.33
#        address_family:
#          - afi: ipv4
#            safi: multicast
#            inherit:
#              template: BasePolicy
#              sequence: 200
#    vrfs:
#      - vrf: site-1
#        neighbors:
#          - neighbor_address: 203.0.113.1
#            address_family:
#              - afi: ipv4
#                safi: unicast
#                suppress_inactive: true
#                next_hop_self:
#                  set: true
#          - neighbor_address: 203.0.113.2
#            address_family:
#              - afi: ipv4
#                safi: multicast
#                send_community:
#                  set: true
#              - afi: ipv6
#                safi: unicast
#
#  commands:
#    - router bgp 65536
#    - neighbor 192.0.2.32
#    - no address-family ipv4 unicast
#    - vrf site-1
#    - neighbor 203.0.113.2
#    - no address-family ipv6 unicast
#
#  after:
#    as_number: "65536"
#    neighbors:
#      - neighbor_address: 192.0.2.32
#        address_family:
#          - afi: ipv6
#            safi: unicast
#      - neighbor_address: 192.0.2.33
#        address_family:
#          - afi: ipv4
#            safi: multicast
#            inherit:
#              template: BasePolicy
#              sequence: 200
#    vrfs:
#      - vrf: site-1
#        neighbors:
#          - neighbor_address: 203.0.113.1
#            address_family:
#              - afi: ipv4
#                safi: unicast
#                suppress_inactive: true
#                next_hop_self:
#                  set: true
#          - neighbor_address: 203.0.113.2
#            address_family:
#              - afi: ipv4
#                safi: multicast
#                send_community:
#                  set: true
#
# After state:
# ------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65536
#   neighbor 192.0.2.32
#     address-family ipv6 unicast
#   neighbor 192.0.2.33
#     address-family ipv4 multicast
#       inherit peer-policy BasePolicy 200
#   vrf site-1
#     neighbor 203.0.113.1
#       address-family ipv4 unicast
#         suppress-inactive
#         next-hop-self
#     neighbor 203.0.113.2
#       address-family ipv4 multicast
#         send-community
#

# Using deleted to remove all neighbor AFs

# Before state:
# -------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65536
#   neighbor 192.0.2.32
#     address-family ipv4 unicast
#       maximum-prefix 20 75
#       weight 100
#       prefix-list rmap1 in
#       prefix-list rmap2 out
#     address-family ipv6 unicast
#   neighbor 192.0.2.33
#     address-family ipv4 multicast
#       inherit peer-policy BasePolicy 200
#   vrf site-1
#     neighbor 203.0.113.1
#       address-family ipv4 unicast
#         suppress-inactive
#         next-hop-self
#     neighbor 203.0.113.2
#       address-family ipv4 multicast
#         send-community
#       address-family ipv6 unicast
#

- name: Delete all BGP neighbor AF configs handled by this module
  cisco.nxos.nxos_bgp_neighbor_address_family:
    state: deleted

# Task output:
# ------------
#  before:
#    as_number: "65536"
#    neighbors:
#      - neighbor_address: 192.0.2.32
#        address_family:
#          - afi: ipv4
#            safi: unicast
#            maximum_prefix:
#              max_prefix_limit: 20
#              generate_warning_threshold: 75
#            weight: 100
#            prefix_list:
#              inbound: rmap1
#              outbound: rmap2
#          - afi: ipv6
#            safi: unicast
#      - neighbor_address: 192.0.2.33
#        address_family:
#          - afi: ipv4
#            safi: multicast
#            inherit:
#              template: BasePolicy
#              sequence: 200
#    vrfs:
#      - vrf: site-1
#        neighbors:
#          - neighbor_address: 203.0.113.1
#            address_family:
#              - afi: ipv4
#                safi: unicast
#                suppress_inactive: true
#                next_hop_self:
#                  set: true
#          - neighbor_address: 203.0.113.2
#            address_family:
#              - afi: ipv4
#                safi: multicast
#                send_community:
#                  set: true
#              - afi: ipv6
#                safi: unicast
#
#  commands:
#    - router bgp 65536
#    - neighbor 192.0.2.32
#    - no address-family ipv4 unicast
#    - no address-family ipv6 unicast
#    - neighbor 192.0.2.33
#    - no address-family ipv4 multicast
#    - vrf site-1
#    - neighbor 203.0.113.1
#    - no address-family ipv4 unicast
#    - neighbor 203.0.113.2
#    - no address-family ipv6 unicast
#    - no address-family ipv4 multicast
#
#  after:
#    as_number: "65536"
#
# After state:
# ------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65536
#   neighbor 192.0.2.32
#   neighbor 192.0.2.33
#   vrf site-1
#     neighbor 203.0.113.1
#     neighbor 203.0.113.2
#

# Using rendered

- name: Render platform specific configuration lines with state rendered (without connecting to the device)
  cisco.nxos.nxos_bgp_neighbor_address_family:
    config:
      as_number: 65536
      neighbors:
        - neighbor_address: 192.0.2.32
          address_family:
            - afi: ipv4
              safi: unicast
              maximum_prefix:
                max_prefix_limit: 20
                generate_warning_threshold: 75
              weight: 100
              prefix_list:
                inbound: rmap1
                outbound: rmap2
            - afi: ipv6
              safi: unicast
        - neighbor_address: 192.0.2.33
          address_family:
            - afi: ipv4
              safi: multicast
              inherit:
                template: BasePolicy
                sequence: 200
      vrfs:
        - vrf: site-1
          neighbors:
            - neighbor_address: 203.0.113.1
              address_family:
                - afi: ipv4
                  safi: unicast
                  suppress_inactive: true
                  next_hop_self:
                    set: true
            - neighbor_address: 203.0.113.2
              address_family:
                - afi: ipv6
                  safi: unicast
                - afi: ipv4
                  safi: multicast
                  send_community:
                    set: true
    state: rendered

# Task output:
# ------------
#  rendered:
#    - router bgp 65536
#    - neighbor 192.0.2.32
#    - address-family ipv4 unicast
#    - maximum-prefix 20 75
#    - weight 100
#    - prefix-list rmap1 in
#    - prefix-list rmap2 out
#    - address-family ipv6 unicast
#    - neighbor 192.0.2.33
#    - address-family ipv4 multicast
#    - inherit peer-policy BasePolicy 200
#    - vrf site-1
#    - neighbor 203.0.113.1
#    - address-family ipv4 unicast
#    - suppress-inactive
#    - next-hop-self
#    - neighbor 203.0.113.2
#    - address-family ipv6 unicast
#    - address-family ipv4 multicast
#    - send-community

# Using parsed

# parsed.cfg
# ------------
# router bgp 65536
#   neighbor 192.0.2.32
#     address-family ipv4 unicast
#       maximum-prefix 20 75
#       weight 100
#       prefix-list rmap1 in
#       prefix-list rmap2 out
#     address-family ipv6 unicast
#   neighbor 192.0.2.33
#     address-family ipv4 multicast
#       inherit peer-policy BasePolicy 200
#   vrf site-1
#     neighbor 203.0.113.1
#       address-family ipv4 unicast
#         suppress-inactive
#         next-hop-self
#     neighbor 203.0.113.2
#       address-family ipv4 multicast
#         send-community
#       address-family ipv6 unicast

- name: Parse externally provided BGP neighbor AF config
  register: result
  cisco.nxos.nxos_bgp_neighbor_address_family:
    running_config: "{{ lookup('file', 'parsed.cfg') }}"
    state: parsed

# Task output:
# ------------
#  parsed:
#    as_number: "65536"
#    neighbors:
#      - neighbor_address: 192.0.2.32
#        address_family:
#          - afi: ipv4
#           safi: unicast
#           maximum_prefix:
#              max_prefix_limit: 20
#              generate_warning_threshold: 75
#           weight: 100
#            prefix_list:
#              inbound: rmap1
#              outbound: rmap2
#          - afi: ipv6
#            safi: unicast
#      - neighbor_address: 192.0.2.33
#        address_family:
#          - afi: ipv4
#            safi: multicast
#            inherit:
#              template: BasePolicy
#              sequence: 200
#    vrfs:
#      - vrf: site-1
#        neighbors:
#          - neighbor_address: 203.0.113.1
#            address_family:
#              - afi: ipv4
#                safi: unicast
#                suppress_inactive: true
#                next_hop_self:
#                  set: true
#          - neighbor_address: 203.0.113.2
#            address_family:
#              - afi: ipv4
#                safi: multicast
#                send_community:
#                  set: true
#              - afi: ipv6
#                safi: unicast
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
    - router bgp 65536
    - neighbor 192.0.2.32
    - address-family ipv4 unicast
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - router bgp 65536
    - neighbor 192.0.2.32
    - address-family ipv4 unicast
gathered:
  description: Facts about the network resource gathered from the remote device as structured data.
  returned: when I(state) is C(gathered)
  type: dict
  sample: >
    This output will always be in the same format as the
    module argspec.
parsed:
  description: The device native config provided in I(running_config) option parsed into structured data as per module argspec.
  returned: when I(state) is C(parsed)
  type: dict
  sample: >
    This output will always be in the same format as the
    module argspec.
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.bgp_neighbor_address_family.bgp_neighbor_address_family import (
    Bgp_neighbor_address_familyArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.config.bgp_neighbor_address_family.bgp_neighbor_address_family import (
    Bgp_neighbor_address_family,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=Bgp_neighbor_address_familyArgs.argument_spec,
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

    result = Bgp_neighbor_address_family(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
