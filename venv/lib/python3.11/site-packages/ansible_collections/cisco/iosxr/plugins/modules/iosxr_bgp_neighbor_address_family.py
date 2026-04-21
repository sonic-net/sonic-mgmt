#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for iosxr_bgp_neighbor_address_family
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: iosxr_bgp_neighbor_address_family
short_description: Resource module to configure BGP Neighbor Address family.
description:
- This module configures and manages the attributes of BGP global on Cisco IOS-XR platforms.
version_added: 2.0.0
author: Ashwini Mhatre (@amhatre)
notes:
- This module works with connection C(network_cli).
options:
    config:
      description: BGP neighbor address family configurations.
      type: dict
      suboptions:
        as_number:
          description: Autonomous system number.
          type: str
        neighbors:
            description: A list of BGP neighbor address family configurations.
            type: list
            elements: dict
            suboptions:
              neighbor_address:
                description:
                  - Neighbor router address.
                type: str
                required: true
              address_family:
                description: Enable address family and enter its config mode
                type: list
                elements: dict
                suboptions:
                  afi:
                    description: address family.
                    type: str
                    choices: [ 'ipv4', 'ipv6', 'l2vpn', 'link-state', 'vpnv4', 'vpnv6']
                  safi:
                    description: Address Family modifier
                    type: str
                    choices: [ 'flowspec', 'mdt', 'multicast', 'mvpn', 'rt-filter', 'tunnel', 'unicast', 'labeled-unicast' ]
                  aigp: &aigp
                    description: AIGP attribute
                    type: dict
                    suboptions:
                      disable:
                        description: Ignore AIGP attribute.
                        type: bool
                      set:
                        description: Set AIGP attribute.
                        type: bool
                      send_cost_community_disable:
                        description: send AIGP attribute.
                        type: bool
                      send_med:
                        description: send med options.
                        type: dict
                        suboptions:
                          set:
                            type: bool
                            description: set Send AIGP value in MED.
                          disable:
                            description: disable Send AIGP value in MED.
                            type: bool
                  allowas_in: &allowas_in
                    type: dict
                    description: Allow as-path with my AS present in it.
                    suboptions:
                      value:
                        type: int
                        description: Number of occurences of AS number 1-10.
                      set:
                        type: bool
                        description: set allowas_in
                  as_override: &as_override
                    type: dict
                    description: Override matching AS-number while sending update
                    suboptions:
                      set:
                        type: bool
                        description: set as_override
                      inheritance_disable:
                        type: bool
                        description: Prevent as-override from being inherited from the parent.
                  bestpath_origin_as_allow_invalid:
                    type: bool
                    description: Change default route selection criteria.Allow BGP origin-AS knobs.
                  capability_orf_prefix: &capability
                    type: str
                    description: Advertise address prefix ORF capability to this neighbor.
                    choices: ['both', 'send', 'none', 'receive']
                  default_originate: &default_originate
                    type: dict
                    description: Originate default route to this neighbor.
                    suboptions:
                      set:
                        type: bool
                        description: set default route.
                      route_policy:
                        type: str
                        description: Route policy to specify criteria to originate default
                      inheritance_disable:
                        type: bool
                        description: Prevent default-originate from being inherited from the parent.
                  long_lived_graceful_restart: &long_lived_graceful_restart
                    type: dict
                    description: Enable long lived graceful restart support.
                    suboptions:
                      capable:
                        type: bool
                        description: Treat neighbor as LLGR capable.
                      stale_time:
                        type: dict
                        description: Maximum time to wait before purging long-lived stale routes.
                        suboptions:
                          send:
                            type: int
                            description: max send time
                          accept:
                            type: int
                            description: max accept time
                  maximum_prefix: &maximum_prefix
                    type: dict
                    description: Maximum number of prefixes to accept from this peer.
                    suboptions:
                      max_limit:
                        type: int
                        description:  maximum no. of prefix limit.<1-4294967295.
                      threshold_value:
                        type: int
                        description: hreshold value (%) at which to generate a warning msg <1-100>.
                      restart:
                        type: int
                        description: Restart time interval.
                      warning_only:
                        type: bool
                        description: Only give warning message when limit is exceeded.
                      discard_extra_paths:
                        description: Discard extra paths when limit is exceeded.
                        type: bool
                  multipath: &multipath
                    type: bool
                    description: Paths from this neighbor is eligible for multipath.
                  next_hop_self: &next_hop_self
                    type: dict
                    description: Disable the next hop calculation for this neighbor.
                    suboptions:
                      set:
                        type: bool
                        description: set next hop self.
                      inheritance_disable:
                        type: bool
                        description: Prevent next_hop_self from being inherited from the parent.
                  next_hop_unchanged: &next_hop_unchanged
                    type: dict
                    description: Disable the next hop calculation for this neighbor.
                    suboptions:
                      set:
                        type: bool
                        description: set next hop unchanged.
                      inheritance_disable:
                        type: bool
                        description: Prevent next_hop_unchanged from being inherited from the parent.
                      multipath:
                        type: bool
                        description: Do not overwrite nexthop before advertising multipaths.
                  optimal_route_reflection_group_name: &optimal_route_reflection
                    type: str
                    description: Configure optimal-route-reflection group.
                  orf_route_policy: &orf_rp
                    type: str
                    description: Specify ORF and inbound filtering criteria.'
                  origin_as:
                    description: BGP origin-AS knobs.
                    type: dict
                    suboptions:
                      validation:
                        description: BGP origin-AS validation knobs.
                        type: dict
                        suboptions:
                          disable:
                            description: Disable RPKI origin-AS validation.
                            type: bool
                  remove_private_AS: &remove_private_AS
                    type: dict
                    description: Remove private AS number from outbound updates.
                    suboptions:
                      set:
                        type: bool
                        description: set remove private As.
                      inbound:
                        type: bool
                        description: Remove private AS number from inbound updates.
                      entire_aspath:
                        type: bool
                        description: remove only if all ASes in the path are private.
                      inheritance_disable:
                        type: bool
                        description: Prevent remove-private-AS from being inherited from the parent.
                  route_policy: &route_policy
                    type: dict
                    description: Apply route policy to neighbor.
                    suboptions:
                      inbound:
                        type: str
                        description: Apply route policy to inbound routes.
                      outbound:
                        type: str
                        description: Apply route policy to outbound routes.
                  route_reflector_client: &route_reflector_client
                    type: dict
                    description:  Configure a neighbor as Route Reflector client.
                    suboptions:
                      set:
                        type: bool
                        description: set route-reflector-client.
                      inheritance_disable:
                        type: bool
                        description: Prevent route-reflector-client from being inherited from the parent.
                  send_community_ebgp: &send_community_ebgp
                    description: Send community attribute to this external neighbor.
                    type: dict
                    suboptions:
                      set:
                        type: bool
                        description: set send_community_ebgp.
                      inheritance_disable:
                        type: bool
                        description: Prevent send_community_ebgp from being inherited from the parent.
                  send_community_gshut_ebgp: &send_community_gshut_ebgp
                    description: Allow the g-shut community to be sent to this external neighbor.
                    type: dict
                    suboptions:
                      set:
                        type: bool
                        description: set send_community_gshut_ebgp.
                      inheritance_disable:
                        type: bool
                        description: Prevent send_community_gshut_ebgp from being inherited from the parent.
                  send_extended_community_ebgp: &send_extended_community_ebgp
                    description: Send extended community attribute to this external neighbor.
                    type: dict
                    suboptions:
                      set:
                        type: bool
                        description: set send_extended_community_ebgp.
                      inheritance_disable:
                        type: bool
                        description: Prevent send_extended_community_ebgp from being inherited from the parent.
                  send_multicast_attributes:
                    description: Send multicast attributes to this neighbor .
                    type: dict
                    suboptions:
                      set:
                        type: bool
                        description: set send_multicast_attributes.
                      disable:
                        type: bool
                        description: Disable send multicast attributes.
                  soft_reconfiguration: &soft_reconfiguration
                    description: Per neighbor soft reconfiguration.
                    type: dict
                    suboptions:
                      inbound:
                        type: dict
                        description: inbound soft reconfiguration
                        suboptions:
                          set:
                            type: bool
                            description: set inbound
                          always:
                            type: bool
                            description: Allow inbound soft reconfiguration for this neighbor. Always use soft reconfig, even if route refresh is supported.
                          inheritance_disable:
                            type: bool
                            description: Prevent soft_reconfiguration from being inherited from the parent.
                  weight: &wt
                    type: int
                    description: Set default weight for routes from this neighbor.
                  validation: &validation
                    type: dict
                    description: Flowspec Validation for this neighbor.
                    suboptions:
                      set:
                       type: bool
                       description: set validation.
                      redirect:
                        type: bool
                        description: Flowspec Redirect nexthop Validation.
                      disable:
                        type: bool
                        description:  disable validation.
        vrfs:
          description: Configure BGP neighbor afin a VRF.
          type: list
          elements: dict
          suboptions:
            vrf:
              description: VRF name.
              type: str
            neighbors:
                description: A list of BGP neighbor address family configurations.
                type: list
                elements: dict
                suboptions:
                  neighbor_address:
                    description:
                      - Neighbor router address.
                    type: str
                    required: true
                  address_family:
                    description: Enable address family and enter its config mode
                    type: list
                    elements: dict
                    suboptions:
                      afi:
                        description: address family.
                        type: str
                        choices: [ 'ipv4', 'ipv6']
                      safi:
                        description: Address Family modifier
                        type: str
                        choices: [ 'flowspec', 'multicast', 'mvpn', 'unicast', 'labeled-unicast' ]
                      aigp: *aigp
                      allowas_in: *allowas_in
                      as_override:
                        type: dict
                        description: Override matching AS-number while sending update
                        aliases:
                          - as_overrride
                        suboptions:
                          set:
                            type: bool
                            description: set as_override
                          inheritance_disable:
                            type: bool
                            description: Prevent as-override from being inherited from the parent.
                      capability_orf_prefix: *capability
                      default_originate: *default_originate
                      long_lived_graceful_restart: *long_lived_graceful_restart
                      maximum_prefix: *maximum_prefix
                      multipath: *multipath
                      next_hop_self: *next_hop_self
                      next_hop_unchanged: *next_hop_unchanged
                      optimal_route_reflection_group_name: *optimal_route_reflection
                      orf_route_policy: *orf_rp
                      remove_private_AS: *remove_private_AS
                      route_policy: *route_policy
                      route_reflector_client: *route_reflector_client
                      send_community_ebgp: *send_community_ebgp
                      send_community_gshut_ebgp: *send_community_gshut_ebgp
                      send_extended_community_ebgp: *send_extended_community_ebgp
                      soft_reconfiguration: *soft_reconfiguration
                      site_of_origin:
                        description: Site-of-Origin extended community associated with the neighbor.
                        type: str
                      weight: *wt
                      validation: *validation

    running_config:
      description:
      - This option is used only with state I(parsed).
      - The value of this option should be the output received from the Iosxr device by
        executing the command B(show running-config router bgp).
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into Ansible structured data as per the resource module's argspec
        and the value is then returned in the I(parsed) key within the result.
      type: str
    state:
      description:
      - The state the configuration should be left in.
      type: str
      choices: [deleted, merged, overridden, replaced, gathered, rendered, parsed]
      default: merged
"""
EXAMPLES = """
# Using merged
# Before state:
# -------------
# RP/0/0/CPU0:iosxr-02#show running-config router bgp
# Sat Feb 20 03:49:43.618 UTC
# router bgp 65536
#  bgp router-id 192.0.2.1
#  address-family ipv4 unicast
#  address-family vpnv4 unicast
#  neighbor 192.0.2.2
#   remote-as 65537
#  neighbor 192.0.2.3
#   remote-as 65538
#  vrf vrf1
#   rd auto
#   neighbor 192.0.2.4
#    remote-as 65539
#  vrf vrf2
#   rd auto
#   neighbor 192.0.2.5
#    remote-as 65540

- name: Merge the provided configuration with the existing running configuration
  cisco.iosxr.iosxr_bgp_neighbor_address_family:
    state: merged
    config:
      as_number: 65536
      neighbors:
        - neighbor_address: 192.0.2.2
          address_family:
            - afi: ipv4
              safi: unicast
              multipath: true
              default_originate:
                set: true
              weight: 5
        - neighbor_address: 192.0.2.3
          address_family:
            - afi: ipv4
              safi: unicast
              multipath: true
              default_originate:
                set: true
              weight: 4
      vrfs:
        - vrf: vrf1
          neighbors:
            - neighbor_address: 192.0.2.4
              address_family:
                - afi: ipv4
                  safi: unicast
                  multipath: true
                  default_originate:
                    set: true
                  capability_orf_prefix: both
        - vrf: vrf2
          neighbors:
            - neighbor_address: 192.0.2.5
              address_family:
                - afi: ipv4
                  safi: unicast
                  multipath: true
                  default_originate:
                    set: true
                  capability_orf_prefix: both
# Task output
# -------------
# commands:
# - router bgp 65536
# - neighbor 192.0.2.2
# - address-family ipv4 unicast
# - default-originate
# - multipath
# - weight 5
# - neighbor 192.0.2.3
# - address-family ipv4 unicast
# - default-originate
# - multipath
# - weight 4
# - vrf vrf1
# - neighbor 192.0.2.4
# - address-family ipv4 unicast
# - capability orf prefix both
# - default-originate
# - multipath
# - vrf vrf2
# - neighbor 192.0.2.5
# - address-family ipv4 unicast
# - capability orf prefix both
# - default-originate
# - multipath
#
#
# after:
#   as_number: 65536
#   neighbors:
#     - neighbor_address: 192.0.2.2
#       address_family:
#         - afi: "ipv4"
#           safi: "unicast"
#           multipath: true
#           default_originate:
#             set: true
#           weight: 5
#     - neighbor_address: 192.0.2.3
#       address_family:
#         - afi: "ipv4"
#           safi: "unicast"
#           multipath: true
#           default_originate:
#             set: true
#           weight: 4
#   vrfs:
#     - vrf: vrf1
#       neighbors:
#         - neighbor_address: 192.0.2.4
#           address_family:
#             - afi: "ipv4"
#               safi: "unicast"
#               multipath: true
#               default_originate:
#                 set: true
#               capability_orf_prefix: both
#     - vrf: vrf2
#       neighbors:
#         - neighbor_address: 192.0.2.5
#           address_family:
#             - afi: "ipv4"
#               safi: "unicast"
#               multipath: true
#               default_originate:
#                 set: true
#               capability_orf_prefix: both
#
#
# After state:
# -------------
# RP/0/0/CPU0:iosxr-02#show running-config router bgp
# Sat Feb 20 03:49:43.618 UTC
# router bgp 65536
#  bgp router-id 192.0.1.1
#  address-family ipv4 unicast
#  address-family vpnv4 unicast
#  neighbor 192.0.2.2
#   remote-as 65537
#   address-family ipv4 unicast
#     multipath
#     weight 5
#     default-originate
#  neighbor 1.1.1.2
#   remote-as 65538
#   address-family ipv4 unicast
#     multipath
#     weight 5
#     default-originate
#  vrf vrf1
#   rd auto
#   neighbor 192.0.2.4
#    remote-as 65539
#    address-family ipv4 unicast
#     multipath
#     capability orf prefix both
#     default-originate
#  vrf vrf2
#   rd auto
#   neighbor 192.0.2.5
#    remote-as 65540
#    address-family ipv4 unicast
#     multipath
#     capability orf prefix both
#     default-originate
#
#
# Using delete
# Before state:
# -------------
#
# RP/0/0/CPU0:iosxr-02#show running-config router bgp
# Sat Feb 20 03:49:43.618 UTC
# router bgp 65536
#  bgp router-id 192.0.1.1
#  address-family ipv4 unicast
#  address-family vpnv4 unicast
#  neighbor 192.0.2.2
#   remote-as 65537
#   address-family ipv4 unicast
#     multipath
#     weight 5
#     default-originate
#  neighbor 192.0.2.3
#   remote-as 65538
#   address-family ipv4 unicast
#     multipath
#     weight 5
#     default-originate
#  vrf vrf1
#   rd auto
#   neighbor 192.0.2.4
#    remote-as 65539
#    address-family ipv4 unicast
#     multipath
#     capability orf prefix both
#     default-originate
#  vrf vrf2
#   rd auto
#   neighbor 192.0.2.5
#    remote-as 65540
#    address-family ipv4 unicast
#     multipath
#     capability orf prefix both
#     default-originate

- name: Delete the provided configuration
  cisco.iosxr.iosxr_bgp_neighbor_address_family:
    state: deleted
    config:
      as_number: 65536
      neighbors:
        - neighbor_address: 192.0.2.2
          address_family:
            - afi: ipv4
              safi: unicast
              multipath: true
              default_originate:
                set: true
              weight: 5

# Task output
# -------------
#
# commands:
# - router bgp 65536
# - neighbor 192.0.2.2
# - no address-family ipv4 unicast
#
#
# after:
#   as_number: 65536
#   neighbors:
#     - neighbor_address: 192.0.2.3
#       address_family:
#         - afi: "ipv4"
#           safi: "unicast"
#           multipath: true
#           default_originate:
#             set: true
#           weight: 4
#   vrfs:
#     - vrf: vrf1
#       neighbors:
#         - neighbor_address: 192.0.2.4
#           address_family:
#             - afi: "ipv4"
#               safi: "unicast"
#               multipath: true
#               default_originate:
#                 set: true
#               capability_orf_prefix: both
#         - neighbor_address: 192.0.2.5
#           address_family:
#             - afi: "ipv4"
#               safi: "unicast"
#               multipath: true
#               default_originate:
#                 set: true
#               capability_orf_prefix: both
#
#
# Using Replaced
# Before state:
# -------------
#
# RP/0/0/CPU0:iosxr-02#show running-config router bgp
# Sat Feb 20 03:49:43.618 UTC
# router bgp 65536
#  bgp router-id 192.0.1.1
#  address-family ipv4 unicast
#  address-family vpnv4 unicast
#  neighbor 192.0.2.2
#   remote-as 65537
#   address-family ipv4 unicast
#     multipath
#     weight 5
#     default-originate
#  neighbor 192.0.2.3
#   remote-as 65538
#   address-family ipv4 unicast
#     multipath
#     weight 5
#     default-originate
#  vrf vrf1
#   rd auto
#   neighbor 192.0.2.4
#    remote-as 65539
#    address-family ipv4 unicast
#     multipath
#     capability orf prefix both
#     default-originate
#  vrf vrf2
#   rd auto
#   neighbor 192.0.2.5
#    remote-as 65540
#    address-family ipv4 unicast
#     multipath
#     capability orf prefix both
#     default-originate

- name: Replace the provided configuration with the existing running configuration
  cisco.iosxr.iosxr_bgp_neighbor_address_family:
    state: replaced
    config:
      as_number: 65536
      neighbors:
        - neighbor_address: 192.0.2.2
          address_family:
            - afi: ipv4
              safi: unicast
              default_originate:
                set: true
              weight: 4
# Task output
# -------------
# commands:
# - router bgp 65536
# - neighbor 192.0.2.2
# - address-family ipv4 unicast
# - no multipath
# - weight 4
#
# after:
#   as_number: 65536
#   neighbors:
#     - neighbor_address: 192.0.2.2
#       address_family:
#         - afi: "ipv4"
#           safi: "unicast"
#           multipath: true
#           default_originate:
#             set: true
#           weight: 4
#     - neighbor_address: 192.0.2.3
#       address_family:
#         - afi: "ipv4"
#           safi: "unicast"
#           multipath: true
#           default_originate:
#             set: true
#           weight: 5
#   vrfs:
#     - vrf: vrf1
#       neighbors:
#         - neighbor_address: 192.0.2.4
#           address_family:
#             - afi: "ipv4"
#               safi: "unicast"
#               multipath: true
#               default_originate:
#                 set: true
#               capability_orf_prefix: both
#         - neighbor_address: 192.0.2.5
#           address_family:
#             - afi: "ipv4"
#               safi: "unicast"
#               multipath: true
#               default_originate:
#                 set: true
#               capability_orf_prefix: both
#
# After state:
# -------------
# Nexus9000v# show running-config router bgp
# router bgp 65536
#  bgp router-id 192.0.1.1
#  address-family ipv4 unicast
#  address-family vpnv4 unicast
#  neighbor 192.0.2.2
#   remote-as 65537
#   address-family ipv4 unicast
#     multipath
#     weight 4
#     default-originate
#  neighbor 192.0.2.3
#   remote-as 65538
#   address-family ipv4 unicast
#     multipath
#     weight 5
#     default-originate
#  vrf vrf1
#   rd auto
#   neighbor 192.0.2.4
#    remote-as 65539
#    address-family ipv4 unicast
#     multipath
#     capability orf prefix both
#     default-originate
#  vrf vrf2
#   rd auto
#   neighbor 192.0.2.5
#    remote-as 65540
#    address-family ipv4 unicast
#     multipath
#     capability orf prefix both
#     default-originate
#
#
# Using overridden
# Before state:
# -------------
# RP/0/0/CPU0:iosxr-02#show running-config router bgp
# Sat Feb 20 03:49:43.618 UTC
# router bgp 65536
#  bgp router-id 192.0.1.1
#  address-family ipv4 unicast
#  address-family vpnv4 unicast
#  neighbor 192.0.2.2
#   remote-as 65537
#   address-family ipv4 unicast
#     multipath
#     weight 5
#     default-originate
#  neighbor 192.0.2.3
#   remote-as 65538
#   address-family ipv4 unicast
#     multipath
#     weight 5
#     default-originate
#  vrf vrf1
#   rd auto
#   neighbor 192.0.2.4
#    remote-as 65539
#    address-family ipv4 unicast
#     multipath
#     capability orf prefix both
#     default-originate
#  vrf vrf2
#   rd auto
#   neighbor 192.0.2.5
#    remote-as 65540
#    address-family ipv4 unicast
#     multipath
#     capability orf prefix both
#     default-originate

- name: override the provided configuration
  cisco.iosxr.iosxr_bgp_neighbor_address_family:
    state: overridden
    config:
      as_number: 65536
      neighbors:
        - neighbor_address: 192.0.2.2
          address_family:
            - afi: ipv4
              safi: unicast
              multipath: true
              default_originate:
                set: true
              weight: 5
# Task output
# -------------
#
# commands:
# - router bgp 65536
# - neighbor 192.0.2.3
# - no address-family ipv4 unicast
# - vrf vrf1
# - neighbor 192.0.2.4
# - no address-family ipv4 unicast
# - vrf vrf1
# - neighbor 192.0.2.5
# - no address-family ipv4 unicast
#
#
#
# after:
#   as_number: 65536
#   neighbors:
#     - neighbor_address: 192.0.2.2
#       address_family:
#         - afi: "ipv4"
#           safi: "unicast"
#           multipath: true
#           default_originate:
#             set: true
#           weight: 5
#
# After state:
# -------------
# RP/0/0/CPU0:iosxr-02#show running-config router bgp
# Sat Feb 20 03:49:43.618 UTC
# router bgp 65536
#  bgp router-id 192.0.1.1
#  address-family ipv4 unicast
#  address-family vpnv4 unicast
#  neighbor 192.0.2.2
#   remote-as 65537
#   address-family ipv4 unicast
#     multipath
#     weight 5
#     default-originate
#
#
#
# Using rendered
# Before state:
# -------------
# RP/0/0/CPU0:iosxr-02#show running-config router bgp
# Sat Feb 20 03:49:43.618 UTC
# router bgp 65536
#  bgp router-id 192.0.2.1
#  address-family ipv4 unicast
#  address-family vpnv4 unicast
#  neighbor 192.0.2.2
#   remote-as 65537
#  neighbor 192.0.2.3
#   remote-as 65538
#  vrf vrf1
#   rd auto
#   neighbor 192.0.2.4
#    remote-as 65539
#  vrf vrf2
#   rd auto
#   neighbor 192.0.2.5
#    remote-as 65540

- name: >-
    Render platform specific configuration lines with state rendered (without
    connecting to the device)
  cisco.iosxr.iosxr_bgp_neighbor_address_family:
    state: rendered
    config:
      as_number: 65536
      neighbors:
        - neighbor_address: 192.0.2.2
          address_family:
            - afi: ipv4
              safi: unicast
              multipath: true
              default_originate:
                set: true
              weight: 5
        - neighbor_address: 192.0.2.3
          address_family:
            - afi: ipv4
              safi: unicast
              multipath: true
              default_originate:
                set: true
              weight: 4
      vrfs:
        - vrf: vrf1
          neighbors:
            - neighbor_address: 192.0.2.4
              address_family:
                - afi: ipv4
                  safi: unicast
                  multipath: true
                  default_originate:
                    set: true
                  capability_orf_prefix: both
        - vrf: vrf2
          neighbors:
            - neighbor_address: 192.0.2.5
              address_family:
                - afi: ipv4
                  safi: unicast
                  multipath: true
                  default_originate:
                    set: true
                  capability_orf_prefix: both
# Task output
# -------------
# commands:
# - router bgp 65536
# - neighbor 192.0.2.2
# - address-family ipv4 unicast
# - default-originate
# - multipath
# - weight 5
# - neighbor 192.0.2.3
# - address-family ipv4 unicast
# - default-originate
# - multipath
# - weight 4
# - vrf vrf1
# - neighbor 192.0.2.4
# - address-family ipv4 unicast
# - capability orf prefix both
# - default-originate
# - multipath
# - vrf vrf2
# - neighbor 192.0.2.5
# - address-family ipv4 unicast
# - capability orf prefix both
# - default-originate
# - multipath
#
# Using parsed
#
# parsed.cfg
# ------------
# router bgp 65536
#  bgp router-id 192.0.1.1
#  address-family ipv4 unicast
#  address-family vpnv4 unicast
#  neighbor 192.0.2.2
#   remote-as 65537
#   address-family ipv4 unicast
#     multipath
#     weight 5
#     default-originate
#  neighbor 1.1.1.2
#   remote-as 65538
#   address-family ipv4 unicast
#     multipath
#     weight 5
#     default-originate
#  vrf vrf1
#   rd auto
#   neighbor 192.0.2.4
#    remote-as 65539
#    address-family ipv4 unicast
#     multipath
#     capability orf prefix both
#     default-originate
#  vrf vrf2
#   rd auto
#   neighbor 192.0.2.5
#    remote-as 65540
#    address-family ipv4 unicast
#     multipath
#     capability orf prefix both
#     default-originate

- name: Parse externally provided BGP neighbor AF config
  cisco.iosxr.iosxr_bgp_neighbor_address_family:
    running_config: "{{ lookup('file', 'parsed.cfg') }}"
    state: parsed
# Task output (redacted)
# -----------------------
# parsed:
#   as_number: 65536
#   neighbors:
#     - neighbor_address: 192.0.2.2
#       address_family:
#         - afi: "ipv4"
#           safi: "unicast"
#           multipath: true
#           default_originate:
#             set: true
#           weight: 5
#     - neighbor_address: 192.0.2.3
#       address_family:
#         - afi: "ipv4"
#           safi: "unicast"
#           multipath: true
#           default_originate:
#             set: true
#           weight: 4
#   vrfs:
#     - vrf: vrf1
#       neighbors:
#         - neighbor_address: 192.0.2.4
#           address_family:
#             - afi: "ipv4"
#               safi: "unicast"
#               multipath: true
#               default_originate:
#                 set: true
#               capability_orf_prefix: both
#     - vrf: vrf2
#       neighbors:
#         - neighbor_address: 192.0.2.5
#           address_family:
#             - afi: "ipv4"
#               safi: "unicast"
#               multipath: true
#               default_originate:
#                 set: true
#               capability_orf_prefix: both
#
#
# Using Gathered
# -----------------
# Before state state:
# -------------
# RP/0/0/CPU0:iosxr-02#show running-config router bgp
# Sat Feb 20 03:49:43.618 UTC
# router bgp 65536
#  bgp router-id 192.0.1.1
#  address-family ipv4 unicast
#  address-family vpnv4 unicast
#  neighbor 192.0.2.2
#   remote-as 65537
#   address-family ipv4 unicast
#     multipath
#     weight 5
#     default-originate
#  neighbor 1.1.1.2
#   remote-as 65538
#   address-family ipv4 unicast
#     multipath
#     weight 5
#     default-originate
#  vrf vrf1
#   rd auto
#   neighbor 192.0.2.4
#    remote-as 65539
#    address-family ipv4 unicast
#     multipath
#     capability orf prefix both
#     default-originate
#  vrf vrf2
#   rd auto
#   neighbor 192.0.2.5
#    remote-as 65540
#    address-family ipv4 unicast
#     multipath
#     capability orf prefix both
#     default-originate
#
#
#
- name: Gathered the provided configuration with the existing running configuration
  cisco.iosxr.iosxr_bgp_neighbor_address_family:
    config:
    state: gathered


# Task output
# -----------------------
# gathered:
#   as_number: 65536
#   neighbors:
#     - neighbor_address: 192.0.2.2
#       address_family:
#         - afi: "ipv4"
#           safi: "unicast"
#           multipath: true
#           default_originate:
#             set: true
#           weight: 5
#     - neighbor_address: 192.0.2.3
#       address_family:
#         - afi: "ipv4"
#           safi: "unicast"
#           multipath: true
#           default_originate:
#             set: true
#           weight: 4
#   vrfs:
#     - vrf: vrf1
#       neighbors:
#         - neighbor_address: 192.0.2.4
#           address_family:
#             - afi: "ipv4"
#               safi: "unicast"
#               multipath: true
#               default_originate:
#                 set: true
#               capability_orf_prefix: both
#     - vrf: vrf2
#       neighbors:
#         - neighbor_address: 192.0.2.5
#           address_family:
#             - afi: "ipv4"
#               safi: "unicast"
#               multipath: true
#               default_originate:
#                 set: true
#               capability_orf_prefix: both
#
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.bgp_neighbor_address_family.bgp_neighbor_address_family import (
    Bgp_neighbor_address_familyArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.config.bgp_neighbor_address_family.bgp_neighbor_address_family import (
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
