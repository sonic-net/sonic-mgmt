#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for iosxr_ospf_interfaces
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: iosxr_ospf_interfaces
version_added: 1.2.0
short_description: Resource module to configure OSPF interfaces.
description:
  - This module manages OSPF(v2/v3) configuration of interfaces on devices running Cisco IOS-XR.
author: Rohit Thakur (@rohitthakur2590)
notes:
  - This module works with connection C(network_cli). See L(the IOS-XR Platform Options,../network/user_guide/platform_iosxr.html)
options:
  running_config:
    description:
      - This option is used only with state I(parsed).
      - The value of this option should be the output received from the IOS-XR device
        by executing the command B(show running-config router ospf').
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into Ansible structured data as per the resource module's argspec
        and the value is then returned in the I(parsed) key within the result.
    type: str
  config:
    description: A list of OSPF configuration for interfaces.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Name/Identifier of the interface.
        type: str
        required: True
      type:
        description:
          - Type of the interface.
        type: str
        required: True
      address_family:
        description:
          - OSPF settings on the interfaces in address-family context.
        type: list
        elements: dict
        suboptions:
          afi:
            description:
              - Address Family Identifier (AFI) for OSPF settings on the interfaces.
            type: str
            choices: ['ipv4', 'ipv6']
            required: True
          processes:
            description:
              - Interfaces configuration for an OSPF process.
            type: list
            elements: dict
            suboptions:
              process_id:
                description:
                  - OSPF process tag.
                type: str
                required: True
              area:
                description: Specify the area-id
                type: dict
                suboptions:
                  area_id:
                    description:
                      - OSPF interfaces area ID as a decimal value. Please
                        refer vendor documentation of Valid values.
                      - OSPF interfaces area ID in IP address format(e.g.
                        A.B.C.D)
                    type: str
          apply_group_option:
            description: Specify configuration from a group
            type: dict
            suboptions:
              group_name:
                description: Specify the name of the group
                type: str
              operation:
                description: Specify the group config operation
                type: str
                choices: [add, remove, append]
          authentication:
            description: Enable authentication
            type: dict
            suboptions:
              message_digest:
                description: Use message-digest authentication
                type: dict
                suboptions:
                  keychain:
                    description: Specify keychain name
                    type: str
              null_auth:
                description: Use no authentication
                type: bool
          authentication_key:
            description: Specify authentication password (key)
            type: dict
            suboptions:
              password:
                description: The OSPFv2 password (key)
                type: str
              clear:
                description: Specifies an UNENCRYPTED password (key) will follow
                type: str
              encrypted:
                description: Specifies an ENCRYPTED password (key) will follow
                type: str
          bfd:
            description: Configure BFD parameters
            type: dict
            suboptions:
              fast_detect:
                description: Configure fast detection
                type: dict
                suboptions:
                  set:
                    description: Enable fast detection only
                    type: bool
                  strict_mode:
                    description: Hold down neighbor session until BFD session is up
                    type: bool
              minimum_interval:
                description: Hello interval in milli-seconds
                type: int
              multiplier:
                description: Detect multiplier
                type: int
          cost:
            description: Specify Interface cost
            type: int
          cost_fallback:
            description: Specify Cost when cumulative bandwidth goes below the theshold
            type: dict
            suboptions:
              cost:
                description: Specify cost w.r.t cummulative bandwidth
                type: int
              threshold:
                description: Specify threshold bandwidth when cost-fallback is applied
                type: int
          database_filter:
            description: Filter OSPF LSAs during synchronization and flooding
            type: dict
            suboptions:
              all_outgoing_lsa:
                description: Filter all outgoing LSA
                type: bool
          dead_interval:
            description: Specify interval after which a neighbor is declared dead
            type: int
          demand_circuit:
            description: Enable/Disable demand circuits
            type: bool
          fast_reroute:
            description: Specify IP Fast Reroute
            type: dict
            suboptions:
              disabled:
                description: Disable IP fast reroute
                type: bool
              per_link:
                description: Specify per-prefix computation
                type: dict
                suboptions:
                  information_type:
                    description: Specify per-link LFA exclusion or FRR LFA candidate information
                    type: str
                    choices: ["exclude", "lfa_candidate"]
                  use_candidate_only:
                    description: Enable/Disable backup selection from candidate-list only
                    type: bool
                  interface:
                    description: Specify Per-link LFA exclusion information
                    type: dict
                    suboptions:
                      bvi:
                        description: Specify Bridge-Group Virtual Interface
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: int
                      bundle_ether:
                        description: Specify Aggregated Ethernet interface(s)
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: int
                      pos_int:
                        description: Specify Aggregated pos interface(s)
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: int
                      fast_ethernet:
                        description: Specify FastEthernet/IEEE 802.3 interface(s)
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: str
                      fiftygige:
                        description: Specify FiftyGigE/IEEE 802.3 interface(s)
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: str
                      fortygige:
                        description: Specify FortyGigE/IEEE 802.3 interface(s)
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: str
                      fourhundredgige:
                        description: Specify FourHundredGigE/IEEE 802.3 interface(s)
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: str
                      gigabitethernet:
                        description: Specify GigabitEthernet/IEEE 802.3 interface(s)
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: str
                      hundredgige:
                        description: Specify HundredGigE/IEEE 802.3 interface(s)
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: str
                      mgmteth:
                        description: Specify MgmtEth/IEEE 802.3 interface(s)
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: str
                      multilink:
                        description: Specify Multilink network interface(s)
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: str
                      pw_ether:
                        description: Specify PWHE Ethernet Interface
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: int
                      pw_iw:
                        description: Specify PWHE VC11 IP Interworking Interface
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: int
                      srp:
                        description: Specify SRP interface(s)
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: str
                      serial:
                        description: Specify Serial network interface(s)
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: str
                      tengige:
                        description: Specify TenGigabitEthernet/IEEE 802.3 interface(s)
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: str
                      twentyfivegige:
                        description: Specify TwentyFiveGigabitEthernet/IEEE 802.3 interface(s)
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: str
                      twohundredgige:
                        description: Specify TwoHundredGigE/IEEE 802.3 interface(s)
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: str
                      nve:
                        description: Specify Network Virtualization Endpoint Interface(s)
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: int
                      tunnel_ip:
                        description: Specify GRE/IPinIP Tunnel Interface(s)
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: int
                      tunnel_ipsec:
                        description: Specify IPSec Tunnel interface(s)
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: int
                      tunnel_mte:
                        description: Specify MPLS Traffic Engineering P2MP Tunnel interface(s)
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: int
                      tunnel_mpls:
                        description: MPLS Transport Protocol Tunnel interface
                        type: list
                        elements: dict
                        suboptions:
                          name:
                            description: Specify the interface id
                            type: str
          flood_reduction:
            description: Enable/Disable flood reduction
            type: bool
          hello_interval:
            description: Specify Time between HELLO packets
            type: int
          link_down_fast_detect:
            description: Configure interface down parameters
            type: bool
          message_digest_key:
            description: Message digest authentication password (key)
            type: dict
            suboptions:
              id:
                description: Key ID
                type: int
                required: true
              md5:
                description: Use MD5 Algorithm
                type: dict
                required: true
                suboptions:
                  password:
                    description: The OSPFv2 password (key)
                    type: str
                  clear:
                    description: Specifies an UNENCRYPTED password (key) will follow
                    type: bool
                  encrypted:
                    description: Specifies an ENCRYPTED password (key) will follow
                    type: bool
          mpls_ldp_sync:
            description: Enable/Disable MPLS LDP Sync
            type: bool
          mtu_ignore:
            description: Enable/Disable ignoring of MTU in DBD packets
            type: bool
          network:
            description: Specify Network type
            type: str
            choices: ["broadcast", "non-broadcast", "point-to-multipoint", "point-to-point"]
          neighbors:
            description: Specify a neighbor routers
            type: list
            elements: dict
            suboptions:
              neighbor_id:
                description: Specify Neighbor address (name)
                type: str
              cost:
                description: Specify OSPF cost for point-to-multipoint neighbor
                type: int
              db_filter_all_out:
                description: Specify Filter OSPF LSA during synchronization and flooding for point-to-multipoint neighbor
                type: bool
              poll_interval:
                description: Specify OSPF dead-router polling interval
                type: int
              priority:
                description: Specify OSPF priority of non-broadcast neighbor
                type: int
          packet_size:
            description: Customize size of OSPF packets upto MTU
            type: int
          passive:
            description: Enable/Disable passive
            type: bool
          prefix_suppression:
            description: Suppress advertisement of the prefixes
            type: bool
          priority:
            description: Specify Router priority
            type: int
          retransmit_interval:
            description: Specify time between retransmitting lost link state advertisements
            type: int
          security_ttl:
            description: Enable security
            type: dict
            suboptions:
              set:
                description: Enable ttl security
                type: bool
              hops:
                description: Maximum number of IP hops allowed <1-254>
                type: int
          transmit_delay:
            description: Specify estimated time needed to send link-state update packet
            type: int
  state:
    description:
      - The state the configuration should be left in.
    type: str
    choices:
      - merged
      - replaced
      - overridden
      - deleted
      - gathered
      - parsed
      - rendered
    default: merged
"""
EXAMPLES = """
# Using merged

# Before state:
# -------------
#
# RP/0/RP0/CPU0:anton#show running-config router ospf
# % No such configuration item(s)
#

- name: Merge provided OSPF interfaces configuration with the existing configuration
  cisco.iosxr.iosxr_ospf_interfaces:
    config:
      - name: GigabitEthernet0/0/0/0
        type: gigabitethernet
        address_family:
          - afi: ipv4
            processes:
              - process_id: LAB3
                area:
                  area_id: 0.0.0.3
            cost: 20
            authentication:
              message_digest:
                keychain: cisco
          - afi: ipv6
            processes:
              - process_id: LAB3
                area:
                  area_id: 0.0.0.2
            cost: 30
    state: merged

#
#
# Task Output:
# ------------
#
# before: []
#
# commands:
#   - router ospf LAB3 area 0.0.0.3 interface GigabitEthernet 0/0/0/0 cost 20
#   - router ospf LAB3 area 0.0.0.3 interface GigabitEthernet 0/0/0/0 authentication message-digest
#   - router ospf LAB3 area 0.0.0.3 interface GigabitEthernet 0/0/0/0 authentication message-digest keychain cisco
#   - router ospfv3 LAB3 area 0.0.0.2 interface GigabitEthernet 0/0/0/0 cost 30
#
# after:
#   - address_family:
#     - afi: ipv4
#       authentication:
#         message_digest:
#           keychain: cisco
#       cost: 20
#       processes:
#       - area:
#           area_id: 0.0.0.3
#         process_id: LAB3
#     - afi: ipv6
#       cost: 30
#       processes:
#       - area:
#           area_id: 0.0.0.2
#         process_id: LAB3
#     name: GigabitEthernet0/0/0/0
#     type: gigabitethernet
#
# After state:
# ------------
#
# RP/0/0/CPU0:an-iosxr-02#show running-config router ospf
# Thu Oct 23 06:00:57.217 UTC
# router ospf LAB3
#  area 0.0.0.3
#   interface GigabitEthernet0/0/0/0
#    cost 20
#    authentication message-digest keychain cisco
#   !
#  !
# !
# router ospfv3 LAB3
#  area 0.0.0.2
#   interface GigabitEthernet0/0/0/0
#    cost 30
#   !
#  !
# !

# Using replaced
#
# Before state:
# -------------
#
#
# RP/0/0/CPU0:an-iosxr-02#show running-config router ospf
# Thu Oct 23 06:00:57.217 UTC
# router ospf LAB3
#  area 0.0.0.3
#   interface GigabitEthernet0/0/0/0
#    cost 20
#    authentication message-digest keychain cisco
#   !
#  !
# !
# router ospfv3 LAB3
#  area 0.0.0.2
#   interface GigabitEthernet0/0/0/0
#    cost 30
#   !
#  !
# !

- name: Replace OSPF interfaces configuration
  cisco.iosxr.iosxr_ospf_interfaces:
    config:
      - name: GigabitEthernet0/0/0/0
        type: gigabitethernet
        address_family:
          - afi: ipv4
            processes:
              - process_id: LAB3
                area:
                  area_id: 0.0.0.3
            cost: 30
            authentication:
              message_digest:
                keychain: ciscoiosxr
          - afi: ipv6
            processes:
              - process_id: LAB3
                area:
                  area_id: 0.0.0.2
            cost: 30
    state: replaced
#
# Task Output:
# ------------
#
# before:
#   - address_family:
#     - afi: ipv4
#       authentication:
#         message_digest:
#           keychain: cisco
#       cost: 20
#       processes:
#       - area:
#           area_id: 0.0.0.3
#         process_id: LAB3
#     - afi: ipv6
#       cost: 30
#       processes:
#       - area:
#           area_id: 0.0.0.2
#         process_id: LAB3
#     name: GigabitEthernet0/0/0/0
#     type: gigabitethernet
#
# commands:
#   - router ospf LAB3 area 0.0.0.3 interface GigabitEthernet 0/0/0/0 cost 30
#   - router ospf LAB3 area 0.0.0.3 interface GigabitEthernet 0/0/0/0 authentication message-digest
#   - router ospf LAB3 area 0.0.0.3 interface GigabitEthernet 0/0/0/0 authentication message-digest keychain ciscoiosxr
#
# after:
#   - address_family:
#     - afi: ipv4
#       authentication:
#         message_digest:
#           keychain: ciscoiosxr
#       cost: 30
#       processes:
#       - area:
#           area_id: 0.0.0.3
#         process_id: LAB3
#     - afi: ipv6
#       cost: 30
#       processes:
#       - area:
#           area_id: 0.0.0.2
#         process_id: LAB3
#     name: GigabitEthernet0/0/0/0
#     type: gigabitethernet
#
# After state:
# ------------
#
# RP/0/0/CPU0:an-iosxr-02#show running-config router ospf
# Thu Oct 23 06:10:39.827 UTC
# router ospf LAB3
#  area 0.0.0.3
#   interface GigabitEthernet0/0/0/0
#    cost 30
#    authentication message-digest keychain ciscoiosxr
#   !
# router ospfv3 LAB3
#  area 0.0.0.2
#   interface GigabitEthernet0/0/0/0
#    cost 30
#   !
#  !
# !

# Using overridden
#
# Before state
# ------------
#
- name: Override existing OSPF interfaces configuration
  cisco.iosxr.iosxr_ospf_interfaces:
    config:
      - name: GigabitEthernet0/0/0/1
        type: gigabitethernet
        address_family:
          - afi: ipv4
            processes:
              - process_id: LAB1
                area:
                  area_id: 0.0.0.3
            cost: 10
            authentication:
              message_digest:
                keychain: iosxr
    state: overridden

#
#
# Task Output:
# ------------
#
# before:
#   - address_family:
#     - afi: ipv4
#       authentication:
#         message_digest:
#           keychain: ciscoiosxr
#       cost: 30
#       processes:
#       - area:
#           area_id: 0.0.0.3
#         process_id: LAB3
#     - afi: ipv6
#       cost: 30
#       processes:
#       - area:
#           area_id: 0.0.0.2
#         process_id: LAB3
#     name: GigabitEthernet0/0/0/0
#     type: gigabitethernet
#
# commands:
#   - no router ospf LAB3 area 0.0.0.3 interface GigabitEthernet 0/0/0/0
#   - no router ospfv3 LAB3 area 0.0.0.2 interface GigabitEthernet 0/0/0/0
#   - router ospf LAB1 area 0.0.0.3 interface GigabitEthernet 0/0/0/1 cost 10
#   - router ospf LAB1 area 0.0.0.3 interface GigabitEthernet 0/0/0/1 authentication message-digest
#   - router ospf LAB1 area 0.0.0.3 interface GigabitEthernet 0/0/0/1 authentication message-digest keychain iosxr
#
# after:
#   - address_family:
#     - afi: ipv4
#       authentication:
#         message_digest:
#           keychain: iosxr
#       cost: 10
#       processes:
#       - area:
#           area_id: 0.0.0.3
#         process_id: LAB1
#     name: GigabitEthernet0/0/0/1
#     type: gigabitethernet
#
# After state:
# ------------
#
# RP/0/0/CPU0:an-iosxr-02#show running-config router ospf
# Thu Oct 23 06:28:15.025 UTC
# router ospf LAB1
#  area 0.0.0.3
#   interface GigabitEthernet0/0/0/1
#    cost 10
#    authentication message-digest keychain iosxr
#   !
#  !
# !
# router ospf LAB3
#  area 0.0.0.3
#  !
# !
# router ospfv3 LAB3
#  area 0.0.0.2
#  !
# !

# Using deleted
#
# Before state:
# -------------
#
#
# RP/0/0/CPU0:an-iosxr-02#show running-config router ospf
# Thu Oct 23 06:28:15.025 UTC
# router ospf LAB1
#  area 0.0.0.3
#   interface GigabitEthernet0/0/0/1
#    cost 10
#    authentication message-digest keychain iosxr
#   !
#  !
# !
# router ospf LAB3
#  area 0.0.0.3
#   interface GigabitEthernet0/0/0/0
#    cost 20
#    authentication message-digest keychain cisco
#   !
#  !
# !
# router ospfv3 LAB3
#  area 0.0.0.2
#   interface GigabitEthernet0/0/0/0
#    cost 30
#   !
#  !
# !

- name: Deleted existing OSPF interfaces from the device
  cisco.iosxr.iosxr_ospf_interfaces:
    config:
      - name: GigabitEthernet0/0/0/1
        type: gigabitethernet
    state: deleted

#
# Task Output:
# ------------
#
# before:
#   - address_family:
#     - afi: ipv4
#       authentication:
#         message_digest:
#           keychain: iosxr
#       cost: 10
#       processes:
#       - area:
#           area_id: 0.0.0.3
#         process_id: LAB1
#     name: GigabitEthernet0/0/0/1
#     type: gigabitethernet
#   - address_family:
#     - afi: ipv4
#       authentication:
#         message_digest:
#           keychain: cisco
#       cost: 20
#       processes:
#       - area:
#           area_id: 0.0.0.3
#         process_id: LAB3
#     - afi: ipv6
#       cost: 30
#       processes:
#       - area:
#           area_id: 0.0.0.2
#         process_id: LAB3
#     name: GigabitEthernet0/0/0/0
#     type: gigabitethernet
#
# commands:
#   - no router ospf LAB1 area 0.0.0.3 interface GigabitEthernet 0/0/0/1]
#
# after:
#   - address_family:
#     - afi: ipv4
#       authentication:
#         message_digest:
#           keychain: cisco
#       cost: 20
#       processes:
#       - area:
#           area_id: 0.0.0.3
#         process_id: LAB3
#     - afi: ipv6
#       cost: 30
#       processes:
#       - area:
#           area_id: 0.0.0.2
#         process_id: LAB3
#     name: GigabitEthernet0/0/0/0
#     type: gigabitethernet
#
# After state:
# ------------
#
# RP/0/0/CPU0:an-iosxr-02#show running-config router ospf
# Thu Oct 23 06:34:38.319 UTC
# router ospf LAB1
#  area 0.0.0.3
#  !
# !
# router ospf LAB3
#  area 0.0.0.3
#   interface GigabitEthernet0/0/0/0
#    cost 20
#    authentication message-digest keychain cisco
#   !
#  !
# !
# router ospfv3 LAB3
#  area 0.0.0.2
#   interface GigabitEthernet0/0/0/0
#    cost 30
#   !
#  !
# !

# Using parsed
#
# parsed.cfg
# ------------
# router ospf LAB
#  area 0.0.0.0
#  !
#  area 0.0.0.9
#  !
# !
# router ospf LAB1
#  area 0.0.0.1
#  !
#  area 0.0.0.3
#  !
# !
# router ospf LAB3
#  area 0.0.0.3
#   interface GigabitEthernet0/0/0/0
#    cost 20
#    authentication message-digest keychain cisco
#   !
#  !
# !
# router ospf ipv4
# !
- name: Parsed running config and display structured facts.
  cisco.iosxr.iosxr_ospf_interfaces:
    running_config: "{{ lookup('file', './parsed.cfg') }}"
    state: parsed
#
# Task Output:
# ------------
#
# parsed:
#   - address_family:
#     - afi: ipv4
#       authentication:
#         message_digest:
#           keychain: cisco
#       cost: 20
#       processes:
#       - area:
#           area_id: 0.0.0.3
#         process_id: LAB3
#     name: GigabitEthernet0/0/0/0
#     type: gigabitethernet

# Using rendered
#
- name: Render the commands for provided  configuration
  cisco.iosxr.iosxr_ospf_interfaces:
    config:
      - name: GigabitEthernet0/0/0/0
        type: gigabitethernet
        address_family:
          - afi: ipv4
            processes:
              - process_id: LAB3
                area:
                  area_id: 0.0.0.3
            cost: 20
            authentication:
              message_digest:
                keychain: cisco
          - afi: ipv6
            processes:
              - process_id: LAB3
                area:
                  area_id: 0.0.0.2
            cost: 30
    state: rendered

#
# Task Output:
# ------------
#
# rendered:
#   - router ospf LAB3 area 0.0.0.3 interface GigabitEthernet 0/0/0/0 cost 20
#   - router ospf LAB3 area 0.0.0.3 interface GigabitEthernet 0/0/0/0 authentication message-digest
#   - router ospf LAB3 area 0.0.0.3 interface GigabitEthernet 0/0/0/0 authentication message-digest keychain cisco
#   - router ospfv3 LAB3 area 0.0.0.2 interface GigabitEthernet 0/0/0/0 cost 30

# Using gathered
#
# Before state:
# -------------
#
# RP/0/0/CPU0:an-iosxr-02#show running-config router ospf
# Thu Oct 23 06:50:38.743 UTC
# router ospf LAB3
#  area 0.0.0.3
#   interface GigabitEthernet0/0/0/0
#    cost 20
#    authentication message-digest keychain cisco
#   !
#  !
# !
# router ospfv3 LAB3
#  area 0.0.0.2
#   interface GigabitEthernet0/0/0/0
#    cost 30
#   !
#  !
# !


- name: Gather ospf_interfaces routes configuration
  cisco.iosxr.iosxr_ospf_interfaces:
    state: gathered
#
# Task Output:
# ------------
#
# gathered:
#   - address_family:
#     - afi: ipv4
#       authentication:
#         message_digest:
#           keychain: cisco
#       cost: 20
#       processes:
#       - area:
#           area_id: 0.0.0.3
#         process_id: LAB3
#     - afi: ipv6
#       cost: 30
#       processes:
#       - area:
#           area_id: 0.0.0.2
#         process_id: LAB3
#     name: GigabitEthernet0/0/0/0
#     type: gigabitethernet
"""
RETURN = """
before:
  description: The configuration prior to the model invocation.
  returned: always
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
after:
  description: The resulting configuration model invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample:
  - router ospf LAB3 area 0.0.0.3 interface GigabitEthernet 0/0/0/0 cost 20
  - router ospf LAB3 area 0.0.0.3 interface GigabitEthernet 0/0/0/0 authentication message-digest

rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
  - router ospf LAB3 area 0.0.0.3 interface GigabitEthernet 0/0/0/0 cost 20

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

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.ospf_interfaces.ospf_interfaces import (
    Ospf_interfacesArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.config.ospf_interfaces.ospf_interfaces import (
    Ospf_interfaces,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=Ospf_interfacesArgs.argument_spec,
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

    result = Ospf_interfaces(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
