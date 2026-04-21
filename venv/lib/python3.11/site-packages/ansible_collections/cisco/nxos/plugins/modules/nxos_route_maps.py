#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for nxos_route_maps
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: nxos_route_maps
short_description: Route Maps resource module.
description:
- This module manages route maps configuration on devices running Cisco NX-OS.
version_added: 2.2.0
notes:
- Tested against NX-OS 9.3.6.
- Unsupported for Cisco MDS
- This module works with connection C(network_cli) and C(httpapi).
author: Nilashish Chakraborty (@NilashishC)
options:
  running_config:
    description:
    - This option is used only with state I(parsed).
    - The value of this option should be the output received from the NX-OS device
      by executing the command B(show running-config | section '^route-map').
    - The state I(parsed) reads the configuration from C(running_config) option and
      transforms it into Ansible structured data as per the resource module's argspec
      and the value is then returned in the I(parsed) key within the result.
    type: str
  config:
    description: A list of route-map configuration.
    type: list
    elements: dict
    suboptions:
      route_map:
        description: Route-map name.
        type: str
      entries:
        description: List of entries (identified by sequence number) for this route-map.
        type: list
        elements: dict
        suboptions:
          sequence:
            description: Sequence to insert to/delete from existing route-map entry.
            type: int
          action:
            description: Route map denies or permits set operations.
            type: str
            choices: ["deny", "permit"]
          continue_sequence:
            description: Continue on a different entry within the route-map.
            type: int
          description:
            description: Description of the route-map.
            type: str
          match:
            description: Match values from routing table.
            type: dict
            suboptions:
              as_number:
                description: Match BGP peer AS number.
                type: dict
                suboptions:
                  asn:
                    description: AS number.
                    type: list
                    elements: str
                  as_path_list:
                    description: AS path access list name.
                    type: list
                    elements: str
              as_path:
                description: Match BGP AS path access-list.
                type: list
                elements: str
              community:
                description: Match BGP community list.
                type: dict
                suboptions:
                  community_list:
                    description: Community list.
                    type: list
                    elements: str
                  exact_match:
                    description: Do exact matching of communities.
                    type: bool
              evpn:
                description: Match BGP EVPN Routes.
                type: dict
                suboptions:
                  route_types:
                    description: Match route type for evpn route.
                    type: list
                    elements: str
              extcommunity:
                description: Match BGP community list.
                type: dict
                suboptions:
                  extcommunity_list:
                    description: Extended Community list.
                    type: list
                    elements: str
                  exact_match:
                    description: Do exact matching of extended communities.
                    type: bool
              interfaces:
                description: Match first hop interface of route.
                type: list
                elements: str
              ip:
                description: Configure IP specific information.
                type: dict
                suboptions: &id001
                  address:
                    description: Match address of route or match packet.
                    type: dict
                    suboptions:
                      access_list:
                        description: IP access-list name (for use in route-maps for PBR only).
                        type: str
                      prefix_lists:
                        description: Match entries of prefix-lists.
                        type: list
                        elements: str
                  multicast:
                    description: Match multicast attributes.
                    type: dict
                    suboptions:
                      source:
                        description: Multicast source address.
                        type: str
                      group:
                        description:
                          - Multicast Group prefix.
                          - Mutually exclusive with group_range.
                        type: dict
                        suboptions:
                          prefix:
                            description: IPv4 group prefix.
                            type: str
                      group_range:
                        description:
                          - Multicast Group address range.
                          - Mutually exclusive with group.
                        type: dict
                        suboptions:
                          first:
                            description: First Group address.
                            type: str
                          last:
                            description: Last Group address.
                            type: str
                      rp:
                        description: Rendezvous point.
                        type: dict
                        suboptions:
                          prefix:
                            description: IPv4 rendezvous prefix.
                            type: str
                          rp_type:
                            description: Multicast rendezvous point type.
                            type: str
                            choices: ["ASM", "Bidir"]
                  next_hop:
                    description: Match next-hop address of route.
                    type: dict
                    suboptions:
                      prefix_lists:
                        description: Match entries of prefix-lists.
                        type: list
                        elements: str
                  route_source:
                    description: Match advertising source address of route.
                    type: dict
                    suboptions:
                      prefix_lists:
                        description: Match entries of prefix-lists.
                        type: list
                        elements: str
              ipv6:
                description: Configure IPv6 specific information.
                type: dict
                suboptions: *id001
              mac_list:
                description: Match entries of mac-lists.
                type: list
                elements: str
              metric:
                description: Match metric of route.
                type: list
                elements: int
              ospf_area:
                description: Match ospf area.
                type: list
                elements: int
              route_types:
                description: Match route-type of route.
                type: list
                elements: str
                choices: ["external", "inter-area", "internal", "intra-area", "level-1", "level-2", "local", "nssa-external", "type-1", "type-2"]
              source_protocol:
                description: Match source protocol.
                type: list
                elements: str
              tags:
                description: Match tag of route.
                type: list
                elements: int
          set:
            description: Set values in destination routing protocol.
            type: dict
            suboptions:
              as_path:
                description: Prepend string for a BGP AS-path attribute.
                type: dict
                suboptions:
                  prepend:
                    description: Prepend to the AS-Path.
                    type: dict
                    suboptions:
                      as_number:
                        description: AS number.
                        type: list
                        elements: str
                      last_as:
                        description: Number of last-AS prepends.
                        type: int
                  tag:
                    description: Set the tag as an AS-path attribute.
                    type: bool
              comm_list:
                description: Set BGP community list (for deletion).
                type: str
              community:
                description: Set BGP community attribute.
                type: dict
                suboptions:
                  additive:
                    description: Add to existing community.
                    type: bool
                  graceful_shutdown:
                    description: Graceful Shutdown (well-known community).
                    type: bool
                  internet:
                    description: Internet (well-known community).
                    type: bool
                  local_as:
                    description: Do not send outside local AS (well-known community).
                    type: bool
                  no_advertise:
                    description: Do not advertise to any peer (well-known community).
                    type: bool
                  no_export:
                    description: Do not export to next AS (well-known community).
                    type: bool
                  number:
                    description: "Community number aa:nn format"
                    type: list
                    elements: str
              dampening:
                description: Set BGP route flap dampening parameters.
                type: dict
                suboptions:
                  half_life:
                    description: Half-life time for the penalty.
                    type: int
                  start_reuse_route:
                    description: Value to start reusing a route.
                    type: int
                  start_suppress_route:
                    description: Value to start suppressing a route.
                    type: int
                  max_suppress_time:
                    description: Maximum suppress time for stable route.
                    type: int
              distance:
                description: Configure administrative distance.
                type: dict
                suboptions:
                  igp_ebgp_routes:
                    description: Administrative distance for IGP or EBGP routes
                    type: int
                  internal_routes:
                    description: Distance for internal routes.
                    type: int
                  local_routes:
                    description: Distance for local routes.
                    type: int
              evpn:
                description: Set BGP EVPN Routes.
                type: dict
                suboptions:
                  gateway_ip:
                    description:
                      - Set gateway IP for type 5 EVPN routes.
                      - Cannot set ip and use-nexthop in the same route-map sequence.
                    type: dict
                    suboptions:
                      ip:
                        description: Gateway IP address.
                        type: str
                      use_nexthop:
                        description: Use nexthop address as gateway IP.
                        type: bool
              extcomm_list:
                description: Set BGP extcommunity list (for deletion).
                type: str
              extcommunity:
                description: Set BGP extcommunity attribute.
                type: dict
                suboptions:
                  rt:
                    description: Route-Target.
                    type: dict
                    suboptions:
                      additive:
                        description: Add to existing rt extcommunity.
                        type: bool
                      extcommunity_numbers:
                        description:
                          - Extcommunity number.
                          - "Supported formats are ASN2:NN, ASN4:NN, IPV4:NN."
                        type: list
                        elements: str
              forwarding_address:
                description: Set the forwarding address.
                type: bool
              null_interface:
                description: Output Null interface.
                type: str
              ip:
                description: Configure IP features.
                type: dict
                suboptions: &id002
                  address:
                    description: Specify IP address.
                    type: dict
                    suboptions:
                      prefix_list:
                        description: Name of prefix list (Max Size 63).
                        type: str
                  precedence:
                    description: Set precedence field.
                    type: str
                  next_hop:
                    description: Set next-hop IP address (for policy-based routing)
                    type: dict
                    suboptions:
                      address:
                        description: Set space-separated list of next-hop IP addresses. Address ordering is important. Also don`t use unnecessary spaces.
                        type: str
                      drop_on_fail:
                        description: Drop packets instead of using default routing when the configured next hop becomes unreachable
                        type: bool
                        default: false
                      force_order:
                        description: Enable next-hop ordering as specified in the address parameter.
                        type: bool
                        default: false
                      load_share:
                        description: Enable traffic load balancing across a maximum of 32 next-hop addresses
                        type: bool
                        default: false
                      peer_address:
                        description:
                          - BGP prefix next hop is set to the local address of the peer.
                          - If no next hop is set in the route map, the next hop is set to the one stored in the path.
                        type: bool
                      redist_unchanged:
                        description:
                          - Set for next-hop address conservation for non-local generated routes.
                          - Used with redistribute command. Available to maintain BGP routing compliant with RFC 4271 on Nexus OS.
                        type: bool
                      unchanged:
                        description:  Set for next-hop address conservation in eBGP outgoing updates
                        type: bool
                      verify_availability:
                        description: Set next-hop ip address tracking with IP SLA
                        type: list
                        elements: dict
                        suboptions:
                          address:
                            description: Set one next-hop address
                            type: str
                            required: true
                          track:
                            description: Set track number
                            type: int
                            required: true
                          drop_on_fail:
                            description: Drop packets instead of using default routing when the configured next hop becomes unreachable
                            type: bool
                            default: false
                          force_order:
                            description: Enable next-hop ordering as specified in the address parameter.
                            type: bool
                            default: false
                          load_share:
                            description: Enable traffic load balancing across a maximum of 32 next-hop addresses
                            type: bool
                            default: false
              ipv6:
                description: Configure IPv6 features.
                type: dict
                suboptions:
                  address:
                    description: Specify IP address.
                    type: dict
                    suboptions:
                      prefix_list:
                        description: Name of prefix list (Max Size 63).
                        type: str
                  precedence:
                    description: Set precedence field.
                    type: str
              label_index:
                description: Set Segment Routing (SR) label index of route.
                type: int
              level:
                description: Where to import route.
                type: str
                choices: ["level-1", "level-1-2", "level-2"]
              local_preference:
                description: BGP local preference path attribute.
                type: int
              metric:
                description: Set metric for destination routing protocol.
                type: dict
                suboptions:
                  bandwidth:
                    description: Metric value or Bandwidth in Kbits per second (Max Size 11).
                    type: int
                  igrp_delay_metric:
                    description: IGRP delay metric.
                    type: int
                  igrp_reliability_metric:
                    description: IGRP reliability metric where 255 is 100 percent reliable.
                    type: int
                  igrp_effective_bandwidth_metric:
                    description: IGRP Effective bandwidth metric (Loading) 255 is 100%.
                    type: int
                  igrp_mtu:
                    description: IGRP MTU of the path.
                    type: int
              metric_type:
                description: Type of metric for destination routing protocol.
                type: str
                choices: ["external", "internal", "type-1", "type-2"]
              nssa_only:
                description: OSPF NSSA Areas.
                type: bool
              origin:
                description: BGP origin code.
                type: str
                choices: ["egp", "igp", "incomplete"]
              path_selection:
                description: Path selection criteria for BGP.
                type: str
                choices: ["all", "backup", "best2", "multipaths"]
              tag:
                description: Tag value for destination routing protocol.
                type: int
              weight:
                description: BGP weight for routing table.
                type: int
  state:
    description:
    - The state the configuration should be left in.
    - With state I(replaced), for the listed route-maps,
      sequences that are in running-config but not in the task are negated.
    - With state I(overridden), all route-maps that are in running-config but
      not in the task are negated.
    - Please refer to examples for more details.
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
# nxos-9k-rdo# show running-config | section "^route-map"
# nxos-9k-rdo#

- name: Merge the provided configuration with the existing running configuration
  cisco.nxos.nxos_route_maps:
    config:
      - route_map: rmap1
        entries:
          - sequence: 10
            action: permit
            description: rmap1-10-permit
            match:
              ip:
                address:
                  access_list: acl_1
              as_path: Allow40
              as_number:
                asn: 65564

          - sequence: 20
            action: deny
            description: rmap1-20-deny
            match:
              community:
                community_list:
                  - BGPCommunity1
                  - BGPCommunity2
              ip:
                address:
                  prefix_lists:
                    - AllowPrefix1
                    - AllowPrefix2
            set:
              dampening:
                half_life: 30
                start_reuse_route: 1500
                start_suppress_route: 10000
                max_suppress_time: 120

      - route_map: rmap2
        entries:
          - sequence: 20
            action: permit
            description: rmap2-20-permit
            continue_sequence: 40
            match:
              ipv6:
                address:
                  prefix_lists: AllowIPv6Prefix
              interfaces: "{{ nxos_int1 }}"
            set:
              as_path:
                prepend:
                  as_number:
                    - 65563
                    - 65568
                    - 65569
              comm_list: BGPCommunity

          - sequence: 40
            action: deny
            description: rmap2-40-deny
            match:
              route_types:
                - level-1
                - level-2
              tags: 2
              ip:
                multicast:
                  rp:
                    prefix: 192.0.2.0/24
                    rp_type: ASM
                  source: 203.0.113.0/24
                  group_range:
                    first: 239.0.0.1
                    last: 239.255.255.255

      - route_map: rmap3
        entries:
          - sequence: 10
            description: "*** first stanza ***"
            action: permit
            set:
              ip:
                next_hop:
                  verify_availability:
                    - address: 3.3.3.3
                      track: 1
                    - address: 4.4.4.4
                      track: 3

          - sequence: 20
            description: "*** second stanza ***"
            action: permit
            set:
              ip:
                next_hop:
                  address: 6.6.6.6 2.2.2.2
                  load_share: true
                  drop_on_fail: true

          - sequence: 30
            description: "*** third stanza ***"
            action: permit
            set:
              ip:
                next_hop:
                  peer_address: true

          - sequence: 40
            description: "*** fourth stanza ***"
            action: permit
            set:
              ip:
                next_hop:
                  unchanged: true
                  redist_unchanged: true
    state: merged

# Task output
# -------------
#  before: []
#
#  commands:
#    - "route-map rmap1 permit 10"
#    - "match as-number 65564"
#    - "match as-path Allow40"
#    - "match ip address acl_1"
#    - "description rmap1-10-permit"
#    - "route-map rmap1 deny 20"
#    - "match community BGPCommunity1 BGPCommunity2"
#    - "match ip address prefix-list AllowPrefix1 AllowPrefix2"
#    - "description rmap1-20-deny"
#    - "set dampening 30 1500 10000 120"
#    - "route-map rmap2 permit 20"
#    - "match interface Ethernet1/1"
#    - "match ipv6 address prefix-list AllowIPv6Prefix"
#    - "set as-path prepend 65563 65568 65569"
#    - "description rmap2-20-permit"
#    - "continue 40"
#    - "set comm-list BGPCommunity delete"
#    - "route-map rmap2 deny 40"
#    - "match ip multicast source 203.0.113.0/24 group-range 239.0.0.1 to 239.255.255.255 rp 192.0.2.0/24 rp-type ASM"
#    - "match route-type level-1 level-2"
#    - "match tag 2"
#    - "description rmap2-40-deny"
#    - "route-map rmap3 permit 10"
#    - "description *** first stanza ***"
#    - "set ip next-hop verify-availability 3.3.3.3 track 1"
#    - "set ip next-hop verify-availability 4.4.4.4 track 3"
#    - "route-map rmap3 permit 20"
#    - "description *** second stanza ***"
#    - "set ip next-hop 6.6.6.6 2.2.2.2 load-share  drop-on-fail"
#    - "route-map rmap3 permit 30"
#    - "description *** third stanza ***"
#    - "set ip next-hop peer-address"
#    - "route-map rmap3 permit 40"
#    - "description *** fourth stanza ***"
#    - "set ip next-hop unchanged"
#    - "set ip next-hop redist-unchanged"
#
#  after:
#   - route_map: rmap1
#     entries:
#     - action: permit
#       description: rmap1-10-permit
#       match:
#         as_number:
#           asn:
#           - '65564'
#         as_path:
#           - Allow40
#         ip:
#           address:
#             access_list: acl_1
#       sequence: 10
#
#     - action: deny
#       description: rmap1-20-deny
#       match:
#         community:
#           community_list:
#           - BGPCommunity1
#           - BGPCommunity2
#         ip:
#           address:
#             prefix_lists:
#             - AllowPrefix1
#             - AllowPrefix2
#       sequence: 20
#       set:
#         dampening:
#           half_life: 30
#           max_suppress_time: 120
#           start_reuse_route: 1500
#           start_suppress_route: 10000
#
#   - route_map: rmap2
#     entries:
#     - action: permit
#       continue_sequence: 40
#       description: rmap2-20-permit
#       match:
#         interfaces:
#         - Ethernet1/1
#         ipv6:
#           address:
#             prefix_lists:
#             - AllowIPv6Prefix
#         sequence: 20
#         set:
#           as_path:
#             prepend:
#               as_number:
#               - '65563'
#               - '65568'
#               - '65569'
#           comm_list: BGPCommunity
#
#     - action: deny
#       description: rmap2-40-deny
#       match:
#         ip:
#           multicast:
#             group_range:
#               first: 239.0.0.1
#               last: 239.255.255.255
#             rp:
#               prefix: 192.0.2.0/24
#               rp_type: ASM
#             source: 203.0.113.0/24
#         route_types:
#         - level-1
#         - level-2
#         tags:
#         - 2
#       sequence: 40
#
#   - route_map: rmap3
#     entries:
#     - sequence: 10
#       description: "*** first stanza ***"
#       action: permit
#       set:
#         ip:
#           next_hop:
#             verify_availability:
#             - address: 3.3.3.3
#               track: 1
#             - address: 4.4.4.4
#               track: 3
#
#     - sequence: 20
#       description: "*** second stanza ***"
#       action: permit
#       set:
#         ip:
#           next_hop:
#             address: 6.6.6.6 2.2.2.2
#             load_share: true
#             drop_on_fail: true
#
#     - sequence: 30
#       description: "*** third stanza ***"
#       action: permit
#       set:
#         ip:
#           next_hop:
#             peer_address: true
#
#     - sequence: 40
#       description: "*** fourth stanza ***"
#       action: permit
#       set:
#         ip:
#           next_hop:
#             unchanged: true
#             redist_unchanged: true

# After state:
# ------------
# nxos-9k-rdo# show running-config | section "^route-map"
# route-map rmap1 permit 10
#   match as-number 65564
#   match as-path Allow40
#   match ip address acl_1
#   description rmap1-10-permit
# route-map rmap1 deny 20
#   match community BGPCommunity1 BGPCommunity2
#   match ip address prefix-list AllowPrefix1 AllowPrefix2
#   description rmap1-20-deny
#   set dampening 30 1500 10000 120
# route-map rmap2 permit 20
#   match interface Ethernet1/1
#   match ipv6 address prefix-list AllowIPv6Prefix
#   set as-path prepend 65563 65568 65569
#   description rmap2-20-permit
#   continue 40
#   set comm-list BGPCommunity delete
# route-map rmap2 deny 40
#   match ip multicast source 203.0.113.0/24 group-range 239.0.0.1 to 239.255.255.255 rp 192.0.2.0/24 rp-type ASM
#   match route-type level-1 level-2
#   match tag 2
#   description rmap2-40-deny
# route-map rmap3 permit 10
#   description *** first stanza ***
#   set ip next-hop verify-availability 3.3.3.3 track 1
#   set ip next-hop verify-availability 4.4.4.4 track 3
# route-map rmap3 permit 20
#   description *** second stanza ***
#   set ip next-hop 6.6.6.6 2.2.2.2 load-share  drop-on-fail
# route-map rmap3 permit 30
#   description *** third stanza ***
#   set ip next-hop peer-address
# route-map rmap3 permit 40
#   description *** fourth stanza ***
#   set ip next-hop unchanged
#   set ip next-hop redist-unchanged
#
# Using replaced
# (for the listed route-map(s), sequences that are in running-config but not in the task are negated)

# Before state:
# ------------
# nxos-9k-rdo# show running-config | section "^route-map"
# route-map rmap1 permit 10
#   match as-number 65564
#   match as-path Allow40
#   match ip address acl_1
#   description rmap1-10-permit
# route-map rmap1 deny 20
#   match community BGPCommunity1 BGPCommunity2
#   match ip address prefix-list AllowPrefix1 AllowPrefix2
#   description rmap1-20-deny
#   set dampening 30 1500 10000 120
# route-map rmap2 permit 20
#   match interface Ethernet1/1
#   match ipv6 address prefix-list AllowIPv6Prefix
#   set as-path prepend 65563 65568 65569
#   description rmap2-20-permit
#   continue 40
#   set comm-list BGPCommunity delete
# route-map rmap2 deny 40
#   match ip multicast source 203.0.113.0/24 group-range 239.0.0.1 to 239.255.255.255 rp 192.0.2.0/24 rp-type ASM
#   match route-type level-1 level-2
#   match tag 2
#   description rmap2-40-deny
# route-map rmap3 permit 10
#   description *** first stanza ***
#   set ip next-hop verify-availability 3.3.3.3 track 1
#   set ip next-hop verify-availability 4.4.4.4 track 3
# route-map rmap3 permit 20
#   description *** second stanza ***
#   set ip next-hop 6.6.6.6 2.2.2.2 load-share  drop-on-fail
# route-map rmap3 permit 30
#   description *** third stanza ***
#   set ip next-hop peer-address
# route-map rmap3 permit 40
#   description *** fourth stanza ***
#   set ip next-hop unchanged
#   set ip next-hop redist-unchanged
#
- name: Replace route-maps configurations of listed route-maps with provided configurations
  cisco.nxos.nxos_route_maps:
    config:
      - route_map: rmap1
        entries:
          - sequence: 20
            action: deny
            description: rmap1-20-deny
            match:
              community:
                community_list:
                  - BGPCommunity4
                  - BGPCommunity5
              ip:
                address:
                  prefix_lists:
                    - AllowPrefix1
            set:
              community:
                local_as: true

      - route_map: rmap3
        entries:
          - sequence: 10
            description: "*** first stanza ***"
            action: permit
            set:
              ip:
                next_hop:
                  verify_availability:
                    - address: 3.3.3.3
                      track: 1
          - sequence: 20
            description: "*** second stanza ***"
            action: permit
            set:
              ip:
                next_hop:
                  peer_address: true
          - sequence: 30
            description: "*** third stanza ***"
            action: permit
            set:
              ip:
                next_hop:
                  address: 6.6.6.6 2.2.2.2
                  load_share: true
                  drop_on_fail: true
    state: replaced

# Task output
# -------------
#  before:
#   - route_map: rmap1
#     entries:
#     - action: permit
#       description: rmap1-10-permit
#       match:
#         as_number:
#           asn:
#           - '65564'
#         as_path:
#           - Allow40
#         ip:
#           address:
#             access_list: acl_1
#       sequence: 10
#
#     - action: deny
#       description: rmap1-20-deny
#       match:
#         community:
#           community_list:
#           - BGPCommunity1
#           - BGPCommunity2
#         ip:
#           address:
#             prefix_lists:
#             - AllowPrefix1
#             - AllowPrefix2
#       sequence: 20
#       set:
#         dampening:
#           half_life: 30
#           max_suppress_time: 120
#           start_reuse_route: 1500
#           start_suppress_route: 10000
#
#   - route_map: rmap2
#     entries:
#     - action: permit
#       continue_sequence: 40
#       description: rmap2-20-permit
#       match:
#         interfaces:
#         - Ethernet1/1
#         ipv6:
#           address:
#             prefix_lists:
#             - AllowIPv6Prefix
#         sequence: 20
#         set:
#           as_path:
#             prepend:
#               as_number:
#               - '65563'
#               - '65568'
#               - '65569'
#           comm_list: BGPCommunity
#
#     - action: deny
#       description: rmap2-40-deny
#       match:
#         ip:
#           multicast:
#             group_range:
#               first: 239.0.0.1
#               last: 239.255.255.255
#             rp:
#               prefix: 192.0.2.0/24
#               rp_type: ASM
#             source: 203.0.113.0/24
#         route_types:
#         - level-1
#         - level-2
#         tags:
#         - 2
#       sequence: 40
#
#   - route_map: rmap3
#     entries:
#     - sequence: 10
#       description: "*** first stanza ***"
#       action: permit
#       set:
#         ip:
#           next_hop:
#             verify_availability:
#             - address: 3.3.3.3
#               track: 1
#             - address: 4.4.4.4
#               track: 3
#
#     - sequence: 20
#       description: "*** second stanza ***"
#       action: permit
#       set:
#         ip:
#           next_hop:
#             address: 6.6.6.6 2.2.2.2
#             load_share: true
#             drop_on_fail: true
#
#     - sequence: 30
#       description: "*** third stanza ***"
#       action: permit
#       set:
#         ip:
#           next_hop:
#             peer_address: true
#
#     - sequence: 40
#       description: "*** fourth stanza ***"
#       action: permit
#       set:
#         ip:
#           next_hop:
#             unchanged: true
#             redist_unchanged: true
#
#  commands:
#    - no route-map rmap1 permit 10
#    - route-map rmap1 deny 20
#    - no match community BGPCommunity1 BGPCommunity2
#    - match community BGPCommunity4 BGPCommunity5
#    - no match ip address prefix-list AllowPrefix1 AllowPrefix2
#    - match ip address prefix-list AllowPrefix1
#    - no set dampening 30 1500 10000 120
#    - set community local-AS
#    - route-map rmap3 permit 10
#    - no set ip next-hop verify-availability 4.4.4.4 track 3
#    - route-map rmap3 permit 20
#    - no set ip next-hop 6.6.6.6 2.2.2.2 load-share drop-on-fail
#    - set ip next-hop peer-address
#    - route-map rmap3 permit 30
#    - no set ip next-hop peer-address
#    - set ip next-hop 6.6.6.6 2.2.2.2 load-share drop-on-fail
#    - no route-map rmap3 permit 40
#
#  after:
#    - route_map: rmap1
#      entries:
#        - sequence: 20
#          action: deny
#          description: rmap1-20-deny
#          match:
#            community:
#              community_list:
#                - BGPCommunity4
#                - BGPCommunity5
#            ip:
#              address:
#                prefix_lists:
#                  - AllowPrefix1
#          set:
#            community:
#              local_as: true
#
#    - route_map: rmap2
#      entries:
#        - action: permit
#          continue_sequence: 40
#          description: rmap2-20-permit
#          match:
#            interfaces:
#            - Ethernet1/1
#            ipv6:
#              address:
#                prefix_lists:
#                - AllowIPv6Prefix
#          sequence: 20
#          set:
#            as_path:
#              prepend:
#                as_number:
#                - '65563'
#                - '65568'
#                - '65569'
#            comm_list: BGPCommunity
#
#        - action: deny
#          description: rmap2-40-deny
#          match:
#            ip:
#              multicast:
#                group_range:
#                  first: 239.0.0.1
#                  last: 239.255.255.255
#                rp:
#                  prefix: 192.0.2.0/24
#                  rp_type: ASM
#                source: 203.0.113.0/24
#            route_types:
#            - level-1
#            - level-2
#            tags:
#            - 2
#          sequence: 40
#
#    - route_map: rmap3
#      entries:
#      - sequence: 10
#        description: "*** first stanza ***"
#        action: permit
#        set:
#          ip:
#            next_hop:
#              verify_availability:
#              - address: 3.3.3.3
#                track: 1
#      - sequence: 20
#        description: "*** second stanza ***"
#        action: permit
#        set:
#          ip:
#            next_hop:
#              peer_address: true
#      - sequence: 30
#        description: "*** third stanza ***"
#        action: permit
#        set:
#          ip:
#            next_hop:
#              address: 6.6.6.6 2.2.2.2
#              load_share: true
#              drop_on_fail: true

# After state:
# ------------
# nxos-9k-rdo# show running-config | section "^route-map"
# route-map rmap1 deny 20
#   description rmap1-20-deny
#   match community BGPCommunity4 BGPCommunity5
#   match ip address prefix-list AllowPrefix1
#   set community local-AS
# route-map rmap2 permit 20
#   match interface Ethernet1/1
#   match ipv6 address prefix-list AllowIPv6Prefix
#   set as-path prepend 65563 65568 65569
#   description rmap2-20-permit
#   continue 40
#   set comm-list BGPCommunity delete
# route-map rmap2 deny 40
#   match ip multicast source 203.0.113.0/24 group-range 239.0.0.1 to 239.255.255.255 rp 192.0.2.0/24 rp-type ASM
#   match route-type level-1 level-2
#   match tag 2
#   description rmap2-40-deny
# route-map rmap3 permit 10
#   description *** first stanza ***
#   set ip next-hop verify-availability 3.3.3.3 track 1
# route-map rmap3 permit 20
#   description *** second stanza ***
#   set ip next-hop peer-address
# route-map rmap3 permit 30
#   description *** third stanza ***
#   set ip next-hop 6.6.6.6 2.2.2.2 load-share  drop-on-fail

# Using overridden

# Before state:
# ------------
# nxos-9k-rdo# show running-config | section "^route-map"
# route-map rmap1 permit 10
#   match as-number 65564
#   match as-path Allow40
#   match ip address acl_1
#   description rmap1-10-permit
# route-map rmap1 deny 20
#   match community BGPCommunity1 BGPCommunity2
#   match ip address prefix-list AllowPrefix1 AllowPrefix2
#   description rmap1-20-deny
#   set dampening 30 1500 10000 120
# route-map rmap2 permit 20
#   match interface Ethernet1/1
#   match ipv6 address prefix-list AllowIPv6Prefix
#   set as-path prepend 65563 65568 65569
#   description rmap2-20-permit
#   continue 40
#   set comm-list BGPCommunity delete
# route-map rmap2 deny 40
#   match ip multicast source 203.0.113.0/24 group-range 239.0.0.1 to 239.255.255.255 rp 192.0.2.0/24 rp-type ASM
#   match route-type level-1 level-2
#   match tag 2
#   description rmap2-40-deny

- name: Override all route-maps configuration with provided configuration
  cisco.nxos.nxos_route_maps:
    config:
      - route_map: rmap1
        entries:
          - sequence: 20
            action: deny
            description: rmap1-20-deny
            match:
              community:
                community_list:
                  - BGPCommunity4
                  - BGPCommunity5
              ip:
                address:
                  prefix_lists:
                    - AllowPrefix1
            set:
              community:
                local_as: true
    state: overridden

# Task output
# -------------
#  before:
#   - route_map: rmap1
#     entries:
#     - action: permit
#       description: rmap1-10-permit
#       match:
#         as_number:
#           asn:
#           - '65564'
#         as_path:
#           - Allow40
#         ip:
#           address:
#             access_list: acl_1
#       sequence: 10
#
#     - action: deny
#       description: rmap1-20-deny
#       match:
#         community:
#           community_list:
#           - BGPCommunity1
#           - BGPCommunity2
#         ip:
#           address:
#             prefix_lists:
#             - AllowPrefix1
#             - AllowPrefix2
#       sequence: 20
#       set:
#         dampening:
#           half_life: 30
#           max_suppress_time: 120
#           start_reuse_route: 1500
#           start_suppress_route: 10000
#
#   - route_map: rmap2
#     entries:
#     - action: permit
#       continue_sequence: 40
#       description: rmap2-20-permit
#       match:
#         interfaces:
#         - Ethernet1/1
#         ipv6:
#           address:
#             prefix_lists:
#             - AllowIPv6Prefix
#         sequence: 20
#         set:
#           as_path:
#             prepend:
#               as_number:
#               - '65563'
#               - '65568'
#               - '65569'
#           comm_list: BGPCommunity
#
#     - action: deny
#       description: rmap2-40-deny
#       match:
#         ip:
#           multicast:
#             group_range:
#               first: 239.0.0.1
#               last: 239.255.255.255
#             rp:
#               prefix: 192.0.2.0/24
#               rp_type: ASM
#             source: 203.0.113.0/24
#         route_types:
#         - level-1
#         - level-2
#         tags:
#         - 2
#       sequence: 40
#
#  commands:
#    - no route-map rmap1 permit 10
#    - route-map rmap1 deny 20
#    - no match community BGPCommunity1 BGPCommunity2
#    - match community BGPCommunity4 BGPCommunity5
#    - no match ip address prefix-list AllowPrefix1 AllowPrefix2
#    - match ip address prefix-list AllowPrefix1
#    - no set dampening 30 1500 10000 120
#    - set community local-AS
#    - no route-map rmap2 permit 20
#    - no route-map rmap2 deny 40
#
#  after:
#  - route_map: rmap1
#    entries:
#    - sequence: 20
#      action: deny
#      description: rmap1-20-deny
#      match:
#        community:
#          community_list:
#          - BGPCommunity4
#          - BGPCommunity5
#        ip:
#          address:
#            prefix_lists:
#            - AllowPrefix1
#      set:
#        community:
#          local_as: true
#
# After state:
# ------------
# nxos-9k-rdo# sh running-config | section "^route-map"
# route-map rmap1 deny 20
#   description rmap1-20-deny
#   match community BGPCommunity4 BGPCommunity5
#   match ip address prefix-list AllowPrefix1
#   set community local-AS

# Using deleted to delete a single route-map

# Before state:
# ------------
# nxos-9k-rdo# show running-config | section "^route-map"
# route-map rmap1 permit 10
#   match as-number 65564
#   match as-path Allow40
#   match ip address acl_1
#   description rmap1-10-permit
# route-map rmap1 deny 20
#   match community BGPCommunity1 BGPCommunity2
#   match ip address prefix-list AllowPrefix1 AllowPrefix2
#   description rmap1-20-deny
#   set dampening 30 1500 10000 120
# route-map rmap2 permit 20
#   match interface Ethernet1/1
#   match ipv6 address prefix-list AllowIPv6Prefix
#   set as-path prepend 65563 65568 65569
#   description rmap2-20-permit
#   continue 40
#   set comm-list BGPCommunity delete
# route-map rmap2 deny 40
#   match ip multicast source 203.0.113.0/24 group-range 239.0.0.1 to 239.255.255.255 rp 192.0.2.0/24 rp-type ASM
#   match route-type level-1 level-2
#   match tag 2
#   description rmap2-40-deny

- name: Delete single route-map
  cisco.nxos.nxos_route_maps:
    config:
      - route_map: rmap1
    state: deleted

# Task output
# -------------
#  before:
#   - route_map: rmap1
#     entries:
#     - action: permit
#       description: rmap1-10-permit
#       match:
#         as_number:
#           asn:
#           - '65564'
#         as_path:
#           - Allow40
#         ip:
#           address:
#             access_list: acl_1
#       sequence: 10
#
#     - action: deny
#       description: rmap1-20-deny
#       match:
#         community:
#           community_list:
#           - BGPCommunity1
#           - BGPCommunity2
#         ip:
#           address:
#             prefix_lists:
#             - AllowPrefix1
#             - AllowPrefix2
#       sequence: 20
#       set:
#         dampening:
#           half_life: 30
#           max_suppress_time: 120
#           start_reuse_route: 1500
#           start_suppress_route: 10000
#
#   - route_map: rmap2
#     entries:
#     - action: permit
#       continue_sequence: 40
#       description: rmap2-20-permit
#       match:
#         interfaces:
#         - Ethernet1/1
#         ipv6:
#           address:
#             prefix_lists:
#             - AllowIPv6Prefix
#         sequence: 20
#         set:
#           as_path:
#             prepend:
#               as_number:
#               - '65563'
#               - '65568'
#               - '65569'
#           comm_list: BGPCommunity
#
#     - action: deny
#       description: rmap2-40-deny
#       match:
#         ip:
#           multicast:
#             group_range:
#               first: 239.0.0.1
#               last: 239.255.255.255
#             rp:
#               prefix: 192.0.2.0/24
#               rp_type: ASM
#             source: 203.0.113.0/24
#         route_types:
#         - level-1
#         - level-2
#         tags:
#         - 2
#       sequence: 40
#
#  commands:
#    - no route-map rmap1 permit 10
#    - no route-map rmap1 deny 20
#
#  after:
#   - route_map: rmap2
#     entries:
#     - action: permit
#       continue_sequence: 40
#       description: rmap2-20-permit
#       match:
#         interfaces:
#         - Ethernet1/1
#         ipv6:
#           address:
#             prefix_lists:
#             - AllowIPv6Prefix
#         sequence: 20
#         set:
#           as_path:
#             prepend:
#               as_number:
#               - '65563'
#               - '65568'
#               - '65569'
#           comm_list: BGPCommunity
#
#     - action: deny
#       description: rmap2-40-deny
#       match:
#         ip:
#           multicast:
#             group_range:
#               first: 239.0.0.1
#               last: 239.255.255.255
#             rp:
#               prefix: 192.0.2.0/24
#               rp_type: ASM
#             source: 203.0.113.0/24
#         route_types:
#         - level-1
#         - level-2
#         tags:
#         - 2
#       sequence: 40
#
# After state:
# ------------
# nxos-9k-rdo# sh running-config | section "^route-map"
# route-map rmap2 permit 20
#   match interface Ethernet1/1
#   match ipv6 address prefix-list AllowIPv6Prefix
#   set as-path prepend 65563 65568 65569
#   description rmap2-20-permit
#   continue 40
#   set comm-list BGPCommunity delete
# route-map rmap2 deny 40
#   match ip multicast source 203.0.113.0/24 group-range 239.0.0.1 to 239.255.255.255 rp 192.0.2.0/24 rp-type ASM
#   match route-type level-1 level-2
#   match tag 2
#   description rmap2-40-deny

# Using deleted to delete all route-maps from the device running-config

# Before state:
# ------------
# nxos-9k-rdo# show running-config | section "^route-map"
# route-map rmap1 permit 10
#   match as-number 65564
#   match as-path Allow40
#   match ip address acl_1
#   description rmap1-10-permit
# route-map rmap1 deny 20
#   match community BGPCommunity1 BGPCommunity2
#   match ip address prefix-list AllowPrefix1 AllowPrefix2
#   description rmap1-20-deny
#   set dampening 30 1500 10000 120
# route-map rmap2 permit 20
#   match interface Ethernet1/1
#   match ipv6 address prefix-list AllowIPv6Prefix
#   set as-path prepend 65563 65568 65569
#   description rmap2-20-permit
#   continue 40
#   set comm-list BGPCommunity delete
# route-map rmap2 deny 40
#   match ip multicast source 203.0.113.0/24 group-range 239.0.0.1 to 239.255.255.255 rp 192.0.2.0/24 rp-type ASM
#   match route-type level-1 level-2
#   match tag 2
#   description rmap2-40-deny

- name: Delete all route-maps
  cisco.nxos.nxos_route_maps:
    state: deleted

# Task output
# -------------
#  before:
#   - route_map: rmap1
#     entries:
#     - action: permit
#       description: rmap1-10-permit
#       match:
#         as_number:
#           asn:
#           - '65564'
#         as_path:
#           - Allow40
#         ip:
#           address:
#             access_list: acl_1
#       sequence: 10
#
#     - action: deny
#       description: rmap1-20-deny
#       match:
#         community:
#           community_list:
#           - BGPCommunity1
#           - BGPCommunity2
#         ip:
#           address:
#             prefix_lists:
#             - AllowPrefix1
#             - AllowPrefix2
#       sequence: 20
#       set:
#         dampening:
#           half_life: 30
#           max_suppress_time: 120
#           start_reuse_route: 1500
#           start_suppress_route: 10000
#
#   - route_map: rmap2
#     entries:
#     - action: permit
#       continue_sequence: 40
#       description: rmap2-20-permit
#       match:
#         interfaces:
#         - Ethernet1/1
#         ipv6:
#           address:
#             prefix_lists:
#             - AllowIPv6Prefix
#         sequence: 20
#         set:
#           as_path:
#             prepend:
#               as_number:
#               - '65563'
#               - '65568'
#               - '65569'
#           comm_list: BGPCommunity
#
#     - action: deny
#       description: rmap2-40-deny
#       match:
#         ip:
#           multicast:
#             group_range:
#               first: 239.0.0.1
#               last: 239.255.255.255
#             rp:
#               prefix: 192.0.2.0/24
#               rp_type: ASM
#             source: 203.0.113.0/24
#         route_types:
#         - level-1
#         - level-2
#         tags:
#         - 2
#       sequence: 40
#
#  commands:
#    - no route-map rmap1 permit 10
#    - no route-map rmap1 deny 20
#    - no route-map rmap2 permit 20
#    - no route-map rmap2 deny 40
#
#  after: []
#
# After state:
# ------------
# nxos-9k-rdo# sh running-config | section "^route-map"

- name: Render platform specific configuration lines with state rendered (without connecting to the device)
  cisco.nxos.nxos_route_maps:
    config:
      - route_map: rmap1
        entries:
          - sequence: 10
            action: permit
            description: rmap1-10-permit
            match:
              ip:
                address:
                  access_list: acl_1
              as_path: Allow40
              as_number:
                asn: 65564

          - sequence: 20
            action: deny
            description: rmap1-20-deny
            match:
              community:
                community_list:
                  - BGPCommunity1
                  - BGPCommunity2
              ip:
                address:
                  prefix_lists:
                    - AllowPrefix1
                    - AllowPrefix2
            set:
              dampening:
                half_life: 30
                start_reuse_route: 1500
                start_suppress_route: 10000
                max_suppress_time: 120

      - route_map: rmap2
        entries:
          - sequence: 20
            action: permit
            description: rmap2-20-permit
            continue_sequence: 40
            match:
              ipv6:
                address:
                  prefix_lists: AllowIPv6Prefix
              interfaces: "{{ nxos_int1 }}"
            set:
              as_path:
                prepend:
                  as_number:
                    - 65563
                    - 65568
                    - 65569
              comm_list: BGPCommunity

          - sequence: 40
            action: deny
            description: rmap2-40-deny
            match:
              route_types:
                - level-1
                - level-2
              tags: 2
              ip:
                multicast:
                  rp:
                    prefix: 192.0.2.0/24
                    rp_type: ASM
                  source: 203.0.113.0/24
                  group_range:
                    first: 239.0.0.1
                    last: 239.255.255.255
    state: rendered

# Task Output (redacted)
# -----------------------
#  rendered:
#    - "route-map rmap1 permit 10"
#    - "match as-number 65564"
#    - "match as-path Allow40"
#    - "match ip address acl_1"
#    - "description rmap1-10-permit"
#    - "route-map rmap1 deny 20"
#    - "match community BGPCommunity1 BGPCommunity2"
#    - "match ip address prefix-list AllowPrefix1 AllowPrefix2"
#    - "description rmap1-20-deny"
#    - "set dampening 30 1500 10000 120"
#    - "route-map rmap2 permit 20"
#    - "match interface Ethernet1/1"
#    - "match ipv6 address prefix-list AllowIPv6Prefix"
#    - "set as-path prepend 65563 65568 65569"
#    - "description rmap2-20-permit"
#    - "continue 40"
#    - "set comm-list BGPCommunity delete"
#    - "route-map rmap2 deny 40"
#    - "match ip multicast source 203.0.113.0/24 group-range 239.0.0.1 to 239.255.255.255 rp 192.0.2.0/24 rp-type ASM"
#    - "match route-type level-1 level-2"
#    - "match tag 2"
#    - "description rmap2-40-deny"

# Using parsed

# parsed.cfg
# ------------
# route-map rmap1 permit 10
#   match as-number 65564
#   match as-path Allow40
#   match ip address acl_1
#   description rmap1-10-permit
# route-map rmap1 deny 20
#   match community BGPCommunity1 BGPCommunity2
#   match ip address prefix-list AllowPrefix1 AllowPrefix2
#   description rmap1-20-deny
#   set dampening 30 1500 10000 120
# route-map rmap2 permit 20
#   match interface Ethernet1/1
#   match ipv6 address prefix-list AllowIPv6Prefix
#   set as-path prepend 65563 65568 65569
#   description rmap2-20-permit
#   continue 40
#   set comm-list BGPCommunity delete
# route-map rmap2 deny 40
#   match ip multicast source 203.0.113.0/24 group-range 239.0.0.1 to 239.255.255.255 rp 192.0.2.0/24 rp-type ASM
#   match route-type level-1 level-2
#   match tag 2
#   description rmap2-40-deny

- name: Parse externally provided route-maps configuration
  cisco.nxos.nxos_route_maps:
    running_config: "{{ lookup('file', './fixtures/parsed.cfg') }}"
    state: parsed

# Task output (redacted)
# -----------------------
#  parsed:
#   - route_map: rmap1
#     entries:
#     - action: permit
#       description: rmap1-10-permit
#       match:
#         as_number:
#           asn:
#           - '65564'
#         as_path:
#           - Allow40
#         ip:
#           address:
#             access_list: acl_1
#       sequence: 10
#
#     - action: deny
#       description: rmap1-20-deny
#       match:
#         community:
#           community_list:
#           - BGPCommunity1
#           - BGPCommunity2
#         ip:
#           address:
#             prefix_lists:
#             - AllowPrefix1
#             - AllowPrefix2
#       sequence: 20
#       set:
#         dampening:
#           half_life: 30
#           max_suppress_time: 120
#           start_reuse_route: 1500
#           start_suppress_route: 10000
#
#   - route_map: rmap2
#     entries:
#     - action: permit
#       continue_sequence: 40
#       description: rmap2-20-permit
#       match:
#         interfaces:
#         - Ethernet1/1
#         ipv6:
#           address:
#             prefix_lists:
#             - AllowIPv6Prefix
#         sequence: 20
#         set:
#           as_path:
#             prepend:
#               as_number:
#               - '65563'
#               - '65568'
#               - '65569'
#           comm_list: BGPCommunity
#
#     - action: deny
#       description: rmap2-40-deny
#       match:
#         ip:
#           multicast:
#             group_range:
#               first: 239.0.0.1
#               last: 239.255.255.255
#             rp:
#               prefix: 192.0.2.0/24
#               rp_type: ASM
#             source: 203.0.113.0/24
#         route_types:
#         - level-1
#         - level-2
#         tags:
#         - 2
#       sequence: 40

# Using gathered

# Existing route-map config
# ---------------------------
# nxos-9k-rdo# show running-config | section "^route-map"
# route-map rmap1 permit 10
#   match as-number 65564
#   match as-path Allow40
#   match ip address acl_1
#   description rmap1-10-permit
# route-map rmap2 permit 20
#   match interface Ethernet1/1
#   match ipv6 address prefix-list AllowIPv6Prefix
#   set as-path prepend 65563 65568 65569
#   description rmap2-20-permit
#   continue 40
#   set comm-list BGPCommunity delete

- name: Gather route-maps facts using gathered
  cisco.nxos.nxos_route_maps:
    state: gathered

#  gathered:
#   - route_map: rmap1
#     entries:
#     - action: permit
#       description: rmap1-10-permit
#       match:
#         as_number:
#           asn:
#           - '65564'
#         as_path:
#           - Allow40
#         ip:
#           address:
#             access_list: acl_1
#       sequence: 10
#
#   - route_map: rmap2
#     entries:
#     - action: permit
#       continue_sequence: 40
#       description: rmap2-20-permit
#       match:
#         interfaces:
#         - Ethernet1/1
#         ipv6:
#           address:
#             prefix_lists:
#             - AllowIPv6Prefix
#         sequence: 20
#         set:
#           as_path:
#             prepend:
#               as_number:
#               - '65563'
#               - '65568'
#               - '65569'
#           comm_list: BGPCommunity
#
"""

RETURN = """
before:
  description: The configuration prior to the model invocation.
  returned: always
  type: dict
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
after:
  description: The resulting configuration model invocation.
  returned: when changed
  type: dict
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample:
    - "route-map rmap1 permit 10"
    - "match as-number 65564"
    - "match as-path Allow40"
    - "match ip address acl_1"
    - "description rmap1-10-permit"
    - "route-map rmap1 deny 20"
    - "match community BGPCommunity1 BGPCommunity2"
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.route_maps.route_maps import (
    Route_mapsArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.config.route_maps.route_maps import (
    Route_maps,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=Route_mapsArgs.argument_spec,
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

    result = Route_maps(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
