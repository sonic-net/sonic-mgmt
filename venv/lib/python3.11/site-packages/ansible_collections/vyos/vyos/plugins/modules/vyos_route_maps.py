#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for vyos_route_maps
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: vyos_route_maps
version_added: "1.0.0"
short_description: Route Map resource module
description:
- This module manages route map configurations on devices running VYOS.
author: Ashwini Mhatre (@amhatre)
notes:
- Tested against VyOS 1.3.8, 1.4.2, the upcoming 1.5, and the rolling release of spring 2025
- This module works with connection C(network_cli).
options:
    config:
      description: A list of route-map configuration.
      type: list
      elements: dict
      suboptions:
        route_map:
          description: Route map name.
          type: str
        entries:
          description: Route Map rules.
          aliases: ["rules"]
          type: list
          elements: dict
          suboptions:
            sequence:
              type: int
              description: Route map rule number <1-65535>.
            call:
              description: Route map name
              type: str
            description:
              description: Description for the rule.
              type: str
            action:
              description: Action for matching routes
              type: str
              choices: ["deny", "permit"]
            continue_sequence:
              description: Continue on a different entry within the route-map.
              type: int
            set:
              description: Route parameters.
              type: dict
              suboptions:
                aggregator:
                  type: dict
                  description: Border Gateway Protocol (BGP) aggregator attribute.
                  suboptions:
                    ip:
                      type: str
                      description: IP address.
                    as:
                      type: str
                      description: AS number of an aggregation.
                as_path_exclude:
                  type: str
                  description: BGP AS path exclude string ex "456 64500 45001"
                as_path_prepend:
                  type: str
                  description: Prepend string for a Border Gateway Protocol (BGP) AS-path attribute.
                atomic_aggregate:
                  type: bool
                  description:  Border Gateway Protocol (BGP) atomic aggregate attribute.
                bgp_extcommunity_rt:
                  type: str
                  description: ExtCommunity in format AS:value
                comm_list:
                  type: dict
                  description: Border Gateway Protocol (BGP) communities matching a community-list.
                  suboptions:
                    comm_list:
                      type: str
                      description: BGP communities with a community-list.
                    delete:
                      type: bool
                      description: Delete BGP communities matching the community-list.
                community:
                  type: dict
                  description: Border Gateway Protocol (BGP) community attribute.
                  suboptions:
                    value:
                      type: str
                      description: Community in 4 octet AS:value format or it can be from local-AS, no-advertise,no-expert,internet,additive,none.
                extcommunity_rt:
                  type: str
                  description: Set route target value.ASN:nn_or_IP_address:nn VPN extended community.
                extcommunity_soo:
                  type: str
                  description: Set Site of Origin value. ASN:nn_or_IP_address:nn VPN extended community
                extcommunity_bandwidth:
                  type: str
                  description: Set Bandwidth of Origin value. 1-25600|cumulative|num-multipaths VPN extended community
                extcommunity_bandwidth_non_transitive:
                  type: bool
                  description: Set the bandwidth extended community encoded as non-transitive True/False VPN extended community
                ip_next_hop:
                  type: str
                  description: IP address.
                ipv6_next_hop:
                  type: dict
                  description: Nexthop IPv6 address.
                  suboptions:
                    ip_type:
                      description: Global or Local
                      type: str
                      choices: ["global", "local"]
                    value:
                      description: ipv6 address
                      type: str
                large_community:
                  type: str
                  description: Set BGP large community value.
                local_preference:
                  type: str
                  description: Border Gateway Protocol (BGP) local preference attribute.Example <0-4294967295>.
                metric:
                  type: str
                  description: Destination routing protocol metric. Example <0-4294967295>.
                metric_type:
                  type: str
                  choices: ['type-1', 'type-2']
                  description: Open Shortest Path First (OSPF) external metric-type.
                origin:
                  description: Set bgp origin.
                  type: str
                  choices: [ "egp", "igp", "incomplete" ]
                originator_id:
                  type: str
                  description: Border Gateway Protocol (BGP) originator ID attribute. Originator IP address.
                src:
                  type: str
                  description: Source address for route. Example <x.x.x.x> IP address.
                tag:
                  type: str
                  description: Tag value for routing protocol. Example <1-65535>
                weight:
                  type: str
                  description: Border Gateway Protocol (BGP) weight attribute. Example <0-4294967295>
                table:
                  type: str
                  description: Set prefixes to table. Example <1-200>
            match:
              description: Route parameters to match.
              type: dict
              suboptions:
                as_path:
                  description: Set as-path.
                  type: str
                community:
                  description: BGP community attribute.
                  type: dict
                  suboptions:
                    community_list:
                      description: BGP community-list to match
                      type: str
                    exact_match:
                      description:  BGP community-list to match
                      type: bool
                extcommunity:
                  description: Extended community name.
                  type: str
                interface:
                  description: First hop interface of a route to match.
                  type: str
                ip:
                  description: IP prefix parameters to match.
                  type: dict
                  suboptions:
                    address:
                      description: IP address of route to match.
                      type: dict
                      suboptions:
                        list_type: &list_type
                          description: type of list
                          type: str
                          choices: ['access-list', 'prefix-list']
                        value: &value
                          type: str
                          description: value of access-list and prefix list
                    next_hop:
                      description: next hop prefix list.
                      type: dict
                      suboptions:
                        list_type: *list_type
                        value: *value
                    route_source:
                      description: IP route-source to match
                      type: dict
                      suboptions:
                        list_type: *list_type
                        value: *value
                ipv6:
                  description: IPv6 prefix parameters to match.
                  type: dict
                  suboptions:
                    address:
                      description: IPv6 address of route to match.
                      type: dict
                      suboptions:
                        list_type: *list_type
                        value: *value
                    next_hop:
                      description: next-hop ipv6 address IPv6 <h:h:h:h:h:h:h:h>.
                      type: str
                large_community_large_community_list:
                  type: str
                  description: BGP large-community-list to match.
                metric:
                  description: Route metric <1-65535>.
                  type: int
                origin:
                  description: bgp origin.
                  type: str
                  choices: [ "ebgp", "ibgp", "incomplete" ]
                peer:
                  type: str
                  description: Peer IP address <x.x.x.x>.
                rpki:
                  type: str
                  description: RPKI validation value.
                  choices: [ "notfound", "invalid", "valid" ]
                protocol:
                  type: str
                  description: Source protocol to match.
                  choices: [ "babel","bgp","connected","isis","kernel","ospf","ospfv3","rip","ripng","static","table","vnc" ]
            on_match:
              type: dict
              description: Exit policy on matches.
              suboptions:
                next:
                  type: bool
                  description: Next sequence number to goto on match.
                goto:
                  type: int
                  description: Rule number to goto on match <1-65535>.
    running_config:
      description:
      - This option is used only with state I(parsed).
      - The value of this option should be the output received from the VYOS device by
        executing the command B(show configuration commands | grep route-map).
      - The state I(parsed) reads the configuration from C(show configuration commands | grep route-map) option and
        transforms it into Ansible structured data as per the resource module's argspec
        and the value is then returned in the I(parsed) key within the result.
      type: str
    state:
      description:
      - The state the configuration should be left in.
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
# Using merged
# Before state

# vyos@vyos:~$ show configuration commands |  match "set policy route-map"
# vyos@vyos:~$
- name: Merge the provided configuration with the existing running configuration
  register: result
  vyos.vyos.vyos_route_maps: &id001
    config:
      - route_map: test1
        entries:
          - sequence: 1
            description: "test"
            action: permit
            continue: 2
            on_match:
              next: true
      - route_map: test3
        entries:
          - sequence: 1
            action: permit
            match:
              rpki: invalid
              metric: 1
              peer: 192.0.2.32
            set:
              local_preference: 4
              metric: 5
              metric_type: "type-1"
              origin: egp
              originator_id: 192.0.2.34
              tag: 5
              weight: 4
    state: merged
# After State
# vyos@vyos:~$ show configuration commands |  match "set policy route-maps"
#   set policy route-map test1 rule 1 description test
#   set policy route-map test1 rule 1 action permit
#   set policy route-map test1 rule 1 continue 2
#   set policy route-map test1 rule 1 on-match next
#   set policy route-map test3 rule 1 action permit
#   set policy route-map test3 rule 1 set local-preference 4
#   set policy route-map test3 rule 1 set metric 5
#   set policy route-map test3 rule 1 set metric-type type-1
#   set policy route-map test3 rule 1 set origin egp
#   set policy route-map test3 rule 1 set originator-id 192.0.2.34
#   set policy route-map test3 rule 1 set tag 5
#   set policy route-map test3 rule 1 set weight 4
#   set policy route-map test3 rule 1 match metric 1
#   set policy route-map test3 rule 1 match peer 192.0.2.32
#   set policy route-map test3 rule 1 match rpki invalid

# "after": [
#         {
#             "entries": [
#                 {
#                     "action": "permit",
#                     "continue_sequence": 2,
#                     "description": "test",
#                     "on_match": {
#                         "next": true
#                     },
#                     "sequence": 1
#                 }
#             ],
#             "route_map": "test1"
#         },
#         {
#             "entries": [
#                 {
#                     "action": "permit",
#                     "match": {
#                         "metric": 1,
#                         "peer": "192.0.2.32",
#                         "rpki": "invalid"
#                     },
#                     "sequence": 1,
#                     "set": {
#                         "local_preference": "4",
#                         "metric": "5",
#                         "metric_type": "type-1",
#                         "origin": "egp",
#                         "originator_id": "192.0.2.34",
#                         "tag": "5",
#                         "weight": "4"
#                     }
#                 }
#             ],
#             "route_map": "test3"
#         }
#     ],
#     "before": [],
#     "changed": true,
#     "commands": [
#         "set policy route-map test1 rule 1 description test",
#         "set policy route-map test1 rule 1 action permit",
#         "set policy route-map test1 rule 1 continue 2",
#         "set policy route-map test1 rule 1 on-match next",
#         "set policy route-map test3 rule 1 action permit",
#         "set policy route-map test3 rule 1 set local-preference 4",
#         "set policy route-map test3 rule 1 set metric 5",
#         "set policy route-map test3 rule 1 set metric-type type-1",
#         "set policy route-map test3 rule 1 set origin egp",
#         "set policy route-map test3 rule 1 set originator-id 192.0.2.34",
#         "set policy route-map test3 rule 1 set tag 5",
#         "set policy route-map test3 rule 1 set weight 4",
#         "set policy route-map test3 rule 1 match metric 1",
#         "set policy route-map test3 rule 1 match peer 192.0.2.32",
#         "set policy route-map test3 rule 1 match rpki invalid"
#     ],

# Using replaced:
# --------------

# Before state:
# vyos@vyos:~$ show configuration commands |  match "set route-map policy"
# set policy route-map test2 rule 1 action 'permit'
# set policy route-map test2 rule 1 description 'test'
# set policy route-map test2 rule 1 on-match next
# set policy route-map test2 rule 2 action 'permit'
# set policy route-map test2 rule 2 on-match goto '4'
# set policy route-map test3 rule 1 action 'permit'
# set policy route-map test3 rule 1 match metric '1'
# set policy route-map test3 rule 1 match peer '192.0.2.32'
# set policy route-map test3 rule 1 match rpki 'invalid'
# set policy route-map test3 rule 1 set community 'internet'
# set policy route-map test3 rule 1 set ip-next-hop '192.0.2.33'
# set policy route-map test3 rule 1 set local-preference '4'
# set policy route-map test3 rule 1 set metric '5'
# set policy route-map test3 rule 1 set metric-type 'type-1'
# set policy route-map test3 rule 1 set origin 'egp'
# set policy route-map test3 rule 1 set originator-id '192.0.2.34'
# set policy route-map test3 rule 1 set tag '5'
# set policy route-map test3 rule 1 set weight '4'
#
#     - name: Replace  the provided configuration with the existing running configuration
#       register: result
#       vyos.vyos.vyos_route_maps: &id001
#         config:
#           - route_map: test3
#             entries:
#               - sequence: 1
#                 action: permit
#                 match:
#                   rpki: invalid
#                   metric: 3
#                   peer: 192.0.2.35
#                 set:
#                   local_preference: 6
#                   metric: 4
#                   metric_type: "type-1"
#                   origin: egp
#                   originator_id: 192.0.2.34
#                   tag: 4
#                   weight: 4
#         state: replaced
# After state:

# vyos@vyos:~$ show configuration commands |  match "set policy route-map"
# set policy route-map test3 rule 1 set local-preference 6
# set policy route-map test3 rule 1 set metric 4
# set policy route-map test3 rule 1 set tag 4
# set policy route-map test3 rule 1 match metric 3
# set policy route-map test3 rule 1 match peer 192.0.2.35
# vyos@vyos:~$
#
#
# Module Execution:
#
# "after": [
#         {
#             "entries": [
#                 {
#                     "action": "permit",
#                     "description": "test",
#                     "on_match": {
#                         "next": true
#                     },
#                     "sequence": 1
#                 },
#                 {
#                     "action": "permit",
#                     "on_match": {
#                         "goto": 4
#                     },
#                     "sequence": 2
#                 }
#             ],
#             "route_map": "test2"
#         },
#         {
#             "entries": [
#                 {
#                     "action": "permit",
#                     "match": {
#                         "metric": 3,
#                         "peer": "192.0.2.35",
#                         "rpki": "invalid"
#                     },
#                     "sequence": 1,
#                     "set": {
#                         "local_preference": "6",
#                         "metric": "4",
#                         "metric_type": "type-1",
#                         "origin": "egp",
#                         "originator_id": "192.0.2.34",
#                         "tag": "4",
#                         "weight": "4"
#                     }
#                 }
#             ],
#             "route_map": "test3"
#         }
#     ],
#     "before": [
#         {
#             "entries": [
#                 {
#                     "action": "permit",
#                     "description": "test",
#                     "on_match": {
#                         "next": true
#                     },
#                     "sequence": 1
#                 },
#                 {
#                     "action": "permit",
#                     "on_match": {
#                         "goto": 4
#                     },
#                     "sequence": 2
#                 }
#             ],
#             "route_map": "test2"
#         },
#         {
#             "entries": [
#                 {
#                     "action": "permit",
#                     "match": {
#                         "metric": 1,
#                         "peer": "192.0.2.32",
#                         "rpki": "invalid"
#                     },
#                     "sequence": 1,
#                     "set": {
#                         "community": {
#                             "value": "internet"
#                         },
#                         "ip_next_hop": "192.0.2.33",
#                         "local_preference": "4",
#                         "metric": "5",
#                         "metric_type": "type-1",
#                         "origin": "egp",
#                         "originator_id": "192.0.2.34",
#                         "tag": "5",
#                         "weight": "4"
#                     }
#                 }
#             ],
#             "route_map": "test3"
#         }
#     ],
#     "changed": true,
#     "commands": [
#         "delete policy route-map test3 rule 1 set ip-next-hop 192.0.2.33",
#         "set policy route-map test3 rule 1 set local-preference 6",
#         "set policy route-map test3 rule 1 set metric 4",
#         "set policy route-map test3 rule 1 set tag 4",
#         "delete policy route-map test3 rule 1 set community internet",
#         "set policy route-map test3 rule 1 match metric 3",
#         "set policy route-map test3 rule 1 match peer 192.0.2.35"
#     ],
#
# Using deleted:
# -------------

# Before state:
# vyos@vyos:~$ show configuration commands |  match "set policy route-map"
# set policy route-map test3 rule 1 set local-preference 6
# set policy route-map test3 rule 1 set metric 4
# set policy route-map test3 rule 1 set tag 4
# set policy route-map test3 rule 1 match metric 3
# set policy route-map test3 rule 1 match peer 192.0.2.35
# vyos@vyos:~$
#
# - name: Delete the provided configuration
#   register: result
#   vyos.vyos.vyos_route_maps:
#     config:
#     state: deleted
# After state:

# vyos@vyos:~$ show configuration commands |  match "set policy route-map"
# vyos@vyos:~$
#
#
# Module Execution:
#
# "after": [],
#     "before": [
#         {
#             "entries": [
#                 {
#                     "action": "permit",
#                     "match": {
#                         "metric": 3,
#                         "peer": "192.0.2.35",
#                     },
#                     "sequence": 1,
#                     "set": {
#                         "local_preference": "6",
#                         "metric": "4",
#                         "tag": "4",
#                     }
#                 }
#             ],
#             "route_map": "test3"
#         }
#     ],
#     "changed": true,
#     "commands": [
#         "delete policy route-map test3"
#     ],
#
# using gathered:
# --------------
#
# Before state:
# vyos@vyos:~$ show configuration commands |  match "set policy route-maps"
#   set policy route-map test1 rule 1 description test
#   set policy route-map test1 rule 1 action permit
#   set policy route-map test1 rule 1 continue 2
#   set policy route-map test1 rule 1 on-match next
#   set policy route-map test3 rule 1 action permit
#   set policy route-map test3 rule 1 set local-preference 4
#   set policy route-map test3 rule 1 set metric 5
#   set policy route-map test3 rule 1 set metric-type type-1
#   set policy route-map test3 rule 1 set origin egp
#   set policy route-map test3 rule 1 set originator-id 192.0.2.34
#   set policy route-map test3 rule 1 set tag 5
#   set policy route-map test3 rule 1 set weight 4
#   set policy route-map test3 rule 1 match metric 1
#   set policy route-map test3 rule 1 match peer 192.0.2.32
#   set policy route-map test3 rule 1 match rpki invalid
#
# - name: gather configs
#     vyos.vyos.vyos_route_maps:
#       state: gathered

# "gathered": [
#         {
#             "entries": [
#                 {
#                     "action": "permit",
#                     "continue_sequence": 2,
#                     "description": "test",
#                     "on_match": {
#                         "next": true
#                     },
#                     "sequence": 1
#                 }
#             ],
#             "route_map": "test1"
#         },
#         {
#             "entries": [
#                 {
#                     "action": "permit",
#                     "match": {
#                         "metric": 1,
#                         "peer": "192.0.2.32",
#                         "rpki": "invalid"
#                     },
#                     "sequence": 1,
#                     "set": {
#                         "local_preference": "4",
#                         "metric": "5",
#                         "metric_type": "type-1",
#                         "origin": "egp",
#                         "originator_id": "192.0.2.34",
#                         "tag": "5",
#                         "weight": "4"
#                     }
#                 }
#             ],
#             "route_map": "test3"
#         }
#     ]

# Using parsed:
# ------------

# parsed.cfg
# set policy route-map test1 rule 1 description test
# set policy route-map test1 rule 1 action permit
# set policy route-map test1 rule 1 continue 2
# set policy route-map test1 rule 1 on-match next
# set policy route-map test3 rule 1 action permit
# set policy route-map test3 rule 1 set local-preference 4
# set policy route-map test3 rule 1 set metric 5
# set policy route-map test3 rule 1 set metric-type type-1
# set policy route-map test3 rule 1 set origin egp
# set policy route-map test3 rule 1 set originator-id 192.0.2.34
# set policy route-map test3 rule 1 set tag 5
# set policy route-map test3 rule 1 set weight 4
# set policy route-map test3 rule 1 match metric 1
# set policy route-map test3 rule 1 match peer 192.0.2.32
# set policy route-map test3 rule 1 match rpki invalid
#
# - name: parse configs
#   vyos.vyos.vyos_route_maps:
#     running_config: "{{ lookup('file', './parsed.cfg') }}"
#     state: parsed
#   tags:
#     - parsed
#
# Module execution:
# "parsed": [
#         {
#             "entries": [
#                 {
#                     "action": "permit",
#                     "continue_sequence": 2,
#                     "description": "test",
#                     "on_match": {
#                         "next": true
#                     },
#                     "sequence": 1
#                 }
#             ],
#             "route_map": "test1"
#         },
#         {
#             "entries": [
#                 {
#                     "action": "permit",
#                     "match": {
#                         "metric": 1,
#                         "peer": "192.0.2.32",
#                         "rpki": "invalid"
#                     },
#                     "sequence": 1,
#                     "set": {
#                         "local_preference": "4",
#                         "metric": "5",
#                         "metric_type": "type-1",
#                         "origin": "egp",
#                         "originator_id": "192.0.2.34",
#                         "tag": "5",
#                         "weight": "4"
#                     }
#                 }
#             ],
#             "route_map": "test3"
#         }
#     ]
#
#
# Using rendered:
# --------------
# - name: Structure provided configuration into device specific commands
#       register: result
#       vyos.vyos.vyos_route_maps: &id001
#         config:
#           - route_map: test1
#             entries:
#               - sequence: 1
#                 description: "test"
#                 action: permit
#                 continue_sequence: 2
#                 on_match:
#                   next: True
#           - route_map: test3
#             entries:
#               - sequence: 1
#                 action: permit
#                 match:
#                   rpki: invalid
#                   metric: 1
#                   peer: 192.0.2.32
#                 set:
#                   local_preference: 4
#                   metric: 5
#                   metric_type: "type-1"
#                   origin: egp
#                   originator_id: 192.0.2.34
#                   tag: 5
#                   weight: 4
#         state: rendered
# Module Execution:
# "rendered": [
#         "set policy route-map test1 rule 1 description test",
#         "set policy route-map test1 rule 1 action permit",
#         "set policy route-map test1 rule 1 continue 2",
#         "set policy route-map test1 rule 1 on-match next",
#         "set policy route-map test3 rule 1 action permit",
#         "set policy route-map test3 rule 1 set local-preference 4",
#         "set policy route-map test3 rule 1 set metric 5",
#         "set policy route-map test3 rule 1 set metric-type type-1",
#         "set policy route-map test3 rule 1 set origin egp",
#         "set policy route-map test3 rule 1 set originator-id 192.0.2.34",
#         "set policy route-map test3 rule 1 set tag 5",
#         "set policy route-map test3 rule 1 set weight 4",
#         "set policy route-map test3 rule 1 match metric 1",
#         "set policy route-map test3 rule 1 match peer 192.0.2.32",
#         "set policy route-map test3 rule 1 match rpki invalid"
#     ]
#
#
# Using overridden:
# --------------
# Before state:
# vyos@vyos:~$ show configuration commands |  match "set policy route-map"
# set policy route-map test2 rule 1 action 'permit'
# set policy route-map test2 rule 1 description 'test'
# set policy route-map test2 rule 1 on-match next
# set policy route-map test2 rule 2 action 'permit'
# set policy route-map test2 rule 2 on-match goto '4'
# set policy route-map test3 rule 1 action 'permit'
# set policy route-map test3 rule 1 match metric '1'
# set policy route-map test3 rule 1 match peer '192.0.2.32'
# set policy route-map test3 rule 1 match rpki 'invalid'
# set policy route-map test3 rule 1 set community 'internet'
# set policy route-map test3 rule 1 set ip-next-hop '192.0.2.33'
# set policy route-map test3 rule 1 set local-preference '4'
# set policy route-map test3 rule 1 set metric '5'
# set policy route-map test3 rule 1 set metric-type 'type-1'
# set policy route-map test3 rule 1 set origin 'egp'
# set policy route-map test3 rule 1 set originator-id '192.0.2.34'
# set policy route-map test3 rule 1 set tag '5'
# set policy route-map test3 rule 1 set weight '4'
#
#     - name: Override the existing configuration with the provided running configuration
#       register: result
#       vyos.vyos.vyos_route_maps: &id001
#         config:
#           - route_map: test3
#             entries:
#               - sequence: 1
#                 action: permit
#                 match:
#                   rpki: invalid
#                   metric: 3
#                   peer: 192.0.2.35
#                 set:
#                   local_preference: 6
#                   metric: 4
#                   metric_type: "type-1"
#                   origin: egp
#                   originator_id: 192.0.2.34
#                   tag: 4
#                   weight: 4
#         state: overridden
# After state:

# vyos@vyos:~$ show configuration commands |  match "set policy route-map"
# set policy route-map test3 rule 1 set metric-type 'type-1'
# set policy route-map test3 rule 1 set origin 'egp'
# set policy route-map test3 rule 1 set originator-id '192.0.2.34'
# set policy route-map test3 rule 1 set weight '4'
# set policy route-map test3 rule 1 set local-preference 6
# set policy route-map test3 rule 1 set metric 4
# set policy route-map test3 rule 1 set tag 4
# set policy route-map test3 rule 1 match metric 3
# set policy route-map test3 rule 1 match peer 192.0.2.35
# set policy route-map test3 rule 1 match rpki 'invalid'

# Module Execution:
# "after": [
#         {
#             "entries": [
#                 {
#                     "action": "permit",
#                     "match": {
#                         "metric": 3,
#                         "peer": "192.0.2.35",
#                         "rpki": "invalid"
#                     },
#                     "sequence": 1,
#                     "set": {
#                         "local_preference": "6",
#                         "metric": "4",
#                         "metric_type": "type-1",
#                         "origin": "egp",
#                         "originator_id": "192.0.2.34",
#                         "tag": "4",
#                         "weight": "4"
#                     }
#                 }
#             ],
#             "route_map": "test3"
#         }
#     ],
#     "before": [
#         {
#             "entries": [
#                 {
#                     "action": "permit",
#                     "description": "test",
#                     "on_match": {
#                         "next": true
#                     },
#                     "sequence": 1
#                 },
#                 {
#                     "action": "permit",
#                     "on_match": {
#                         "goto": 4
#                     },
#                     "sequence": 2
#                 }
#             ],
#             "route_map": "test2"
#         },
#         {
#             "entries": [
#                 {
#                     "action": "permit",
#                     "match": {
#                         "metric": 1,
#                         "peer": "192.0.2.32",
#                         "rpki": "invalid"
#                     },
#                     "sequence": 1,
#                     "set": {
#                         "community": {
#                             "value": "internet"
#                         },
#                         "ip_next_hop": "192.0.2.33",
#                         "local_preference": "4",
#                         "metric": "5",
#                         "metric_type": "type-1",
#                         "origin": "egp",
#                         "originator_id": "192.0.2.34",
#                         "tag": "5",
#                         "weight": "4"
#                     }
#                 }
#             ],
#             "route_map": "test3"
#         }
#     ],
#     "changed": true,
#     "commands": [
#         "delete policy route-map test2",
#         "delete policy route-map test3 rule 1 set ip-next-hop 192.0.2.33",
#         "set policy route-map test3 rule 1 set local-preference 6",
#         "set policy route-map test3 rule 1 set metric 4",
#         "set policy route-map test3 rule 1 set tag 4",
#         "delete policy route-map test3 rule 1 set community internet",
#         "set policy route-map test3 rule 1 match metric 3",
#         "set policy route-map test3 rule 1 match peer 192.0.2.35"
#     ],
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
  - "set policy route-map test3 rule 1 set local-preference 6"
  - "set policy route-map test3 rule 1 set metric 4"
  - "set policy route-map test3 rule 1 set tag 4"
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
  - "set policy route-map test3 rule 1 set local-preference 6"
  - "set policy route-map test3 rule 1 set metric 4"
  - "set policy route-map test3 rule 1 set tag 4"
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

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.argspec.route_maps.route_maps import (
    Route_mapsArgs,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.config.route_maps.route_maps import (
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
