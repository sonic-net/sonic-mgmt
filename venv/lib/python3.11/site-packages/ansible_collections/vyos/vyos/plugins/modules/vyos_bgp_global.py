#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for vyos_bgp_global
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: vyos_bgp_global
version_added: 1.0.0
short_description: BGP global resource module
description:
- This module manages BGP global configuration of interfaces on devices running VYOS.
- Tested against VyOS 1.3.8, 1.4.2, the upcoming 1.5, and the rolling release of spring 2025
- The provided examples of commands are valid for VyOS 1.4+
author:
- Gomathi Selvi Srinivasan (@GomathiselviS)
options:
  config:
    description: A dict of BGP global configuration for interfaces.
    type: dict
    suboptions:
      as_number:
        description:
        - AS number.
        type: int
      # aggregate_address:
      #   description:
      #   - BGP aggregate network.
      #   type: list
      #   elements: dict
      #   suboptions:
      #     prefix:
      #       description:
      #       - BGP aggregate network.
      #       type: str
      #     as_set:
      #       description:
      #       - Generate AS-set path information for this aggregate address.
      #       type: bool
      #     summary_only:
      #       description:
      #       - Announce the aggregate summary network only.
      #       type: bool
      #maximum_paths: --> moved to address-family before 1.3
      #  description: BGP multipaths
      #  type: list
      #  elements: dict
      #  suboptions:
      #    path:
      #      description: BGP multipaths
      #      type: str
      #    count:
      #      description: No. of paths.
      #      type: int
      neighbor:
        description: BGP neighbor
        type: list
        elements: dict
        suboptions:
          address:
            description:
            - BGP neighbor address (v4/v6).
            type: str
          advertisement_interval:
            description:
            - Minimum interval for sending routing updates.
            type: int
      #    bfd: # <-- added in 1.3
      #      description: Enable Bidirectional Forwarding Detection (BFD) support
      #      type: dict
      #      suboptions:
      #        check-control-plane-failure:
      #          description:
      #          - Allow to write CBIT independence in BFD outgoing packets
      #            and read both C-BIT value of BFD and lookup BGP peer status
      #          type: bool
      #    allowas_in:   --> Moved to address-family before 1.3
      #      description:
      #      - Number of occurrences of AS number.
      #      type: int
      #    as_override:  --> Moved to address-family before 1.3
      #      description:
      #      - AS for routes sent to this neighbor to be the local AS.
      #      type: bool
      #    attribute_unchanged: --> Moved to address-family before 1.3
      #      description:
      #      - BGP attributes are sent unchanged.
      #      type: dict
      #      suboptions:
      #        as_path:
      #          description: as_path
      #          type: bool
      #        med:
      #          description: med
      #          type: bool
      #        next_hop:
      #          description: next_hop
      #          type: bool
          capability:
            description:
            - Advertise capabilities to this neighbor.
            type: dict
            suboptions:
              dynamic:
                description:
                - Advertise dynamic capability to this neighbor.
                type: bool
              extended_nexthop:
                description:
                - Advertise extended nexthop capability to this neighbor.
                type: bool
      #       orf:   --> Removed before 1.3
      #         description:
      #          - Advertise ORF capability to this neighbor.
      #         type: str
      #         choices:
      #         - send
      #         - receive
          default_originate:
            description:
            - Send default route to this neighbor
            type: str
          description:
            description:
            - Description of the neighbor
            type: str
          disable_capability_negotiation:
            description:
            - Disbale capability negotiation with the neighbor
            type: bool
          disable_connected_check:
            description:
            - Disable check to see if EBGP peer's address is a connected route.
            type: bool
          disable_send_community:
            description:
            - Disable sending community attributes to this neighbor.
            type: str
            choices: ['extended', 'standard']
      #   distribute_list:  --> Moved to address-family before 1.3
      #     description: Access-list to filter route updates to/from this neighbor.
      #     type: list
      #     elements: dict
      #     suboptions:
      #       action:
      #         description: Access-list to filter outgoing/incoming route updates to this neighbor
      #         type: str
      #         choices: ['export', 'import']
      #       acl:
      #         description: Access-list number.
      #         type: int
          ebgp_multihop:
            description:
              - Allow this EBGP neighbor to not be on a directly connected network. Specify
                the number hops.
            type: int
      #    interface: # <-- added in 1.3
      #      description: interface parameters
      #      type: dict
      #      suboptions:
      #        peer_group:
      #          description: Peer group for this neighbor
      #          type: str
      #        remote_as:
      #          description:
      #          - Remote AS number
      #          - Or 'external' for any number except this AS number
      #          - or 'internal' for this AS number
      #          type: str
      #        v6only:
      #          description: Enable BGP with v6 link-local only
      #          type: dict
      #          suboptions:
      #            peer_group:
      #              description: Peer group for this neighbor
      #              type: str
      #            remote_as:
      #              description:
      #              - Remote AS number
      #              - Or 'external' for any number except this AS number
      #              - or 'internal' for this AS number
      #    filter_list:  --> Moved to address-family before 1.3
      #      description: As-path-list to filter route updates to/from this neighbor.
      #      type: list
      #      elements: dict
      #      suboptions:
      #        action:
      #          description: filter outgoing/incoming route updates
      #          type: str
      #          choices: ['export', 'import']
      #        path_list:
      #          description: As-path-list to filter
      #          type: str
          local_as:
            description: local as number not to be prepended to updates from EBGP peers
            type: int
      #   maximum_prefix:  --> Moved to address-family before 1.3
      #     description: Maximum number of prefixes to accept from this neighbor
      #        nexthop-self Nexthop for routes sent to this neighbor to be the local router.
      #     type: int
      #   nexthop_self: --> Moved to address-family before 1.3
      #     description: Nexthop for routes sent to this neighbor to be the local router.
      #     type: bool
          override_capability:
            description: Ignore capability negotiation with specified neighbor.
            type: bool
          passive:
            description: Do not initiate a session with this neighbor
            type: bool
          password:
            description: BGP MD5 password
            type: str
          peer_group_name:
            description: IPv4 peer group for this peer
            type: str
          peer_group:
            description: True if all the configs under this neighbor key is for peer group template.
            type: bool
          port:
            description: Neighbor's BGP port
            type: int
      #    prefix_list:  --> Moved to address-family before 1.3
      #      description: Prefix-list to filter route updates to/from this neighbor.
      #      type: list
      #      elements: dict
      #      suboptions:
      #        action:
      #          description: filter outgoing/incoming route updates
      #          type: str
      #          choices: ['export', 'import']
      #        prefix_list:
      #          description: Prefix-list to filter
      #          type: str
          remote_as:
            description: Neighbor BGP AS number
            type: int
      #    remove_private_as: --> Moved to address-family before 1.3
      #      description: Remove private AS numbers from AS path in outbound route updates
      #      type: bool
      #   route_map:    --> Moved to address-family before 1.3
      #     description: Route-map to filter route updates to/from this neighbor.
      #     type: list
      #     elements: dict
      #     suboptions:
      #       action:
      #         description: filter outgoing/incoming route updates
      #         type: str
      #         choices: ['export', 'import']
      #       route_map:
      #         description: route-map to filter
      #         type: str
      #    route_reflector_client:   --> Moved to address-family before 1.3
      #      description: Neighbor as a route reflector client
      #      type: bool
      #    route_server_client:   --> Removed prior to 1.3
      #      description: Neighbor is route server client
      #      type: bool
          shutdown:
            description: Administratively shut down neighbor
            type: bool
      #    soft_reconfiguration:  --> Moved to address-family before 1.3
      #      description: Soft reconfiguration for neighbor
      #      type: bool
          solo: # <-- added in 1.3
            description: Do not send back prefixes learned from the neighbor
            type: bool
          strict_capability_match:
            description: Enable strict capability negotiation
            type: bool
      #    unsuppress_map:   --> Moved to address-family before 1.3
      #      description: Route-map to selectively unsuppress suppressed routes
      #      type: str

      #    weight:    --> Moved to address-family before 1.3
      #      description: Default weight for routes from this neighbor
      #      type: int
          timers:
            description: Neighbor timers
            type: dict
            suboptions:
              connect:
                description: BGP connect timer for this neighbor.
                type: int
              holdtime:
                description: BGP hold timer for this neighbor
                type: int
              keepalive:
                description: BGP keepalive interval for this neighbor
                type: int
          ttl_security:
            description: Number of the maximum number of hops to the BGP peer
            type: int
          update_source:
            description: Source IP of routing updates
            type: str
      # network:
      #   description: BGP network
      #   type: list
      #   elements: dict
      #   suboptions:
      #     address:
      #       description: BGP network address
      #       type: str
      #     backdoor:
      #       description: Network as a backdoor route
      #       type: bool
      #     route_map:
      #       description: Route-map to modify route attributes
      #       type: str
      # redistribute:
      #   description: Redistribute routes from other protocols into BGP
      #   type: list
      #   elements: dict
      #   suboptions:
      #     protocol:
      #       description: types of routes to be redistributed.
      #       type: str
      #       choices: ['connected', 'kernel', 'ospf', 'rip', 'static']
      #     route_map:
      #       description: Route map to filter redistributed routes
      #       type: str
      #     metric:
      #       description: Metric for redistributed routes.
      #       type: int
      timers:
        description: BGP protocol timers
        type: dict
        suboptions:
          keepalive:
            description: Keepalive interval
            type: int
          holdtime:
            description: Hold time interval
            type: int
      bgp_params:
        description: BGP parameters
        type: dict
        suboptions:
          always_compare_med:
            description: Always compare MEDs from different neighbors
            type: bool
          bestpath:
            description: Default bestpath selection mechanism
            type: dict
            suboptions:
              as_path:
                description: AS-path attribute comparison parameters
                type: str
                choices: ['confed', 'ignore']
              compare_routerid:
                description: Compare the router-id for identical EBGP paths
                type: bool
              med:
                description: MED attribute comparison parameters
                type: str
                choices: ['confed', 'missing-as-worst']
          cluster_id:
            description: Route-reflector cluster-id
            type: str
          confederation:
            description: AS confederation parameters
            type: list
            elements: dict
            suboptions:
              identifier:
                description: Confederation AS identifier
                type: int
              peers:
                description: Peer ASs in the BGP confederation
                type: int
          dampening:
            description: Enable route-flap dampening
            type: dict
            suboptions:
              half_life:
                description: Half-life penalty in seconds
                type: int
              max_suppress_time:
                description: Maximum duration to suppress a stable route
                type: int
              re_use:
                description: Time to start reusing a route
                type: int
              start_suppress_time:
                description: When to start suppressing a route
                type: int
          default:
            description: BGP defaults
            type: dict
            suboptions:
              local_pref:
                description: Default local preference
                type: int
              no_ipv4_unicast:
                description: |
                  Deactivate IPv4 unicast for a peer by default
                  Deprecated: Unavailable after 1.4
                type: bool
          deterministic_med:
            description: Compare MEDs between different peers in the same AS
            type: bool
          disable_network_import_check:
            description: Disable IGP route check for network statements
            type: bool
          distance:
            description: Administrative distances for BGP routes
            type: list
            elements: dict
            suboptions:
              type:
                description: Type of route
                type: str
                choices: ['external', 'internal', 'local']
              value:
                description: distance
                type: int
              prefix:
                description: Administrative distance for a specific BGP prefix
                type: int
          enforce_first_as:
            description: Require first AS in the path to match peer's AS
            type: bool
          graceful_restart:
            description: Maximum time to hold onto restarting peer's stale paths
            type: int
          log_neighbor_changes:
            description: Log neighbor up/down changes and reset reason
            type: bool
          no_client_to_client_reflection:
            description: Disable client to client route reflection
            type: bool
          no_fast_external_failover:
            description: Disable immediate session reset if peer's connected link goes down
            type: bool
          router_id:
            description: BGP router-id
            type: str
          scan_time:
            description: BGP route scanner interval
            type: int
  state:
    description:
        - The state the configuration should be left in.
        - State I(purged) removes all the BGP configurations from the
          target device. Use caution with this state.('delete protocols bgp <x>')
        - State I(deleted) only removes BGP attributes that this modules
          manages and does not negate the BGP process completely. Thereby, preserving
          address-family related configurations under BGP context.
        - Running states I(deleted) and I(replaced) will result in an error if there
          are address-family configuration lines present under neighbor context that is
          is to be removed. Please use the  M(vyos.vyos.vyos_bgp_address_family)
          module for prior cleanup.
        - Refer to examples for more details.
    type: str
    choices: [deleted, merged, purged, replaced, gathered, rendered, parsed]
    default: merged
  running_config:
    description:
      - This option is used only with state I(parsed).
      - The value of this option should be the output received from the EOS device by
        executing the command B(show running-config | section bgp).
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into Ansible structured data as per the resource module's argspec
        and the value is then returned in the I(parsed) key within the result.
    type: str
"""

EXAMPLES = """
# Using merged
# Before state

# vyos@vyos:~$ show configuration commands |  match "set protocols bgp"
# vyos@vyos:~$

- name: Merge provided configuration with device configuration
  vyos.vyos.vyos_bgp_global:
    config:
      as_number: "65536"
      aggregate_address:
        - prefix: "203.0.113.0/24"
          as_set: true
        - prefix: "192.0.2.0/24"
          summary_only: true
      network:
        - address: "192.1.13.0/24"
          backdoor: true
      redistribute:
        - protocol: "kernel"
          metric: 45
        - protocol: "connected"
          route_map: "map01"
      maximum_paths:
        - path: "ebgp"
          count: 20
        - path: "ibgp"
          count: 55
      timers:
        keepalive: 35
      bgp_params:
        bestpath:
          as_path: "confed"
          compare_routerid: true
        default:
          no_ipv4_unicast: true
        router_id: "192.1.2.9"
        confederation:
          - peers: 20
          - peers: 55
          - identifier: 66
      neighbor:
        - address: "192.0.2.25"
          disable_connected_check: true
          timers:
            holdtime: 30
            keepalive: 10
        - address: "203.0.113.5"
          attribute_unchanged:
            as_path: true
            med: true
          ebgp_multihop: 2
          remote_as: 101
          update_source: "192.0.2.25"
        - address: "5001::64"
          maximum_prefix: 34
          distribute_list:
            - acl: 20
              action: "export"
            - acl: 40
              action: "import"
    state: merged

# After State
# vyos@vyos:~$ show configuration commands |  match "set protocols bgp"
# set protocols bgp system-as 65536
# set protocols bgp aggregate-address 192.0.2.0/24 'summary-only'
# set protocols bgp aggregate-address 203.0.113.0/24 'as-set'
# set protocols bgp maximum-paths ebgp '20'
# set protocols bgp maximum-paths ibgp '55'
# set protocols bgp neighbor 192.0.2.25 'disable-connected-check'
# set protocols bgp neighbor 192.0.2.25 timers holdtime '30'
# set protocols bgp neighbor 192.0.2.25 timers keepalive '10'
# set protocols bgp neighbor 203.0.113.5 attribute-unchanged 'as-path'
# set protocols bgp neighbor 203.0.113.5 attribute-unchanged 'med'
# set protocols bgp neighbor 203.0.113.5 attribute-unchanged 'next-hop'
# set protocols bgp neighbor 203.0.113.5 ebgp-multihop '2'
# set protocols bgp neighbor 203.0.113.5 remote-as '101'
# set protocols bgp neighbor 203.0.113.5 update-source '192.0.2.25'
# set protocols bgp neighbor 5001::64 distribute-list export '20'
# set protocols bgp neighbor 5001::64 distribute-list import '40'
# set protocols bgp neighbor 5001::64 maximum-prefix '34'
# set protocols bgp network 192.1.13.0/24 'backdoor'
# set protocols bgp parameters bestpath as-path 'confed'
# set protocols bgp parameters bestpath 'compare-routerid'
# set protocols bgp parameters confederation identifier '66'
# set protocols bgp parameters confederation peers '20'
# set protocols bgp parameters confederation peers '55'
# set protocols bgp parameters default 'no-ipv4-unicast'
# set protocols bgp parameters router-id '192.1.2.9'
# set protocols bgp redistribute connected route-map 'map01'
# set protocols bgp redistribute kernel metric '45'
# set protocols bgp timers keepalive '35'
# vyos@vyos:~$
#
# # Module Execution:
#
# "after": {
#         "aggregate_address": [
#             {
#                 "prefix": "192.0.2.0/24",
#                 "summary_only": true
#             },
#             {
#                 "prefix": "203.0.113.0/24",
#                 "as_set": true
#             }
#         ],
#         "as_number": 65536,
#         "bgp_params": {
#             "bestpath": {
#                 "as_path": "confed",
#                 "compare_routerid": true
#             },
#             "confederation": [
#                 {
#                     "identifier": 66
#                 },
#                 {
#                     "peers": 20
#                 },
#                 {
#                     "peers": 55
#                 }
#             ],
#             "default": {
#                 "no_ipv4_unicast": true
#             },
#             "router_id": "192.1.2.9"
#         },
#         "maximum_paths": [
#             {
#                 "count": 20,
#                 "path": "ebgp"
#             },
#             {
#                 "count": 55,
#                 "path": "ibgp"
#             }
#         ],
#         "neighbor": [
#             {
#                 "address": "192.0.2.25",
#                 "disable_connected_check": true,
#                 "timers": {
#                     "holdtime": 30,
#                     "keepalive": 10
#                 }
#             },
#             {
#                 "address": "203.0.113.5",
#                 "attribute_unchanged": {
#                     "as_path": true,
#                     "med": true,
#                     "next_hop": true
#                 },
#                 "ebgp_multihop": 2,
#                 "remote_as": 101,
#                 "update_source": "192.0.2.25"
#             },
#             {
#                 "address": "5001::64",
#                 "distribute_list": [
#                     {
#                         "acl": 20,
#                         "action": "export"
#                     },
#                     {
#                         "acl": 40,
#                         "action": "import"
#                     }
#                 ],
#                 "maximum_prefix": 34
#             }
#         ],
#         "network": [
#             {
#                 "address": "192.1.13.0/24",
#                 "backdoor": true
#             }
#         ],
#         "redistribute": [
#             {
#                 "protocol": "connected",
#                 "route_map": "map01"
#             },
#             {
#                 "metric": 45,
#                 "protocol": "kernel"
#             }
#         ],
#         "timers": {
#             "keepalive": 35
#         }
#     },
#     "before": {},
#     "changed": true,
#     "commands": [
#         "set protocols bgp neighbor 192.0.2.25 disable-connected-check",
#         "set protocols bgp neighbor 192.0.2.25 timers holdtime 30",
#         "set protocols bgp neighbor 192.0.2.25 timers keepalive 10",
#         "set protocols bgp neighbor 203.0.113.5 attribute-unchanged as-path",
#         "set protocols bgp neighbor 203.0.113.5 attribute-unchanged med",
#         "set protocols bgp neighbor 203.0.113.5 attribute-unchanged next-hop",
#         "set protocols bgp neighbor 203.0.113.5 ebgp-multihop 2",
#         "set protocols bgp neighbor 203.0.113.5 remote-as 101",
#         "set protocols bgp neighbor 203.0.113.5 update-source 192.0.2.25",
#         "set protocols bgp neighbor 5001::64 maximum-prefix 34",
#         "set protocols bgp neighbor 5001::64 distribute-list export 20",
#         "set protocols bgp neighbor 5001::64 distribute-list import 40",
#         "set protocols bgp redistribute kernel metric 45",
#         "set protocols bgp redistribute connected route-map map01",
#         "set protocols bgp network 192.1.13.0/24 backdoor",
#         "set protocols bgp aggregate-address 203.0.113.0/24 as-set",
#         "set protocols bgp aggregate-address 192.0.2.0/24 summary-only",
#         "set protocols bgp parameters bestpath as-path confed",
#         "set protocols bgp parameters bestpath compare-routerid",
#         "set protocols bgp parameters default no-ipv4-unicast",
#         "set protocols bgp parameters router-id 192.1.2.9",
#         "set protocols bgp parameters confederation peers 20",
#         "set protocols bgp parameters confederation peers 55",
#         "set protocols bgp parameters confederation identifier 66",
#         "set protocols bgp maximum-paths ebgp 20",
#         "set protocols bgp maximum-paths ibgp 55",
#         "set protocols bgp timers keepalive 35"
#     ],

# Using replaced:
# --------------

# Before state:

# vyos@vyos:~$ show configuration commands |  match "set protocols bgp"
# set protocols bgp system-as 65536
# set protocols bgp aggregate-address 192.0.2.0/24 'summary-only'
# set protocols bgp aggregate-address 203.0.113.0/24 'as-set'
# set protocols bgp maximum-paths ebgp '20'
# set protocols bgp maximum-paths ibgp '55'
# set protocols bgp neighbor 192.0.2.25 'disable-connected-check'
# set protocols bgp neighbor 192.0.2.25 timers holdtime '30'
# set protocols bgp neighbor 192.0.2.25 timers keepalive '10'
# set protocols bgp neighbor 203.0.113.5 attribute-unchanged 'as-path'
# set protocols bgp neighbor 203.0.113.5 attribute-unchanged 'med'
# set protocols bgp neighbor 203.0.113.5 attribute-unchanged 'next-hop'
# set protocols bgp neighbor 203.0.113.5 ebgp-multihop '2'
# set protocols bgp neighbor 203.0.113.5 remote-as '101'
# set protocols bgp neighbor 203.0.113.5 update-source '192.0.2.25'
# set protocols bgp neighbor 5001::64 distribute-list export '20'
# set protocols bgp neighbor 5001::64 distribute-list import '40'
# set protocols bgp neighbor 5001::64 maximum-prefix '34'
# set protocols bgp network 192.1.13.0/24 'backdoor'
# set protocols bgp parameters bestpath as-path 'confed'
# set protocols bgp parameters bestpath 'compare-routerid'
# set protocols bgp parameters confederation identifier '66'
# set protocols bgp parameters confederation peers '20'
# set protocols bgp parameters confederation peers '55'
# set protocols bgp parameters default 'no-ipv4-unicast'
# set protocols bgp parameters router-id '192.1.2.9'
# set protocols bgp redistribute connected route-map 'map01'
# set protocols bgp redistribute kernel metric '45'
# set protocols bgp timers keepalive '35'
# vyos@vyos:~$

- name: Replace
  vyos.vyos.vyos_bgp_global:
    config:
      as_number: "65536"
      network:
        - address: "203.0.113.0/24"
          route_map: map01
      redistribute:
        - protocol: "static"
          route_map: "map01"
      neighbor:
        - address: "192.0.2.40"
          advertisement_interval: 72
          capability:
            orf: "receive"
      bgp_params:
        bestpath:
          as_path: "confed"
    state: replaced
# After state:

# vyos@vyos:~$ show configuration commands |  match "set protocols bgp"
# set protocols bgp system-as 65536
# set protocols bgp neighbor 192.0.2.40 advertisement-interval '72'
# set protocols bgp neighbor 192.0.2.40 capability orf prefix-list 'receive'
# set protocols bgp network 203.0.113.0/24 route-map 'map01'
# set protocols bgp parameters bestpath as-path 'confed'
# set protocols bgp redistribute static route-map 'map01'
# vyos@vyos:~$
#
#
# Module Execution:
#
# "after": {
#         "as_number": 65536,
#         "bgp_params": {
#             "bestpath": {
#                 "as_path": "confed"
#             }
#         },
#         "neighbor": [
#             {
#                 "address": "192.0.2.40",
#                 "advertisement_interval": 72,
#                 "capability": {
#                     "orf": "receive"
#                 }
#             }
#         ],
#         "network": [
#             {
#                 "address": "203.0.113.0/24",
#                 "route_map": "map01"
#             }
#         ],
#         "redistribute": [
#             {
#                 "protocol": "static",
#                 "route_map": "map01"
#             }
#         ]
#     },
#     "before": {
#         "aggregate_address": [
#             {
#                 "prefix": "192.0.2.0/24",
#                 "summary_only": true
#             },
#             {
#                 "prefix": "203.0.113.0/24",
#                 "as_set": true
#             }
#         ],
#         "as_number": 65536,
#         "bgp_params": {
#             "bestpath": {
#                 "as_path": "confed",
#                 "compare_routerid": true
#             },
#             "confederation": [
#                 {
#                     "identifier": 66
#                 },
#                 {
#                     "peers": 20
#                 },
#                 {
#                     "peers": 55
#                 }
#             ],
#             "default": {
#                 "no_ipv4_unicast": true
#             },
#             "router_id": "192.1.2.9"
#         },
#         "maximum_paths": [
#             {
#                 "count": 20,
#                 "path": "ebgp"
#             },
#             {
#                 "count": 55,
#                 "path": "ibgp"
#             }
#         ],
#         "neighbor": [
#             {
#                 "address": "192.0.2.25",
#                 "disable_connected_check": true,
#                 "timers": {
#                     "holdtime": 30,
#                     "keepalive": 10
#                 }
#             },
#             {
#                 "address": "203.0.113.5",
#                 "attribute_unchanged": {
#                     "as_path": true,
#                     "med": true,
#                     "next_hop": true
#                 },
#                 "ebgp_multihop": 2,
#                 "remote_as": 101,
#                 "update_source": "192.0.2.25"
#             },
#             {
#                 "address": "5001::64",
#                 "distribute_list": [
#                     {
#                         "acl": 20,
#                         "action": "export"
#                     },
#                     {
#                         "acl": 40,
#                         "action": "import"
#                     }
#                 ],
#                 "maximum_prefix": 34
#             }
#         ],
#         "network": [
#             {
#                 "address": "192.1.13.0/24",
#                 "backdoor": true
#             }
#         ],
#         "redistribute": [
#             {
#                 "protocol": "connected",
#                 "route_map": "map01"
#             },
#             {
#                 "metric": 45,
#                 "protocol": "kernel"
#             }
#         ],
#         "timers": {
#             "keepalive": 35
#         }
#     },
#     "changed": true,
#     "commands": [
#         "delete protocols bgp timers",
#         "delete protocols bgp maximum-paths ",
#         "delete protocols bgp maximum-paths ",
#         "delete protocols bgp parameters router-id 192.1.2.9",
#         "delete protocols bgp parameters default",
#         "delete protocols bgp parameters confederation",
#         "delete protocols bgp parameters bestpath compare-routerid",
#         "delete protocols bgp aggregate-address",
#         "delete protocols bgp network 192.1.13.0/24",
#         "delete protocols bgp redistribute kernel",
#         "delete protocols bgp redistribute kernel",
#         "delete protocols bgp redistribute connected",
#         "delete protocols bgp redistribute connected",
#         "delete protocols bgp neighbor 5001::64",
#         "delete protocols bgp neighbor 203.0.113.5",
#         "delete protocols bgp neighbor 192.0.2.25",
#         "set protocols bgp neighbor 192.0.2.40 advertisement-interval 72",
#         "set protocols bgp neighbor 192.0.2.40 capability orf prefix-list receive",
#         "set protocols bgp redistribute static route-map map01",
#         "set protocols bgp network 203.0.113.0/24 route-map map01"
#     ],

# Using deleted:
# -------------

# Before state:

# vyos@vyos:~$ show configuration commands |  match "set protocols bgp"
# set protocols bgp system-as 65536
# set protocols bgp neighbor 192.0.2.40 advertisement-interval '72'
# set protocols bgp neighbor 192.0.2.40 capability orf prefix-list 'receive'
# set protocols bgp network 203.0.113.0/24 route-map 'map01'
# set protocols bgp parameters bestpath as-path 'confed'
# set protocols bgp redistribute static route-map 'map01'
# vyos@vyos:~$

- name: Delete configuration
  vyos.vyos.vyos_bgp_global:
    config:
      as_number: "65536"
    state: deleted

# After state:

# vyos@vyos:~$ show configuration commands |  match "set protocols bgp"
# set protocols bgp '65536'
# vyos@vyos:~$
#
#
# Module Execution:
#
# "after": {
#         "as_number": 65536
#     },
#     "before": {
#         "as_number": 65536,
#         "bgp_params": {
#             "bestpath": {
#                 "as_path": "confed"
#             }
#         },
#         "neighbor": [
#             {
#                 "address": "192.0.2.40",
#                 "advertisement_interval": 72,
#                 "capability": {
#                     "orf": "receive"
#                 }
#             }
#         ],
#         "network": [
#             {
#                 "address": "203.0.113.0/24",
#                 "route_map": "map01"
#             }
#         ],
#         "redistribute": [
#             {
#                 "protocol": "static",
#                 "route_map": "map01"
#             }
#         ]
#     },
#     "changed": true,
#     "commands": [
#         "delete protocols bgp neighbor 192.0.2.40",
#         "delete protocols bgp redistribute",
#         "delete protocols bgp network",
#         "delete protocols bgp parameters"
#     ],

# Using purged:

# Before state:

# vyos@vyos:~$ show configuration commands |  match "set protocols bgp"
# set protocols bgp system-as 65536
# set protocols bgp aggregate-address 192.0.2.0/24 'summary-only'
# set protocols bgp aggregate-address 203.0.113.0/24 'as-set'
# set protocols bgp maximum-paths ebgp '20'
# set protocols bgp maximum-paths ibgp '55'
# set protocols bgp neighbor 192.0.2.25 'disable-connected-check'
# set protocols bgp neighbor 192.0.2.25 timers holdtime '30'
# set protocols bgp neighbor 192.0.2.25 timers keepalive '10'
# set protocols bgp neighbor 203.0.113.5 attribute-unchanged 'as-path'
# set protocols bgp neighbor 203.0.113.5 attribute-unchanged 'med'
# set protocols bgp neighbor 203.0.113.5 attribute-unchanged 'next-hop'
# set protocols bgp neighbor 203.0.113.5 ebgp-multihop '2'
# set protocols bgp neighbor 203.0.113.5 remote-as '101'
# set protocols bgp neighbor 203.0.113.5 update-source '192.0.2.25'
# set protocols bgp neighbor 5001::64 distribute-list export '20'
# set protocols bgp neighbor 5001::64 distribute-list import '40'
# set protocols bgp neighbor 5001::64 maximum-prefix '34'
# set protocols bgp network 192.1.13.0/24 'backdoor'
# set protocols bgp parameters bestpath as-path 'confed'
# set protocols bgp parameters bestpath 'compare-routerid'
# set protocols bgp parameters confederation identifier '66'
# set protocols bgp parameters confederation peers '20'
# set protocols bgp parameters confederation peers '55'
# set protocols bgp parameters default 'no-ipv4-unicast'
# set protocols bgp parameters router-id '192.1.2.9'
# set protocols bgp redistribute connected route-map 'map01'
# set protocols bgp redistribute kernel metric '45'
# set protocols bgp timers keepalive '35'
# vyos@vyos:~$


- name: Purge configuration
  vyos.vyos.vyos_bgp_global:
    config:
      as_number: "65536"
    state: purged

# After state:

# vyos@vyos:~$ show configuration commands |  match "set protocols bgp"
# vyos@vyos:~$
#
# Module Execution:
#
#     "after": {},
#     "before": {
#         "aggregate_address": [
#             {
#                 "prefix": "192.0.2.0/24",
#                 "summary_only": true
#             },
#             {
#                 "prefix": "203.0.113.0/24",
#                 "as_set": true
#             }
#         ],
#         "as_number": 65536,
#         "bgp_params": {
#             "bestpath": {
#                 "as_path": "confed",
#                 "compare_routerid": true
#             },
#             "confederation": [
#                 {
#                     "identifier": 66
#                 },
#                 {
#                     "peers": 20
#                 },
#                 {
#                     "peers": 55
#                 }
#             ],
#             "default": {
#                 "no_ipv4_unicast": true
#             },
#             "router_id": "192.1.2.9"
#         },
#         "maximum_paths": [
#             {
#                 "count": 20,
#                 "path": "ebgp"
#             },
#             {
#                 "count": 55,
#                 "path": "ibgp"
#             }
#         ],
#         "neighbor": [
#             {
#                 "address": "192.0.2.25",
#                 "disable_connected_check": true,
#                 "timers": {
#                     "holdtime": 30,
#                     "keepalive": 10
#                 }
#             },
#             {
#                 "address": "203.0.113.5",
#                 "attribute_unchanged": {
#                     "as_path": true,
#                     "med": true,
#                     "next_hop": true
#                 },
#                 "ebgp_multihop": 2,
#                 "remote_as": 101,
#                 "update_source": "192.0.2.25"
#             },
#             {
#                 "address": "5001::64",
#                 "distribute_list": [
#                     {
#                         "acl": 20,
#                         "action": "export"
#                     },
#                     {
#                         "acl": 40,
#                         "action": "import"
#                     }
#                 ],
#                 "maximum_prefix": 34
#             }
#         ],
#         "network": [
#             {
#                 "address": "192.1.13.0/24",
#                 "backdoor": true
#             }
#         ],
#         "redistribute": [
#             {
#                 "protocol": "connected",
#                 "route_map": "map01"
#             },
#             {
#                 "metric": 45,
#                 "protocol": "kernel"
#             }
#         ],
#         "timers": {
#             "keepalive": 35
#         }
#     },
#     "changed": true,
#     "commands": [
#         "delete protocols bgp 65536"
#     ],


# Deleted in presence of address family under neighbors:

# Before state:
# vyos@vyos:~$ show configuration commands |  match "set protocols bgp"
# set protocols bgp system-as 65536
# set protocols bgp neighbor 192.0.2.43 advertisement-interval '72'
# set protocols bgp neighbor 192.0.2.43 capability 'dynamic'
# set protocols bgp neighbor 192.0.2.43 'disable-connected-check'
# set protocols bgp neighbor 192.0.2.43 timers holdtime '30'
# set protocols bgp neighbor 192.0.2.43 timers keepalive '10'
# set protocols bgp neighbor 203.0.113.0 address-family 'ipv6-unicast'
# set protocols bgp neighbor 203.0.113.0 capability orf prefix-list 'receive'
# set protocols bgp network 203.0.113.0/24 route-map 'map01'
# set protocols bgp parameters 'always-compare-med'
# set protocols bgp parameters bestpath as-path 'confed'
# set protocols bgp parameters bestpath 'compare-routerid'
# set protocols bgp parameters dampening half-life '33'
# set protocols bgp parameters dampening max-suppress-time '20'
# set protocols bgp parameters dampening re-use '60'
# set protocols bgp parameters dampening start-suppress-time '5'
# set protocols bgp parameters default 'no-ipv4-unicast'
# set protocols bgp parameters distance global external '66'
# set protocols bgp parameters distance global internal '20'
# set protocols bgp parameters distance global local '10'
# set protocols bgp redistribute static route-map 'map01'
# vyos@vyos:~$ ^C
# vyos@vyos:~$

- name: Delete configuration
  vyos.vyos.vyos_bgp_global:
    config:
      as_number: "65536"
    state: deleted

# Module Execution:
#
# "changed": false,
#     "invocation": {
#         "module_args": {
#             "config": {
#                 "aggregate_address": null,
#                 "as_number": 65536,
#                 "bgp_params": null,
#                 "maximum_paths": null,
#                 "neighbor": null,
#                 "network": null,
#                 "redistribute": null,
#                 "timers": null
#             },
#             "running_config": null,
#             "state": "deleted"
#         }
#     },
#     "msg": "Use the _bgp_address_family module to delete the address_family under neighbor 203.0.113.0, before replacing/deleting the neighbor."
# }

# using gathered:
# --------------

# Before state:
# vyos@vyos:~$ show configuration commands |  match "set protocols bgp"
# set protocols bgp system-as 65536
# set protocols bgp neighbor 192.0.2.43 advertisement-interval '72'
# set protocols bgp neighbor 192.0.2.43 capability 'dynamic'
# set protocols bgp neighbor 192.0.2.43 'disable-connected-check'
# set protocols bgp neighbor 192.0.2.43 timers holdtime '30'
# set protocols bgp neighbor 192.0.2.43 timers keepalive '10'
# set protocols bgp neighbor 203.0.113.0 address-family 'ipv6-unicast'
# set protocols bgp neighbor 203.0.113.0 capability orf prefix-list 'receive'
# set protocols bgp network 203.0.113.0/24 route-map 'map01'
# set protocols bgp parameters 'always-compare-med'
# set protocols bgp parameters bestpath as-path 'confed'
# set protocols bgp parameters bestpath 'compare-routerid'
# set protocols bgp parameters dampening half-life '33'
# set protocols bgp parameters dampening max-suppress-time '20'
# set protocols bgp parameters dampening re-use '60'
# set protocols bgp parameters dampening start-suppress-time '5'
# set protocols bgp parameters default 'no-ipv4-unicast'
# set protocols bgp parameters distance global external '66'
# set protocols bgp parameters distance global internal '20'
# set protocols bgp parameters distance global local '10'
# set protocols bgp redistribute static route-map 'map01'
# vyos@vyos:~$ ^C

- name: gather configs
  vyos.vyos.vyos_bgp_global:
    state: gathered

# Module Execution:
# "gathered": {
#         "as_number": 65536,
#         "bgp_params": {
#             "always_compare_med": true,
#             "bestpath": {
#                 "as_path": "confed",
#                 "compare_routerid": true
#             },
#             "default": {
#                 "no_ipv4_unicast": true
#             },
#             "distance": [
#                 {
#                     "type": "external",
#                     "value": 66
#                 },
#                 {
#                     "type": "internal",
#                     "value": 20
#                 },
#                 {
#                     "type": "local",
#                     "value": 10
#                 }
#             ]
#         },
#         "neighbor": [
#             {
#                 "address": "192.0.2.43",
#                 "advertisement_interval": 72,
#                 "capability": {
#                     "dynamic": true
#                 },
#                 "disable_connected_check": true,
#                 "timers": {
#                     "holdtime": 30,
#                     "keepalive": 10
#                 }
#             },
#             {
#                 "address": "203.0.113.0",
#                 "capability": {
#                     "orf": "receive"
#                 }
#             }
#         ],
#         "network": [
#             {
#                 "address": "203.0.113.0/24",
#                 "route_map": "map01"
#             }
#         ],
#         "redistribute": [
#             {
#                 "protocol": "static",
#                 "route_map": "map01"
#             }
#         ]
#     },
#

# Using parsed:
# ------------

# parsed.cfg

# set protocols bgp neighbor 192.0.2.43 advertisement-interval '72'
# set protocols bgp neighbor 192.0.2.43 capability 'dynamic'
# set protocols bgp neighbor 192.0.2.43 'disable-connected-check'
# set protocols bgp neighbor 192.0.2.43 timers holdtime '30'
# set protocols bgp neighbor 192.0.2.43 timers keepalive '10'
# set protocols bgp neighbor 203.0.113.0 address-family 'ipv6-unicast'
# set protocols bgp neighbor 203.0.113.0 capability orf prefix-list 'receive'
# set protocols bgp network 203.0.113.0/24 route-map 'map01'
# set protocols bgp parameters 'always-compare-med'
# set protocols bgp parameters bestpath as-path 'confed'
# set protocols bgp parameters bestpath 'compare-routerid'
# set protocols bgp parameters dampening half-life '33'
# set protocols bgp parameters dampening max-suppress-time '20'
# set protocols bgp parameters dampening re-use '60'
# set protocols bgp parameters dampening start-suppress-time '5'
# set protocols bgp parameters default 'no-ipv4-unicast'
# set protocols bgp parameters distance global external '66'
# set protocols bgp parameters distance global internal '20'
# set protocols bgp parameters distance global local '10'
# set protocols bgp redistribute static route-map 'map01'

- name: parse configs
  vyos.vyos.vyos_bgp_global:
    running_config: "{{ lookup('file', './parsed.cfg') }}"
    state: parsed
  tags:
    - parsed

# Module execution:
# "parsed": {
#         "as_number": 65536,
#         "bgp_params": {
#             "always_compare_med": true,
#             "bestpath": {
#                 "as_path": "confed",
#                 "compare_routerid": true
#             },
#             "default": {
#                 "no_ipv4_unicast": true
#             },
#             "distance": [
#                 {
#                     "type": "external",
#                     "value": 66
#                 },
#                 {
#                     "type": "internal",
#                     "value": 20
#                 },
#                 {
#                     "type": "local",
#                     "value": 10
#                 }
#             ]
#         },
#         "neighbor": [
#             {
#                 "address": "192.0.2.43",
#                 "advertisement_interval": 72,
#                 "capability": {
#                     "dynamic": true
#                 },
#                 "disable_connected_check": true,
#                 "timers": {
#                     "holdtime": 30,
#                     "keepalive": 10
#                 }
#             },
#             {
#                 "address": "203.0.113.0",
#                 "capability": {
#                     "orf": "receive"
#                 }
#             }
#         ],
#         "network": [
#             {
#                 "address": "203.0.113.0/24",
#                 "route_map": "map01"
#             }
#         ],
#         "redistribute": [
#             {
#                 "protocol": "static",
#                 "route_map": "map01"
#             }
#         ]
#     }
#

# Using rendered:
# --------------

- name: Render
  vyos.vyos.vyos_bgp_global:
    config:
      as_number: "65536"
      network:
        - address: "203.0.113.0/24"
          route_map: map01
      redistribute:
        - protocol: "static"
          route_map: "map01"
      bgp_params:
        always_compare_med: true
        dampening:
          start_suppress_time: 5
          max_suppress_time: 20
          half_life: 33
          re_use: 60
        distance:
          - type: "internal"
            value: 20
          - type: "local"
            value: 10
          - type: "external"
            value: 66
        bestpath:
          as_path: "confed"
          compare_routerid: true
        default:
          no_ipv4_unicast: true
      neighbor:
        - address: "192.0.2.43"
          disable_connected_check: true
          advertisement_interval: 72
          capability:
            dynamic: true
          timers:
            holdtime: 30
            keepalive: 10
        - address: "203.0.113.0"
          capability:
            orf: "receive"
    state: rendered

# Module Execution:
# "rendered": [
#         "set protocols bgp neighbor 192.0.2.43 disable-connected-check",
#         "set protocols bgp neighbor 192.0.2.43 advertisement-interval 72",
#         "set protocols bgp neighbor 192.0.2.43 capability dynamic",
#         "set protocols bgp neighbor 192.0.2.43 timers holdtime 30",
#         "set protocols bgp neighbor 192.0.2.43 timers keepalive 10",
#         "set protocols bgp neighbor 203.0.113.0 capability orf prefix-list receive",
#         "set protocols bgp redistribute static route-map map01",
#         "set protocols bgp network 203.0.113.0/24 route-map map01",
#         "set protocols bgp parameters always-compare-med",
#         "set protocols bgp parameters dampening half-life 33",
#         "set protocols bgp parameters dampening max-suppress-time 20",
#         "set protocols bgp parameters dampening re-use 60",
#         "set protocols bgp parameters dampening start-suppress-time 5",
#         "set protocols bgp parameters distance global internal 20",
#         "set protocols bgp parameters distance global local 10",
#         "set protocols bgp parameters distance global external 66",
#         "set protocols bgp parameters bestpath as-path confed",
#         "set protocols bgp parameters bestpath compare-routerid",
#         "set protocols bgp parameters default no-ipv4-unicast"
#     ]
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
    - set protocols bgp redistribute static route-map map01
    - set protocols bgp network 203.0.113.0/24 route-map map01
    - set protocols bgp parameters always-compare-med
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - set protocols bgp redistribute static route-map map01
    - set protocols bgp network 203.0.113.0/24 route-map map01
    - set protocols bgp parameters always-compare-med
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

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.argspec.bgp_global.bgp_global import (
    Bgp_globalArgs,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.config.bgp_global.bgp_global import (
    Bgp_global,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=Bgp_globalArgs.argument_spec,
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

    result = Bgp_global(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
