#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for vyos_bgp_address_family
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: vyos_bgp_address_family
version_added: 1.0.0
short_description: BGP Address Family resource module
description:
- This module manages BGP address family configuration of interfaces on devices running VYOS.
- Tested against VyOS 1.3.8, 1.4.2, the upcoming 1.5, and the rolling release of spring 2025
- The provided examples of commands are valid for VyOS 1.4+
author: Gomathi Selvi Srinivasan (@GomathiselviS)
options:
  config:
    description: A dict of BGP global configuration for interfaces.
    type: dict
    suboptions:
      as_number:
        description:
        - AS number
        type: int
      address_family:
        description: BGP address-family parameters.
        type: list
        elements: dict
        suboptions:
          afi:
            description: BGP address family settings.
            type: str
            choices: ['ipv4', 'ipv6']
          aggregate_address:
            description:
              - BGP aggregate network.
            type: list
            elements: dict
            suboptions:
              prefix:
                description: BGP aggregate network.
                type: str
              as_set:
                description: Generate AS-set path information for this aggregate address.
                type: bool
              summary_only:
                description: Announce the aggregate summary network only.
                type: bool
          networks:
            description: BGP network
            type: list
            elements: dict
            suboptions:
              prefix:
                description: BGP network address
                type: str
              path_limit:
                description: AS path hop count limit
                type: int
              backdoor:
                description: Network as a backdoor route.
                type: bool
              route_map:
                description: Route-map to modify route attributes
                type: str
          redistribute:
            description: Redistribute routes from other protocols into BGP
            type: list
            elements: dict
            suboptions:
              protocol:
                description: types of routes to be redistributed.
                type: str
                choices: ['connected', 'kernel', 'ospf', 'ospfv3', 'rip', 'ripng', 'static']
              table:
                description: Redistribute non-main Kernel Routing Table.
                type: str
              route_map:
                description: Route map to filter redistributed routes
                type: str
              metric:
                description: Metric for redistributed routes.
                type: int
      neighbors:
        description: BGP neighbor
        type: list
        elements: dict
        suboptions:
          neighbor_address:
            description: BGP neighbor address (v4/v6).
            type: str
          address_family:
            description: address family.
            type: list
            elements: dict
            suboptions:
              afi:
                description: BGP neighbor parameters.
                type: str
                choices: ['ipv4', 'ipv6']
              allowas_in:
                description: Number of occurrences of AS number.
                type: int
              as_override:
                description:  AS for routes sent to this neighbor to be the local AS.
                type: bool
              attribute_unchanged:
                description: BGP attributes are sent unchanged.
                type: dict
                suboptions:
                    as_path:
                      description: as_path attribute
                      type: bool
                    med:
                      description: med attribute
                      type: bool
                    next_hop:
                      description: next_hop attribute
                      type: bool
              capability:
                description: Advertise capabilities to this neighbor.
                type: dict
                suboptions:
                  dynamic:
                    description: Advertise dynamic capability to this neighbor.
                    type: bool
                  orf:
                    description: Advertise ORF capability to this neighbor.
                    type: str
                    choices: ['send', 'receive']
              default_originate:
                description: Send default route to this neighbor
                type: str
              distribute_list:
                description:  Access-list to filter route updates to/from this neighbor.
                type: list
                elements: dict
                suboptions:
                  action:
                    description:  Access-list to filter outgoing/incoming route updates to this neighbor
                    type: str
                    choices: ['export', 'import']
                  acl:
                    description: Access-list number.
                    type: int
              filter_list:
                description: As-path-list to filter route updates to/from this neighbor.
                type: list
                elements: dict
                suboptions:
                  action:
                    description: filter outgoing/incoming route updates
                    type: str
                    choices: ['export', 'import']
                  path_list:
                    description: As-path-list to filter
                    type: str
              maximum_prefix:
                description:  Maximum number of prefixes to accept from this neighbor
                   nexthop-self Nexthop for routes sent to this neighbor to be the local router.
                type: int
              nexthop_local:
                description:  Nexthop attributes.
                type: bool
              nexthop_self:
                description:  Nexthop for routes sent to this neighbor to be the local router.
                type: bool
              peer_group:
                description:  IPv4 peer group for this peer
                type: str
              prefix_list:
                description: Prefix-list to filter route updates to/from this neighbor.
                type: list
                elements: dict
                suboptions:
                  action:
                    description: filter outgoing/incoming route updates
                    type: str
                    choices: ['export', 'import']
                  prefix_list:
                    description: Prefix-list to filter
                    type: str
              remove_private_as:
                description: Remove private AS numbers from AS path in outbound route updates
                type: bool
              route_map:
                description: Route-map to filter route updates to/from this neighbor.
                type: list
                elements: dict
                suboptions:
                  action:
                    description: filter outgoing/incoming route updates
                    type: str
                    choices: ['export', 'import']
                  route_map:
                    description: route-map to filter
                    type: str
              route_reflector_client:
                description: Neighbor as a route reflector client
                type: bool
              route_server_client:
                description: Neighbor is route server client
                type: bool
              soft_reconfiguration:
                description: Soft reconfiguration for neighbor
                type: bool
              unsupress_map:
                description:  Route-map to selectively unsuppress suppressed routes
                type: str
              weight:
                description: Default weight for routes from this neighbor
                type: int
  running_config:
    type: str
    description:
    - This option is used only with state I(parsed).
    - The value of this option should be the output received from the VYOS device by
      executing the command B(show configuration command | match bgp).
    - The state I(parsed) reads the configuration from C(running_config) option and
      transforms it into Ansible structured data as per the resource module's argspec
      and the value is then returned in the I(parsed) key within the result.
  state:
    description:
      - The state the configuration should be left in.
    type: str
    choices:
    - merged
    - replaced
    - deleted
    - gathered
    - parsed
    - rendered
    - purged
    - overridden
    default: merged
"""

EXAMPLES = """
# Using merged
# Before state
# vyos@vyos:~$ show configuration commands |  match "set protocols bgp"
# vyos@vyos:~$

- name: Merge provided configuration with device configuration
  vyos.vyos.vyos_bgp_address_family:
    config:
      as_number: "100"
      address_family:
        - afi: "ipv4"
          redistribute:
            - protocol: "static"
              metric: 50
      neighbors:
        - neighbor_address: "20.33.1.1/24"
          address_family:
            - afi: "ipv4"
              allowas_in: 4
              as_override: true
              attribute_unchanged:
                med: true
            - afi: "ipv6"
              default_originate: "map01"
              distribute_list:
                - action: "export"
                  acl: 10
        - neighbor_address: "100.11.34.12"
          address_family:
            - afi: "ipv4"
              maximum_prefix: 45
              nexthop_self: true
              route_map:
                - action: "export"
                  route_map: "map01"
                - action: "import"
                  route_map: "map01"
              weight: 50

# After State:
# vyos@vyos:~$ show configuration commands | match "set protocols bgp"
# set protocols bgp system-as 100
# set protocols bgp address-family ipv4-unicast redistribute static metric '50'
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast allowas-in number '4'
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast as-override
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast attribute-unchanged med
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv6-unicast default-originate route-map 'map01'
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv6-unicast distribute-list export '10'
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast maximum-prefix '45'
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast nexthop-self
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast route-map export 'map01'
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast route-map import 'map01'
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast weight '50'
# vyos@vyos:~$
#
# Module Execution:
#
# "after": {
#         "address_family": [
#             {
#                 "afi": "ipv4",
#                 "redistribute": [
#                     {
#                         "metric": 50,
#                         "protocol": "static"
#                     }
#                 ]
#             }
#         ],
#         "as_number": 100,
#         "neighbors": [
#             {
#                 "address_family": [
#                     {
#                         "afi": "ipv4",
#                         "maximum_prefix": 45,
#                         "nexthop_self": true,
#                         "route_map": [
#                             {
#                                 "action": "export",
#                                 "route_map": "map01"
#                             },
#                             {
#                                 "action": "import",
#                                 "route_map": "map01"
#                             }
#                         ],
#                         "weight": 50
#                     }
#                 ],
#                 "neighbor_address": "100.11.34.12"
#             },
#             {
#                 "address_family": [
#                     {
#                         "afi": "ipv4",
#                         "allowas_in": 4,
#                         "as_override": true,
#                         "attribute_unchanged": {
#                             "med": true
#                         }
#                     },
#                     {
#                         "afi": "ipv6",
#                         "default_originate": "map01",
#                         "distribute_list": [
#                             {
#                                 "acl": 10,
#                                 "action": "export"
#                             }
#                         ]
#                     }
#                 ],
#                 "neighbor_address": "20.33.1.1/24"
#             }
#         ]
#     },
#     "before": {},
#     "changed": true,
#     "commands": [
#         "set protocols bgp address-family ipv4-unicast redistribute static metric 50",
#         "set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast allowas-in number 4",
#         "set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast as-override",
#         "set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast attribute-unchanged med",
#         "set protocols bgp neighbor 20.33.1.1/24 address-family ipv6-unicast default-originate route-map map01",
#         "set protocols bgp neighbor 20.33.1.1/24 address-family ipv6-unicast distribute-list export 10",
#         "set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast maximum-prefix 45",
#         "set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast nexthop-self",
#         "set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast route-map export map01",
#         "set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast route-map import map01",
#         "set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast weight 50"
#     ],
#

# Using replaced:

# Before state:

# vyos@vyos:~$ show configuration commands | match "set protocols bgp"
# set protocols bgp system-as 100
# set protocols bgp address-family ipv4-unicast redistribute static metric '50'
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast allowas-in number '4'
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast as-override
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast attribute-unchanged med
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv6-unicast default-originate route-map 'map01'
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv6-unicast distribute-list export '10'
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast maximum-prefix '45'
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast nexthop-self
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast route-map export 'map01'
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast route-map import 'map01'
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast weight '50'
# vyos@vyos:~$

- name: Replace provided configuration with device configuration
  vyos.vyos.vyos_bgp_address_family:
    config:
      as_number: "100"
      neighbors:
        - neighbor_address: "100.11.34.12"
          address_family:
            - afi: "ipv4"
              allowas_in: 4
              as_override: true
              attribute_unchanged:
                med: true
            - afi: "ipv6"
              default_originate: "map01"
              distribute_list:
                - action: "export"
                  acl: 10
        - neighbor_address: "20.33.1.1/24"
          address_family:
            - afi: "ipv6"
              maximum_prefix: 45
              nexthop_self: true
    state: replaced

# After State:
#
# vyos@vyos:~$ show configuration commands | match "set protocols bgp"
# set protocols bgp system-as 100
# set protocols bgp address-family ipv4-unicast redistribute static metric '50'
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv6-unicast maximum-prefix '45'
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv6-unicast nexthop-self
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast allowas-in number '4'
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast as-override
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast attribute-unchanged med
# set protocols bgp neighbor 100.11.34.12 address-family ipv6-unicast default-originate route-map 'map01'
# set protocols bgp neighbor 100.11.34.12 address-family ipv6-unicast distribute-list export '10'
# vyos@vyos:~$
#
#
# # Module Execution:
# "after": {
#         "address_family": [
#             {
#                 "afi": "ipv4",
#                 "redistribute": [
#                     {
#                         "metric": 50,
#                         "protocol": "static"
#                     }
#                 ]
#             }
#         ],
#         "as_number": 100,
#         "neighbors": [
#             {
#                 "address_family": [
#                     {
#                         "afi": "ipv4",
#                         "allowas_in": 4,
#                         "as_override": true,
#                         "attribute_unchanged": {
#                             "med": true
#                         }
#                     },
#                     {
#                         "afi": "ipv6",
#                         "default_originate": "map01",
#                         "distribute_list": [
#                             {
#                                 "acl": 10,
#                                 "action": "export"
#                             }
#                         ]
#                     }
#                 ],
#                 "neighbor_address": "100.11.34.12"
#             },
#             {
#                 "address_family": [
#                     {
#                         "afi": "ipv4"
#                     },
#                     {
#                         "afi": "ipv6",
#                         "maximum_prefix": 45,
#                         "nexthop_self": true
#                     }
#                 ],
#                 "neighbor_address": "20.33.1.1/24"
#             }
#         ]
#     },
#     "before": {
#         "address_family": [
#             {
#                 "afi": "ipv4",
#                 "redistribute": [
#                     {
#                         "metric": 50,
#                         "protocol": "static"
#                     }
#                 ]
#             }
#         ],
#         "as_number": 100,
#         "neighbors": [
#             {
#                 "address_family": [
#                     {
#                         "afi": "ipv4",
#                         "maximum_prefix": 45,
#                         "nexthop_self": true,
#                         "route_map": [
#                             {
#                                 "action": "export",
#                                 "route_map": "map01"
#                             },
#                             {
#                                 "action": "import",
#                                 "route_map": "map01"
#                             }
#                         ],
#                         "weight": 50
#                     }
#                 ],
#                 "neighbor_address": "100.11.34.12"
#             },
#             {
#                 "address_family": [
#                     {
#                         "afi": "ipv4",
#                         "allowas_in": 4,
#                         "as_override": true,
#                         "attribute_unchanged": {
#                             "med": true
#                         }
#                     },
#                     {
#                         "afi": "ipv6",
#                         "default_originate": "map01",
#                         "distribute_list": [
#                             {
#                                 "acl": 10,
#                                 "action": "export"
#                             }
#                         ]
#                     }
#                 ],
#                 "neighbor_address": "20.33.1.1/24"
#             }
#         ]
#     },
#     "changed": true,
#     "commands": [
#         "delete protocols bgp neighbor 20.33.1.1/24 address-family ipv6-unicast distribute-list",
#         "delete protocols bgp neighbor 20.33.1.1/24 address-family ipv6-unicast default-originate",
#         "delete protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast attribute-unchanged",
#         "delete protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast as-override",
#         "delete protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast allowas-in",
#         "delete protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast weight",
#         "delete protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast route-map",
#         "delete protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast nexthop-self",
#         "delete protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast maximum-prefix",
#         "set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast allowas-in number 4",
#         "set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast as-override",
#         "set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast attribute-unchanged med",
#         "set protocols bgp neighbor 100.11.34.12 address-family ipv6-unicast default-originate route-map map01",
#         "set protocols bgp neighbor 100.11.34.12 address-family ipv6-unicast distribute-list export 10",
#         "set protocols bgp neighbor 20.33.1.1/24 address-family ipv6-unicast maximum-prefix 45",
#         "set protocols bgp neighbor 20.33.1.1/24 address-family ipv6-unicast nexthop-self"
#     ],


# Using overridden
# vyos@vyos:~$ show configuration commands | match "set protocols bgp"
# set protocols bgp system-as 100
# set protocols bgp address-family ipv4-unicast network 35.1.1.0/24 backdoor
# set protocols bgp address-family ipv4-unicast redistribute static metric '50'
# set protocols bgp address-family ipv6-unicast aggregate-address 6601:1:1:1::/64 summary-only
# set protocols bgp address-family ipv6-unicast network 5001:1:1:1::/64 route-map 'map01'
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv6-unicast maximum-prefix '45'
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv6-unicast nexthop-self
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast allowas-in number '4'
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast as-override
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast attribute-unchanged med
# set protocols bgp neighbor 100.11.34.12 address-family ipv6-unicast default-originate route-map 'map01'
# set protocols bgp neighbor 100.11.34.12 address-family ipv6-unicast distribute-list export '10'
# vyos@vyos:~$

- name: Override
  vyos.vyos.vyos_bgp_address_family:
    config:
      as_number: "100"
      neighbors:
        - neighbor_address: "100.11.34.12"
          address_family:
            - afi: "ipv6"
              maximum_prefix: 45
              nexthop_self: true
              route_map:
                - action: "import"
                  route_map: "map01"
      address_family:
        - afi: "ipv4"
          aggregate_address:
            - prefix: "60.9.2.0/24"
              summary_only: true
        - afi: "ipv6"
          redistribute:
            - protocol: "static"
              metric: 50
    state: overridden

# After State

# vyos@vyos:~$ show configuration commands | match "set protocols bgp"
# set protocols bgp system-as 100
# set protocols bgp address-family ipv4-unicast aggregate-address 60.9.2.0/24 summary-only
# set protocols bgp address-family ipv6-unicast redistribute static metric '50'
# set protocols bgp neighbor 20.33.1.1/24
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast
# set protocols bgp neighbor 100.11.34.12 address-family ipv6-unicast maximum-prefix '45'
# set protocols bgp neighbor 100.11.34.12 address-family ipv6-unicast nexthop-self
# set protocols bgp neighbor 100.11.34.12 address-family ipv6-unicast route-map import 'map01'
# vyos@vyos:~$


# Module Execution:

# "after": {
#         "address_family": [
#             {
#                 "afi": "ipv4",
#                 "aggregate_address": [
#                     {
#                         "prefix": "60.9.2.0/24",
#                         "summary_only": true
#                     }
#                 ]
#             },
#             {
#                 "afi": "ipv6",
#                 "redistribute": [
#                     {
#                         "metric": 50,
#                         "protocol": "static"
#                     }
#                 ]
#             }
#         ],
#         "as_number": 100,
#         "neighbors": [
#             {
#                 "address_family": [
#                     {
#                         "afi": "ipv4"
#                     },
#                     {
#                         "afi": "ipv6",
#                         "maximum_prefix": 45,
#                         "nexthop_self": true,
#                         "route_map": [
#                             {
#                                 "action": "import",
#                                 "route_map": "map01"
#                             }
#                         ]
#                     }
#                 ],
#                 "neighbor_address": "100.11.34.12"
#             }
#         ]
#     },
#     "before": {
#         "address_family": [
#             {
#                 "afi": "ipv4",
#                 "networks": [
#                     {
#                         "backdoor": true,
#                         "prefix": "35.1.1.0/24"
#                     }
#                 ],
#                 "redistribute": [
#                     {
#                         "metric": 50,
#                         "protocol": "static"
#                     }
#                 ]
#             },
#             {
#                 "afi": "ipv6",
#                 "aggregate_address": [
#                     {
#                         "prefix": "6601:1:1:1::/64",
#                         "summary_only": true
#                     }
#                 ],
#                 "networks": [
#                     {
#                         "prefix": "5001:1:1:1::/64",
#                         "route_map": "map01"
#                     }
#                 ]
#             }
#         ],
#         "as_number": 100,
#         "neighbors": [
#             {
#                 "address_family": [
#                     {
#                         "afi": "ipv4",
#                         "allowas_in": 4,
#                         "as_override": true,
#                         "attribute_unchanged": {
#                             "med": true
#                         }
#                     },
#                     {
#                         "afi": "ipv6",
#                         "default_originate": "map01",
#                         "distribute_list": [
#                             {
#                                 "acl": 10,
#                                 "action": "export"
#                             }
#                         ]
#                     }
#                 ],
#                 "neighbor_address": "100.11.34.12"
#             },
#             {
#                 "address_family": [
#                     {
#                         "afi": "ipv4"
#                     },
#                     {
#                         "afi": "ipv6",
#                         "maximum_prefix": 45,
#                         "nexthop_self": true
#                     }
#                 ],
#                 "neighbor_address": "20.33.1.1/24"
#             }
#         ]
#     },
#     "changed": true,
#     "commands": [
#         "delete protocols bgp neighbor 20.33.1.1/24 address-family",
#         "delete protocols bgp neighbor 100.11.34.12 address-family ipv6-unicast distribute-list",
#         "delete protocols bgp neighbor 100.11.34.12 address-family ipv6-unicast default-originate",
#         "delete protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast attribute-unchanged",
#         "delete protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast as-override",
#         "delete protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast allowas-in",
#         "delete protocols bgp address-family ipv6 aggregate-address",
#         "delete protocols bgp address-family ipv6 network",
#         "delete protocols bgp address-family ipv4 network",
#         "delete protocols bgp address-family ipv4 redistribute",
#         "set protocols bgp address-family ipv4-unicast aggregate-address 60.9.2.0/24 summary-only",
#         "set protocols bgp address-family ipv6-unicast redistribute static metric 50",
#         "set protocols bgp neighbor 100.11.34.12 address-family ipv6-unicast maximum-prefix 45",
#         "set protocols bgp neighbor 100.11.34.12 address-family ipv6-unicast nexthop-self",
#         "set protocols bgp neighbor 100.11.34.12 address-family ipv6-unicast route-map import map01"
#     ],
#

# Using deleted:

# Before State:

# vyos@vyos:~$ show configuration commands | match "set protocols bgp"
# set protocols bgp system-as 100
# set protocols bgp address-family ipv4-unicast aggregate-address 60.9.2.0/24 summary-only
# set protocols bgp address-family ipv4-unicast redistribute static metric '50'
# set protocols bgp address-family ipv6-unicast redistribute static metric '50'
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast allowas-in number '4'
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast as-override
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast attribute-unchanged med
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv6-unicast default-originate route-map 'map01'
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv6-unicast distribute-list export '10'
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast maximum-prefix '45'
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast nexthop-self
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast route-map export 'map01'
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast route-map import 'map01'
# set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast weight '50'
# set protocols bgp neighbor 100.11.34.12 address-family ipv6-unicast maximum-prefix '45'
# set protocols bgp neighbor 100.11.34.12 address-family ipv6-unicast nexthop-self
# set protocols bgp neighbor 100.11.34.12 address-family ipv6-unicast route-map import 'map01'
# vyos@vyos:~$

- name: Delete
  vyos.vyos.vyos_bgp_address_family:
    config:
      as_number: "100"
      neighbors:
        - neighbor_address: "20.33.1.1/24"
          address_family:
            - afi: "ipv6"
        - neighbor_address: "100.11.34.12"
      address_family:
        - afi: "ipv4"
    state: deleted


# After State:

# vyos@vyos:~$ show configuration commands | match "set protocols bgp"
# set protocols bgp system-as 100
# set protocols bgp address-family ipv6-unicast redistribute static metric '50'
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast allowas-in number '4'
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast as-override
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast attribute-unchanged med
# set protocols bgp neighbor 100.11.34.12
# vyos@vyos:~$
#
#
# Module Execution:
#
# "after": {
#         "address_family": [
#             {
#                 "afi": "ipv6",
#                 "redistribute": [
#                     {
#                         "metric": 50,
#                         "protocol": "static"
#                     }
#                 ]
#             }
#         ],
#         "as_number": 100,
#         "neighbors": [
#             {
#                 "address_family": [
#                     {
#                         "afi": "ipv4",
#                         "allowas_in": 4,
#                         "as_override": true,
#                         "attribute_unchanged": {
#                             "med": true
#                         }
#                     }
#                 ],
#                 "neighbor_address": "20.33.1.1/24"
#             }
#         ]
#     },
#     "before": {
#         "address_family": [
#             {
#                 "afi": "ipv4",
#                 "aggregate_address": [
#                     {
#                         "prefix": "60.9.2.0/24",
#                         "summary_only": true
#                     }
#                 ],
#                 "redistribute": [
#                     {
#                         "metric": 50,
#                         "protocol": "static"
#                     }
#                 ]
#             },
#             {
#                 "afi": "ipv6",
#                 "redistribute": [
#                     {
#                         "metric": 50,
#                         "protocol": "static"
#                     }
#                 ]
#             }
#         ],
#         "as_number": 100,
#         "neighbors": [
#             {
#                 "address_family": [
#                     {
#                         "afi": "ipv4",
#                         "maximum_prefix": 45,
#                         "nexthop_self": true,
#                         "route_map": [
#                             {
#                                 "action": "export",
#                                 "route_map": "map01"
#                             },
#                             {
#                                 "action": "import",
#                                 "route_map": "map01"
#                             }
#                         ],
#                         "weight": 50
#                     },
#                     {
#                         "afi": "ipv6",
#                         "maximum_prefix": 45,
#                         "nexthop_self": true,
#                         "route_map": [
#                             {
#                                 "action": "import",
#                                 "route_map": "map01"
#                             }
#                         ]
#                     }
#                 ],
#                 "neighbor_address": "100.11.34.12"
#             },
#             {
#                 "address_family": [
#                     {
#                         "afi": "ipv4",
#                         "allowas_in": 4,
#                         "as_override": true,
#                         "attribute_unchanged": {
#                             "med": true
#                         }
#                     },
#                     {
#                         "afi": "ipv6",
#                         "default_originate": "map01",
#                         "distribute_list": [
#                             {
#                                 "acl": 10,
#                                 "action": "export"
#                             }
#                         ]
#                     }
#                 ],
#                 "neighbor_address": "20.33.1.1/24"
#             }
#         ]
#     },
#     "changed": true,
#     "commands": [
#         "delete protocols bgp address-family ipv4-unicast",
#         "delete protocols bgp neighbor 20.33.1.1/24 address-family ipv6-unicast",
#         "delete protocols bgp neighbor 100.11.34.12 address-family"
#     ],
#

# using parsed:

# parsed.cfg
# set protocols bgp 65536 address-family ipv4-unicast aggregate-address 192.0.2.0/24 as-set
# set protocols bgp 65536 address-family ipv4-unicast network 192.1.13.0/24 route-map 'map01'
# set protocols bgp 65536 address-family ipv4-unicast network 192.2.13.0/24 backdoor
# set protocols bgp 65536 address-family ipv6-unicast redistribute ripng metric '20'
# set protocols bgp 65536 neighbor 192.0.2.25 address-family ipv4-unicast route-map export 'map01'
# set protocols bgp 65536 neighbor 192.0.2.25 address-family ipv4-unicast soft-reconfiguration inbound
# set protocols bgp 65536 neighbor 203.0.113.5 address-family ipv6-unicast attribute-unchanged next-hop


- name: parse configs
  vyos.vyos.vyos_bgp_address_family:
    running_config: "{{ lookup('file', './parsed.cfg') }}"
    state: parsed

# Module execution result:
#
# "parsed": {
#         "address_family": [
#             {
#                 "afi": "ipv4",
#                 "aggregate_address": [
#                     {
#                         "as_set": true,
#                         "prefix": "192.0.2.0/24"
#                     }
#                 ],
#                 "networks": [
#                     {
#                         "prefix": "192.1.13.0/24",
#                         "route_map": "map01"
#                     },
#                     {
#                         "backdoor": true,
#                         "prefix": "192.2.13.0/24"
#                     }
#                 ]
#             },
#             {
#                 "afi": "ipv6",
#                 "redistribute": [
#                     {
#                         "metric": 20,
#                         "protocol": "ripng"
#                     }
#                 ]
#             }
#         ],
#         "as_number": 65536,
#         "neighbors": [
#             {
#                 "address_family": [
#                     {
#                         "afi": "ipv4",
#                         "route_map": [
#                             {
#                                 "action": "export",
#                                 "route_map": "map01"
#                             }
#                         ],
#                         "soft_reconfiguration": true
#                     }
#                 ],
#                 "neighbor_address": "192.0.2.25"
#             },
#             {
#                 "address_family": [
#                     {
#                         "afi": "ipv6",
#                         "attribute_unchanged": {
#                             "next_hop": true
#                         }
#                     }
#                 ],
#                 "neighbor_address": "203.0.113.5"
#             }
#         ]
#

# Using gathered:

# Native config:

# vyos@vyos:~$ show configuration commands | match "set protocols bgp"
# set protocols bgp system-as 100
# set protocols bgp address-family ipv4-unicast network 35.1.1.0/24 backdoor
# set protocols bgp address-family ipv4-unicast redistribute static metric '50'
# set protocols bgp address-family ipv6-unicast aggregate-address 6601:1:1:1::/64 summary-only
# set protocols bgp address-family ipv6-unicast network 5001:1:1:1::/64 route-map 'map01'
# set protocols bgp address-family ipv6-unicast redistribute static metric '50'
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast allowas-in number '4'
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast as-override
# set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast attribute-unchanged med
# set protocols bgp neighbor 100.11.34.12

- name: gather configs
  vyos.vyos.vyos_bgp_address_family:
    state: gathered

# Module execution result:
#
# "gathered": {
#         "address_family": [
#             {
#                 "afi": "ipv4",
#                 "networks": [
#                     {
#                         "backdoor": true,
#                         "prefix": "35.1.1.0/24"
#                     }
#                 ],
#                 "redistribute": [
#                     {
#                         "metric": 50,
#                         "protocol": "static"
#                     }
#                 ]
#             },
#             {
#                 "afi": "ipv6",
#                 "aggregate_address": [
#                     {
#                         "prefix": "6601:1:1:1::/64",
#                         "summary_only": true
#                     }
#                 ],
#                 "networks": [
#                     {
#                         "prefix": "5001:1:1:1::/64",
#                         "route_map": "map01"
#                     }
#                 ],
#                 "redistribute": [
#                     {
#                         "metric": 50,
#                         "protocol": "static"
#                     }
#                 ]
#             }
#         ],
#         "as_number": 100,
#         "neighbors": [
#             {
#                 "address_family": [
#                     {
#                         "afi": "ipv4",
#                         "allowas_in": 4,
#                         "as_override": true,
#                         "attribute_unchanged": {
#                             "med": true
#                         }
#                     }
#                 ],
#                 "neighbor_address": "20.33.1.1/24"
#             }
#         ]

# Using rendered:

- name: Render
  vyos.vyos.vyos_bgp_address_family:
    config:
      as_number: "100"
      address_family:
        - afi: "ipv4"
          redistribute:
            - protocol: "static"
              metric: 50
      neighbors:
        - neighbor_address: "20.33.1.1/24"
          address_family:
            - afi: "ipv4"
              allowas_in: 4
              as_override: true
              attribute_unchanged:
                med: true
            - afi: "ipv6"
              default_originate: "map01"
              distribute_list:
                - action: "export"
                  acl: 10
        - neighbor_address: "100.11.34.12"
          address_family:
            - afi: "ipv4"
              maximum_prefix: 45
              nexthop_self: true
              route_map:
                - action: "export"
                  route_map: "map01"
                - action: "import"
                  route_map: "map01"
              weight: 50
    state: rendered

# Module Execution:

# "rendered": [
#         "set protocols bgp address-family ipv4-unicast redistribute static metric 50",
#         "set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast allowas-in number 4",
#         "set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast as-override",
#         "set protocols bgp neighbor 20.33.1.1/24 address-family ipv4-unicast attribute-unchanged med",
#         "set protocols bgp neighbor 20.33.1.1/24 address-family ipv6-unicast default-originate route-map map01",
#         "set protocols bgp neighbor 20.33.1.1/24 address-family ipv6-unicast distribute-list export 10",
#         "set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast maximum-prefix 45",
#         "set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast nexthop-self",
#         "set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast route-map export map01",
#         "set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast route-map import map01",
#         "set protocols bgp neighbor 100.11.34.12 address-family ipv4-unicast weight 50"
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
    - sample command 1
    - sample command 2
    - sample command 3
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - sample command 1
    - sample command 2
    - sample command 3
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

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.argspec.bgp_address_family.bgp_address_family import (
    Bgp_address_familyArgs,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.config.bgp_address_family.bgp_address_family import (
    Bgp_address_family,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=Bgp_address_familyArgs.argument_spec,
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

    result = Bgp_address_family(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
