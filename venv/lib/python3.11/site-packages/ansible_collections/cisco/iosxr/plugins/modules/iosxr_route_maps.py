#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for iosxr_route_maps
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: iosxr_route_maps
short_description: Resource module to configure route maps.
description:
  - This module configures and manages the attributes of Route maps on Cisco IOSXR.
version_added: 10.2.0
author: Sagar Paul (@KB-perByte)
notes:
  - Tested against Cisco IOS-XR 7.2.2.
  - This module works with connection C(network_cli).
options:
  config:
    description: A list of configurations for route policy.
    type: list
    elements: dict
    suboptions:
      name:
        description: Name of the route policy.
        type: str
      global: &global
        description: A dictionary of configurations for route policy without any conditions
        type: dict
        suboptions:
          add: &add
            description: Add offset to the existing value
            type: dict
            suboptions:
              eigrp_metric:
                description: EIGRP metric attribute
                type: dict
                suboptions:
                  bandwidth:
                    description: <0-4294967295> Bandwidth in Kbits per second
                    type: int
                  delay:
                    description: <0-4294967295> Delay metric in 10 microsecond units
                    type: int
                  reliability:
                    description: <0-255> Reliability metric where 255 is 100% reliable
                    type: int
                  effective_bandwith:
                    type: int
                    description: <0-255> Effective bandwidth metric (Loading) where 255 is 100% loaded
                  max_transmission:
                    description: <0-65535> Maximum Transmission Unit metric of the path
                    type: int
              rip_metric:
                description: <0-16> RIP metric attribute
                type: int
          apply: &apply
            description: Apply a route policy
            type: list
            elements: dict
            suboptions:
              route_policy:
                type: str
                description: Apply a specific route policy
              route_policy_input:
                type: str
                description: ipv4/ ipv6 / name-string
          drop: &drop
            type: bool
            description: Reject this route with no further processing
          pass: &pass
            type: bool
            description: Pass this route for further processing
          prepend: &prepend
            description: Prepend to BGP AS-path
            type: dict
            suboptions:
              number_of_times:
                type: int
                description: number of times to prepend
              as_path:
                type: int
                description: <1-4294967295> 32-bit decimal number/ 16-bit decimal number as-path
              most_recent:
                type: bool
                description: Most recent Autonomous System Number
              own_as:
                type: bool
                description: Local Autonomous System Number
          suppress_route: &suppess
            type: bool
            description: Suppress specific routes when aggregating
          unsuppress_route: &unsuppess
            type: bool
            description: Unsuppress specific aggregated routes
          remove: &remove
            description: Remove all private-as entries
            type: dict
            suboptions:
              set:
                type: bool
                description: Remove all private-as entries (remove as-path private-as)
              entire_aspath:
                type: bool
                description: Remove private-AS from entire aspath
          set: &set
            description: Set a route attribute
            type: dict
            suboptions:
              administrative_distance:
                description: Administrative Distance of the prefix, <1-255> 8 bit decimal numbe
                type: int
              local_preference:
                description: List of local preference configurations
                type: list
                elements: dict
                suboptions:
                  increment:
                    type: bool
                    description: "+ Increment the attribute with specified value"
                  decrement:
                    description: "- Decrement the attribute by specified value"
                    type: bool
                  metric_number:
                    description: "<0-4294967295> 32-bit decimal number"
                    type: int
                    required: true
                  multiply:
                    description: "* multiply the attribute by specified value"
                    type: bool
              aigp_metric:
                description: AIGP metric attribute
                type: dict
                suboptions:
                  icrement:
                    type: bool
                    description: "+ Increment the attribute with specified value"
                  decrement:
                    description: "- Decrement the attribute by specified value"
                    type: bool
                  metric_number:
                    description: <0-4294967295>  32-bit decimal number
                    type: int
                  igp_cost:
                    description: Internal routing protocol cost
                    type: bool
              attribute_set:
                description: TE attribute-set name <0-4294967295> 32-bit decimal number
                type: str
              c_multicast_routing:
                description: Multicast Customer routing type
                type: dict
                suboptions:
                  bgp:
                    type: bool
                    description: BGP customer-multicast routing
                  pim:
                    type: bool
                    description: PIM customer-multicast routing
              community:
                description: BGP community attribute
                type: dict
                suboptions:
                  community_name:
                    type: str
                    description: Community set name
                  additive:
                    type: bool
                    description: Add to the existing community
              core_tree:
                description: Multicast Distribution Tree type
                type: dict
                suboptions:
                  ingress_replication:
                    type: bool
                    description: Ingress Replication core segment
                  ingress_replication_default:
                    type: bool
                    description: Ingress Replication Default MDT core
                  ingress_replication_partitioned:
                    type: bool
                    description: Ingress Replication Partitioned MDT core
                  mldp:
                    type: bool
                    description: MLDP core segment
                  mldp_default:
                    type: bool
                    description: MLDP Default MDT core
                  mldp_inband:
                    type: bool
                    description: MLDP Inband core
                  mldp_partitioned_mp2mp:
                    type: bool
                    description: MLDP Partitioned MP2MP MDT core
                  mldp_partitioned_p2mp:
                    type: bool
                    description: MLDP Partitioned P2MP MDT core
                  p2mp_te:
                    type: bool
                    description: P2MP TE core segment
                  p2mp_te_default:
                    type: bool
                    description: P2MP TE Default MDT core
                  p2mp_te_partitioned:
                    type: bool
                    description: P2MP TE Partitioned MDT core
                  pim_default:
                    type: bool
                    description: PIM Default MDT core
                  sr_p2mp:
                    type: bool
                    description: Segment-Routing P2MP core
              dampening:
                description: BGP route flap dampening parameters
                type: dict
                suboptions:
                  halflife:
                    type: int
                    description: Dampening penalty half-life, <1-45> Half-life time for penalty, default 15
                  max_suppress:
                    type: int
                    description: Maximum dampening penalty, <1-255> Maximum dampening penalty time, default 60
                  reuse:
                    type: int
                    description: Penalty before reusing suppressed route, <1-20000> Dampening reuse threshold, default 750
                  suppress:
                    type: int
                    description: Dampening penalty to start suppressing a route, <1-20000>  Suppress penalty threshold, default 2000
              downstream_core_tree:
                description: BGP I-PMSI/S-PMSI core tree type
                type: dict
                suboptions:
                  ingress_replication:
                    type: bool
                    description: Ingress Replication core segment
                  mldp:
                    type: bool
                    description: MLDP core segment
                  p2mp_te:
                    type: bool
                    description: P2MP TE core segment
                  sr_p2mp:
                    type: bool
                    description: Segment-Routing P2MP core
              eigrp_metric:
                description: EIGRP metric attribute
                type: dict
                suboptions:
                  bandwidth:
                    description: <0-4294967295> Bandwidth in Kbits per second
                    type: int
                  delay:
                    description: <0-4294967295> Delay metric in 10 microsecond units
                    type: int
                  reliability:
                    description: <0-255> Reliability metric where 255 is 100% reliable
                    type: int
                  effective_bandwith:
                    type: int
                    description: <0-255> Effective bandwidth metric (Loading) where 255 is 100% loaded
                  max_transmission:
                    description: <0-65535> Maximum Transmission Unit metric of the path
                    type: int
              extcommunity:
                description: BGP extended community attribute
                type: dict
                suboptions:
                  soo:
                    description: Sub-OR-Organization
                    type: str
                  rt:
                    description: Route Target
                    type: str
                  bandwidth:
                    description: Bandwidth
                    type: str
                  color:
                    description: Color
                    type: str
                  cost:
                    description: Cost
                    type: str
                  redirect_to_rt:
                    description: Redirect to Route Target
                    type: str
                  seg_nh:
                    description: Segment Next Hop
                    type: str
                  additive:
                    description: Additive
                    type: bool
              fallback_vrf_lookup:
                description: fallback vrf look-up
                type: bool
              flow_tag:
                description: flow tag value for PBR BGP flow-tag, <1-63> 6 bit decimal number starting from 1
                type: int
              forward_class:
                description: Forward class (default value 0), <1-7> 3 bit decimal number starting from 1
                type: int
              ip_precedence:
                description: IP Precedence to classify packets, <1-7> 3 bit decimal number starting from 1
                type: int
              isis_metric:
                description: IS-IS metric attribute, <0-16777215> 24 bit decimal number
                type: int
              label:
                description: Set BGP label value, <0-1048575> 20 bit decimal number
                type: int
              label_index:
                description: Set Segment Routing label-index value, <0-1048575>  20 bit decimal number
                type: int
              label_mode:
                description: Set BGP label-mode value
                type: dict
                suboptions:
                  per_ce:
                    type: bool
                    description: Set the label mode to per-ce
                  per_prefix:
                    type: bool
                    description: Set the label mode to per-prefix
                  per_vrf:
                    type: bool
                    description: Set the label mode to per-vrf
              large_community:
                description: BGP large community attribute
                type: str
              level:
                description: Where to import route
                type: dict
                suboptions:
                  level_1:
                    type: bool
                    description: IS-IS level-1 routes
                  level_1_2:
                    type: bool
                    description: IS-IS level-1 and level-2 routes
                  level_2:
                    type: bool
                    description: IS-IS level-2 routes
              load_balance:
                description: Load-balance for ECMP ecmp-consistent
                type: bool
              lsm_root:
                description: Label Switched Multicast Root address
                type: str
              metric_type:
                description: Type of metric for destination routing protocol
                type: dict
                suboptions:
                  external:
                    type: bool
                    description: ISIS external metric-type
                  internal:
                    type: bool
                    description: ISIS internal metric-type
                  rib_metric_as_external:
                    type: bool
                    description: Use RIB metric and set ISIS external metric-type
                  rib_metric_as_internal:
                    type: bool
                    description: Use RIB metric and set ISIS internal metric-type
                  type_1:
                    type: bool
                    description: OSPF type-1 route
                  type_2:
                    type: bool
                    description: OSPF type-2 route
              mpls:
                description: MPLS traffic-eng attributeset name-string
                type: str
              med:
                description: Metric for Equal-Cost Multi-Path
                type: dict
                suboptions:
                  value:
                    description: Metric value
                    type: int
                  increment:
                    description: Increment the metric value
                    type: int
                  decrement:
                    description: Decrement the metric value
                    type: int
                  igp_cost:
                    description: Use IGP metric
                    type: bool
                  max_reachable:
                    description: Use maximum reachable metric
                    type: bool
                  parameter:
                    description: Parameter
                    type: str
              next_hop:
                description: Next hop address specified in this route
                type: dict
                suboptions:
                  address:
                    type: str
                    description: next hop address
              origin:
                description: BGP origin code
                type: dict
                suboptions:
                  egp:
                    type: bool
                    description: ISIS external metric-type
                  igp:
                    type: bool
                    description: ISIS internal metric-type
                  rincomplete:
                    type: bool
                    description: Use RIB metric and set ISIS external metric-type
              ospf_metric:
                description: OSPF metric attribute
                type: int
              path_selection:
                description: BGP path selection
                type: dict
                suboptions:
                  all:
                    type: bool
                    description: BGP all advertise
                  backup:
                    description: BGP backup
                    type: dict
                    suboptions:
                      backup_decimal:
                        type: int
                        description: <1>, decimal number 1
                      advertise:
                        type: bool
                        description: Advertise the path
                      install:
                        type: bool
                        description: Install the path
                  best_path:
                    type: bool
                    description: BGP best path
                  group_best:
                    type: bool
                    description: BGP group-best advertise
                  multiplath:
                    type: bool
                    description: BGP multipath advertise
              path_color:
                description: BGP Path Color for RIB (path-color external-reach)
                type: bool
              qos_group:
                description: QoS Group to classify packets
                type: int
              rib_metric:
                description: RIB metric for table-policy
                type: int
              rip_metric:
                description: RIP metric attribute
                type: int
              rip_tag:
                description: RIP Route tag attribute
                type: int
              rt_set:
                description: Limit on routes with paths with an RT-set
                type: int
              s_pmsi:
                description: S-PMSI Advertisement type (star-g)
                type: bool
              spf_priority:
                description: OSPF SPF priority
                type: dict
                suboptions:
                  critical:
                    type: bool
                    description: Critical priority
                  high:
                    type: bool
                    description: High priority
                  medium:
                    type: bool
                    description: Medium priority
              static_p2mp_te:
                description: Static P2MP-TE tunnel
                type: str
              tag:
                description: Route tag attribute
                type: int
              traffic_index:
                description: Traffic-index for BGP policy accounting
                type: dict
                suboptions:
                  index_number:
                    type: int
                    description: 6 bit decimal number starting from 1 <1-63>
                  ignore:
                    type: bool
                    description: Remove any traffic-index setting
              upstream_core_tree:
                description: BGP Leaf AD core tree type
                type: dict
                suboptions:
                  ingress_replication:
                    type: bool
                    description: Ingress Replication core segment
                  mldp:
                    type: bool
                    description: MLDP core segment
                  p2mp_te:
                    type: bool
                    description: P2MP TE core segment
                  sr_p2mp:
                    type: bool
                    description: Segment-Routing P2MP core
              vpn_distinguisher:
                description: BGP VPN distinguisher (VD) attribute
                type: int
              weight:
                description: Weight attribute for route selection
                type: int
      if_section:
        description: A dictionary of configurations for route policy for the top level if condition for the policy
        type: dict
        suboptions: &ifcondition
          condition:
            type: str
            description:
              - the condition string, eg - aigp-metric eq 23 and as-path in tmp1 and
                community is-empty and community matches-any test1 (don't add then at end)
          add: *add
          apply: *apply
          drop: *drop
          pass: *pass
          prepend: *prepend
          suppress_route: *suppess
          unsuppress_route: *unsuppess
          remove: *remove
          set: *set
      elseif_section: &elifmodel
        description: A list of elif configurations that would follow along with the top level if
        type: list
        elements: dict
        suboptions: *ifcondition
      else_section:
        description: A dictionary of configurations that would be considered in the else block
        type: dict
        suboptions:
          global: *global
          if_section:
            description: A dictionary of configurations for route policy for the nested if condition, under top level else
            type: dict
            suboptions: *ifcondition
          elseif_section: *elifmodel
          else_section:
            description: A dictionary of configurations for nested else, does not support if/ elseif
            type: dict
            suboptions:
              add: *add
              apply: *apply
              drop: *drop
              pass: *pass
              prepend: *prepend
              suppress_route: *suppess
              unsuppress_route: *unsuppess
              remove: *remove
              set: *set
  running_config:
    description:
      - This option is used only with state I(parsed).
      - The value of this option should be and aggregate of the output received from the IOS XR
        device by executing the command B(show running-config route-policy <policy_name>)
        for per route-policy.
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into Ansible structured data as per the resource module's argspec
        and the value is then returned in the I(parsed) key within the result.
    type: str
  state:
    description:
      - The state the configuration should be left in
      - The states I(rendered), I(gathered) and I(parsed) does not perform any change
        on the device.
      - The state I(rendered) will transform the configuration in C(config) option to
        platform specific CLI commands which will be returned in the I(rendered) key
        within the result. For state I(rendered) active connection to remote host is
        not required.
      - The state I(gathered) will fetch the running configuration from device and
        transform it into structured data in the format as per the resource module
        argspec and the value is returned in the I(gathered) key within the result.
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into JSON format as per the resource module parameters and the
        value is returned in the I(parsed) key within the result. The value of
        C(running_config) option should be the aggregate of the output of
        command I(show running-config route-policy <policy_name>) that gives individual
        route-policy details and executed on device.
        For state I(parsed) active connection to remote host is not required.
    type: str
    choices:
      - merged
      - replaced
      - overridden
      - purged
      - rendered
      - gathered
      - parsed
    default: merged
"""

EXAMPLES = """
# Using merged

# Before state:
# -------------
#
# viosxr#show running-config | include route-policy
#

- name: Merge route-policy configuration
  cisco.iosxr.iosxr_route_maps:
    state: merged
    config:
      - global:
          apply:
            - route_policy: A_NEW_ROUTE_POLICY
          set:
            community:
              additive: true
              community_name: (11011:1001)
            weight: 20000
        name: SIMPLE_GLOBAL_ROUTE_POLICY
      - else_section:
          global:
            drop: true
        if_section:
          condition: destination in SIMPLE_CONDITION_ROUTE_POLICY
          pass: true
        name: SIMPLE_CONDITION_ROUTE_POLICY
      - else_section:
          else_section:
            drop: true
          if_section:
            condition: destination in A_RANDOM_POLICY
            pass: true
            set:
              community:
                additive: true
                community_name: (101010:1)
        if_section:
          condition: as-path in (ios-regex '_3117_', ios-regex '_600_')
          drop: true
        name: COMPLEX_ROUTE_POLICY
      - else_section:
          global:
            pass: true
        if_section:
          condition: community matches-any (9119:1001) or community matches-any (11100:1001)
          drop: true
        name: COMPLEX_CONDITION_ROUTE_POLICY

# Task Output
# -----------
#
# before:
# - {}
# commands:
# - route-policy SIMPLE_GLOBAL_ROUTE_POLICY
# - apply A_NEW_ROUTE_POLICY
# - set community (11011:1001) additive
# - set weight 20000
# - end-policy
# - route-policy SIMPLE_CONDITION_ROUTE_POLICY
# - if destination in SIMPLE_CONDITION_ROUTE_POLICY then
# - pass
# - else
# - drop
# - endif
# - end-policy
# - route-policy COMPLEX_ROUTE_POLICY
# - if as-path in (ios-regex '_3117_', ios-regex '_600_') then
# - drop
# - else
# - if destination in A_RANDOM_POLICY then
# - pass
# - set community (101010:1) additive
# - else
# - drop
# - endif
# - endif
# - end-policy
# - route-policy COMPLEX_CONDITION_ROUTE_POLICY
# - if community matches-any (9119:1001) or community matches-any (11100:1001) then
# - drop
# - else
# - pass
# - endif
# - end-policy
# after:
# - global:
#     apply:
#       - route_policy: A_NEW_ROUTE_POLICY
#     set:
#       community:
#         additive: true
#         community_name: (11011:1001)
#       weight: 20000
#   name: SIMPLE_GLOBAL_ROUTE_POLICY
# - else_section:
#     global:
#       drop: true
#   if_section:
#     condition: destination in SIMPLE_CONDITION_ROUTE_POLICY
#     pass: true
#   name: SIMPLE_CONDITION_ROUTE_POLICY
# - else_section:
#     else_section:
#       drop: true
#     if_section:
#       condition: destination in A_RANDOM_POLICY
#       pass: true
#       set:
#         community:
#           additive: true
#           community_name: (101010:1)
#   if_section:
#     condition: as-path in (ios-regex '_3117_', ios-regex '_600_')
#     drop: true
#   name: COMPLEX_ROUTE_POLICY
# - else_section:
#     global:
#       pass: true
#   if_section:
#     condition: community matches-any (9119:1001) or community matches-any (11100:1001)
#     drop: true
#   name: COMPLEX_CONDITION_ROUTE_POLICY

# After state:
# -------------
#
# viosxr#show running-config | include route-policy
# route-policy SIMPLE_GLOBAL_ROUTE_POLICY
# route-policy SIMPLE_CONDITION_ROUTE_POLICY
# route-policy COMPLEX_ROUTE_POLICY
# route-policy COMPLEX_CONDITION_ROUTE_POLICY
#
# viosxr#show running-config route-policy SIMPLE_GLOBAL_ROUTE_POLICY
# route-policy SIMPLE_GLOBAL_ROUTE_POLICY
#   set weight 20000
#   set local-preference 200
#   set community (11011:1001) additive
#   apply A_NEW_ROUTE_POLICY
# end-policy
# viosxr#show running-config route-policy SIMPLE_CONDITION_ROUTE_POLICY
# route-policy SIMPLE_CONDITION_ROUTE_POLICY
#   if destination in SIMPLE_CONDITION_ROUTE_POLICY then
#     pass
#   else
#     drop
#   endif
# end-policy
# viosxr#show running-config route-policy COMPLEX_ROUTE_POLICY
# route-policy COMPLEX_ROUTE_POLICY
#   if as-path in (ios-regex '_3117_', ios-regex '_600_') then
#     drop
#   else
#     if destination in A_RANDOM_POLICY then
#       pass
#       set community (101010:1) additive
#       set local-preference 200
#     else
#       drop
#     endif
#   endif
# end-policy
# viosxr#show running-config route-policy COMPLEX_CONDITION_ROUTE_POLICY
# route-policy COMPLEX_CONDITION_ROUTE_POLICY
#   if community matches-any (9119:1001) or community matches-any (11100:1001) then
#     drop
#   else
#     pass
#   endif
# end-policy

# Using replaced

# Before state:
# -------------
#
# viosxr#show running-config | include route-policy
# route-policy SIMPLE_GLOBAL_ROUTE_POLICY
# route-policy SIMPLE_CONDITION_ROUTE_POLICY
# route-policy COMPLEX_ROUTE_POLICY
# route-policy COMPLEX_CONDITION_ROUTE_POLICY
#
# viosxr#show running-config route-policy SIMPLE_GLOBAL_ROUTE_POLICY
# route-policy SIMPLE_GLOBAL_ROUTE_POLICY
#   set weight 20000
#   set local-preference 200
#   set community (11011:1001) additive
#   apply A_NEW_ROUTE_POLICY
# end-policy
# viosxr#show running-config route-policy SIMPLE_CONDITION_ROUTE_POLICY
# route-policy SIMPLE_CONDITION_ROUTE_POLICY
#   if destination in SIMPLE_CONDITION_ROUTE_POLICY then
#     pass
#   else
#     drop
#   endif
# end-policy
# viosxr#show running-config route-policy COMPLEX_ROUTE_POLICY
# route-policy COMPLEX_ROUTE_POLICY
#   if as-path in (ios-regex '_3117_', ios-regex '_600_') then
#     drop
#   else
#     if destination in A_RANDOM_POLICY then
#       pass
#       set community (101010:1) additive
#       set local-preference 200
#     else
#       drop
#     endif
#   endif
# end-policy
# viosxr#show running-config route-policy COMPLEX_CONDITION_ROUTE_POLICY
# route-policy COMPLEX_CONDITION_ROUTE_POLICY
#   if community matches-any (9119:1001) or community matches-any (11100:1001) then
#     drop
#   else
#     pass
#   endif
# end-policy

- name: Replace the route-policy configuration
  cisco.iosxr.iosxr_route_maps:
    state: replaced
    config:
      - global:
          apply:
            - route_policy: A_NEW_ROUTE_POLICY
          set:
            community:
              additive: true
              community_name: (11011:1001)
            weight: 20000
        name: SIMPLE_GLOBAL_ROUTE_POLICY
      - else_section:
          global:
            drop: true
        if_section:
          condition: destination in SIMPLE_CONDITION_ROUTE_POLICY
          pass: true
        name: VERY_SIMPLE_CONDITION_ROUTE_POLICY

# Task Output
# -----------
#
# before:
# - global:
#     apply:
#       - route_policy: A_NEW_ROUTE_POLICY
#     set:
#       community:
#         additive: true
#         community_name: (11011:1001)
#       weight: 20000
#   name: SIMPLE_GLOBAL_ROUTE_POLICY
# - else_section:
#     global:
#       drop: true
#   if_section:
#     condition: destination in SIMPLE_CONDITION_ROUTE_POLICY
#     pass: true
#   name: SIMPLE_CONDITION_ROUTE_POLICY
# - else_section:
#     else_section:
#       drop: true
#     if_section:
#       condition: destination in A_RANDOM_POLICY
#       pass: true
#       set:
#         community:
#           additive: true
#           community_name: (101010:1)
#   if_section:
#     condition: as-path in (ios-regex '_3117_', ios-regex '_600_')
#     drop: true
#   name: COMPLEX_ROUTE_POLICY
# - else_section:
#     global:
#       pass: true
#   if_section:
#     condition: community matches-any (9119:1001) or community matches-any (11100:1001)
#     drop: true
#   name: COMPLEX_CONDITION_ROUTE_POLICY
# commands:
# - route-policy VERY_SIMPLE_CONDITION_ROUTE_POLICY
# - if destination in SIMPLE_CONDITION_ROUTE_POLICY then
# - pass
# - else
# - drop
# - endif
# - end-policy
# after:
# - global:
#     apply:
#       - route_policy: A_NEW_ROUTE_POLICY
#     set:
#       community:
#         additive: true
#         community_name: (11011:1001)
#       weight: 20000
#   name: SIMPLE_GLOBAL_ROUTE_POLICY
# - else_section:
#     global:
#       drop: true
#   if_section:
#     condition: destination in SIMPLE_CONDITION_ROUTE_POLICY
#     pass: true
#   name: SIMPLE_CONDITION_ROUTE_POLICY
# - else_section:
#     else_section:
#       drop: true
#     if_section:
#       condition: destination in A_RANDOM_POLICY
#       pass: true
#       set:
#         community:
#           additive: true
#           community_name: (101010:1)
#   if_section:
#     condition: as-path in (ios-regex '_3117_', ios-regex '_600_')
#     drop: true
#   name: COMPLEX_ROUTE_POLICY
# - else_section:
#     global:
#       pass: true
#   if_section:
#     condition: community matches-any (9119:1001) or community matches-any (11100:1001)
#     drop: true
#   name: COMPLEX_CONDITION_ROUTE_POLICY
# - else_section:
#     global:
#       drop: true
#   if_section:
#     condition: destination in SIMPLE_CONDITION_ROUTE_POLICY
#     pass: true
#   name: VERY_SIMPLE_CONDITION_ROUTE_POLICY

# After state:
# -------------
#
# viosxr#show running-config | include route-policy
# route-policy SIMPLE_GLOBAL_ROUTE_POLICY
# route-policy SIMPLE_CONDITION_ROUTE_POLICY
# route-policy COMPLEX_ROUTE_POLICY
# route-policy COMPLEX_CONDITION_ROUTE_POLICY
# route-policy VERY_SIMPLE_CONDITION_ROUTE_POLICY
#
# viosxr#show running-config route-policy SIMPLE_GLOBAL_ROUTE_POLICY
# route-policy SIMPLE_GLOBAL_ROUTE_POLICY
#   set weight 20000
#   set local-preference 200
#   set community (11011:1001) additive
#   apply A_NEW_ROUTE_POLICY
# end-policy
# viosxr#show running-config route-policy SIMPLE_CONDITION_ROUTE_POLICY
# route-policy SIMPLE_CONDITION_ROUTE_POLICY
#   if destination in SIMPLE_CONDITION_ROUTE_POLICY then
#     pass
#   else
#     drop
#   endif
# end-policy
# viosxr#show running-config route-policy COMPLEX_ROUTE_POLICY
# route-policy COMPLEX_ROUTE_POLICY
#   if as-path in (ios-regex '_3117_', ios-regex '_600_') then
#     drop
#   else
#     if destination in A_RANDOM_POLICY then
#       pass
#       set community (101010:1) additive
#       set local-preference 200
#     else
#       drop
#     endif
#   endif
# end-policy
# viosxr#show running-config route-policy COMPLEX_CONDITION_ROUTE_POLICY
# route-policy COMPLEX_CONDITION_ROUTE_POLICY
#   if community matches-any (9119:1001) or community matches-any (11100:1001) then
#     drop
#   else
#     pass
#   endif
# end-policy
# viosxr#show running-config route-policy SIMPLE_CONDITION_ROUTE_POLICY
# route-policy SIMPLE_CONDITION_ROUTE_POLICY
#   if destination in SIMPLE_CONDITION_ROUTE_POLICY then
#     pass
#   else
#     drop
#   endif
# end-policy
# viosxr#show running-config route-policy VERY_SIMPLE_CONDITION_ROUTE_POLICY
# route-policy SIMPLE_CONDITION_ROUTE_POLICY
#   if destination in SIMPLE_CONDITION_ROUTE_POLICY then
#     pass
#   else
#     drop
#   endif
# end-policy

# Using overridden

# Before state:
# -------------
#
# viosxr#show running-config | include route-policy
# route-policy SIMPLE_GLOBAL_ROUTE_POLICY
# route-policy SIMPLE_CONDITION_ROUTE_POLICY
# route-policy COMPLEX_ROUTE_POLICY
# route-policy COMPLEX_CONDITION_ROUTE_POLICY
#
# viosxr#show running-config route-policy SIMPLE_GLOBAL_ROUTE_POLICY
# route-policy SIMPLE_GLOBAL_ROUTE_POLICY
#   set weight 20000
#   set local-preference 200
#   set community (11011:1001) additive
#   apply A_NEW_ROUTE_POLICY
# end-policy
# viosxr#show running-config route-policy SIMPLE_CONDITION_ROUTE_POLICY
# route-policy SIMPLE_CONDITION_ROUTE_POLICY
#   if destination in SIMPLE_CONDITION_ROUTE_POLICY then
#     pass
#   else
#     drop
#   endif
# end-policy
# viosxr#show running-config route-policy COMPLEX_ROUTE_POLICY
# route-policy COMPLEX_ROUTE_POLICY
#   if as-path in (ios-regex '_3117_', ios-regex '_600_') then
#     drop
#   else
#     if destination in A_RANDOM_POLICY then
#       pass
#       set community (101010:1) additive
#       set local-preference 200
#     else
#       drop
#     endif
#   endif
# end-policy
# viosxr#show running-config route-policy COMPLEX_CONDITION_ROUTE_POLICY
# route-policy COMPLEX_CONDITION_ROUTE_POLICY
#   if community matches-any (9119:1001) or community matches-any (11100:1001) then
#     drop
#   else
#     pass
#   endif
# end-policy

- name: Override the route-policy configuration
  cisco.iosxr.iosxr_route_maps:
    state: overridden
    config:
      - global:
          apply:
            - route_policy: A_NEW_ROUTE_POLICY
          set:
            community:
              additive: true
              community_name: (11011:1001)
            weight: 20000
        name: SIMPLE_GLOBAL_ROUTE_POLICY
      - else_section:
          global:
            drop: true
        if_section:
          condition: destination in SIMPLE_CONDITION_ROUTE_POLICY
          pass: true
        name: VERY_SIMPLE_CONDITION_ROUTE_POLICY

# Task Output
# -----------
#
# before:
# - global:
#     apply:
#       - route_policy: A_NEW_ROUTE_POLICY
#     set:
#       community:
#         additive: true
#         community_name: (11011:1001)
#       weight: 20000
#   name: SIMPLE_GLOBAL_ROUTE_POLICY
# - else_section:
#     global:
#       drop: true
#   if_section:
#     condition: destination in SIMPLE_CONDITION_ROUTE_POLICY
#     pass: true
#   name: SIMPLE_CONDITION_ROUTE_POLICY
# - else_section:
#     else_section:
#       drop: true
#     if_section:
#       condition: destination in A_RANDOM_POLICY
#       pass: true
#       set:
#         community:
#           additive: true
#           community_name: (101010:1)
#   if_section:
#     condition: as-path in (ios-regex '_3117_', ios-regex '_600_')
#     drop: true
#   name: COMPLEX_ROUTE_POLICY
# - else_section:
#     global:
#       pass: true
#   if_section:
#     condition: community matches-any (9119:1001) or community matches-any (11100:1001)
#     drop: true
#   name: COMPLEX_CONDITION_ROUTE_POLICY
# commands:
# - route-policy VERY_SIMPLE_CONDITION_ROUTE_POLICY
# - if destination in SIMPLE_CONDITION_ROUTE_POLICY then
# - pass
# - else
# - drop
# - endif
# - end-policy
# - no route-policy SIMPLE_CONDITION_ROUTE_POLICY
# - no route-policy COMPLEX_ROUTE_POLICY
# - no route-policy COMPLEX_CONDITION_ROUTE_POLICY
# after:
# - global:
#     apply:
#       - route_policy: A_NEW_ROUTE_POLICY
#     set:
#       community:
#         additive: true
#         community_name: (11011:1001)
#       weight: 20000
#   name: SIMPLE_GLOBAL_ROUTE_POLICY
# - else_section:
#     global:
#       drop: true
#   if_section:
#     condition: destination in SIMPLE_CONDITION_ROUTE_POLICY
#     pass: true
#   name: VERY_SIMPLE_CONDITION_ROUTE_POLICY

# After state:
# -------------
#
# viosxr#show running-config | include route-policy
# route-policy SIMPLE_GLOBAL_ROUTE_POLICY
# route-policy VERY_SIMPLE_CONDITION_ROUTE_POLICY
#
# viosxr#show running-config route-policy SIMPLE_GLOBAL_ROUTE_POLICY
# route-policy SIMPLE_GLOBAL_ROUTE_POLICY
#   set weight 20000
#   set local-preference 200
#   set community (11011:1001) additive
#   apply A_NEW_ROUTE_POLICY
# end-policy
# viosxr#show running-config route-policy VERY_SIMPLE_CONDITION_ROUTE_POLICY
# route-policy SIMPLE_CONDITION_ROUTE_POLICY
#   if destination in SIMPLE_CONDITION_ROUTE_POLICY then
#     pass
#   else
#     drop
#   endif
# end-policy

# Using purged

# Before state:
# -------------
#
# viosxr#show running-config | include route-policy
# route-policy SIMPLE_GLOBAL_ROUTE_POLICY
# route-policy SIMPLE_CONDITION_ROUTE_POLICY
# route-policy COMPLEX_ROUTE_POLICY
#
# viosxr#show running-config route-policy SIMPLE_GLOBAL_ROUTE_POLICY
# route-policy SIMPLE_GLOBAL_ROUTE_POLICY
#   set weight 20000
#   set local-preference 200
#   set community (11011:1001) additive
#   apply A_NEW_ROUTE_POLICY
# end-policy
# viosxr#show running-config route-policy SIMPLE_CONDITION_ROUTE_POLICY
# route-policy SIMPLE_CONDITION_ROUTE_POLICY
#   if destination in SIMPLE_CONDITION_ROUTE_POLICY then
#     pass
#   else
#     drop
#   endif
# end-policy
# viosxr#show running-config route-policy COMPLEX_ROUTE_POLICY
# route-policy COMPLEX_ROUTE_POLICY
#   if as-path in (ios-regex '_3117_', ios-regex '_600_') then
#     drop
#   else
#     if destination in A_RANDOM_POLICY then
#       pass
#       set community (101010:1) additive
#       set local-preference 200
#     else
#       drop
#     endif
#   endif
# end-policy

- name: Purge or remove route-policy configuration
  cisco.iosxr.iosxr_route_maps:
    state: purged
    config:
      - name: COMPLEX_ROUTE_POLICY_NO_EXIST
      - name: COMPLEX_ROUTE_POLICY

# Task Output
# -----------
#
# before:
# - global:
#     apply:
#       - route_policy: A_NEW_ROUTE_POLICY
#     set:
#       community:
#         additive: true
#         community_name: (11011:1001)
#       weight: 20000
#   name: SIMPLE_GLOBAL_ROUTE_POLICY
# - else_section:
#     global:
#       drop: true
#   if_section:
#     condition: destination in SIMPLE_CONDITION_ROUTE_POLICY
#     pass: true
#   name: SIMPLE_CONDITION_ROUTE_POLICY
# - else_section:
#     else_section:
#       drop: true
#     if_section:
#       condition: destination in A_RANDOM_POLICY
#       pass: true
#       set:
#         community:
#           additive: true
#           community_name: (101010:1)
#   if_section:
#     condition: as-path in (ios-regex '_3117_', ios-regex '_600_')
#     drop: true
#   name: COMPLEX_ROUTE_POLICY
# commands:
# - no route-policy COMPLEX_CONDITION_ROUTE_POLICY
# after:
# - global:
#     apply:
#       - route_policy: A_NEW_ROUTE_POLICY
#     set:
#       community:
#         additive: true
#         community_name: (11011:1001)
#       weight: 20000
#   name: SIMPLE_GLOBAL_ROUTE_POLICY
# - else_section:
#     global:
#       drop: true
#   if_section:
#     condition: destination in SIMPLE_CONDITION_ROUTE_POLICY
#     pass: true
#   name: SIMPLE_CONDITION_ROUTE_POLICY

# After state:
# -------------
#
# viosxr#show running-config | include route-policy
# route-policy SIMPLE_GLOBAL_ROUTE_POLICY
# route-policy SIMPLE_CONDITION_ROUTE_POLICY
#
# viosxr#show running-config route-policy SIMPLE_GLOBAL_ROUTE_POLICY
# route-policy SIMPLE_GLOBAL_ROUTE_POLICY
#   set weight 20000
#   set local-preference 200
#   set community (11011:1001) additive
#   apply A_NEW_ROUTE_POLICY
# end-policy
# viosxr#show running-config route-policy SIMPLE_CONDITION_ROUTE_POLICY
# route-policy SIMPLE_CONDITION_ROUTE_POLICY
#   if destination in SIMPLE_CONDITION_ROUTE_POLICY then
#     pass
#   else
#     drop
#   endif
# end-policy

# Using rendered

- name: Render route-policy configuration
  cisco.iosxr.iosxr_route_maps:
    state: rendered
    config:
      - global:
          apply:
            - route_policy: A_NEW_ROUTE_POLICY
          set:
            community:
              additive: true
              community_name: (11011:1001)
            weight: 20000
        name: SIMPLE_GLOBAL_ROUTE_POLICY
      - else_section:
          global:
            drop: true
        if_section:
          condition: destination in SIMPLE_CONDITION_ROUTE_POLICY
          pass: true
        name: SIMPLE_CONDITION_ROUTE_POLICY
      - else_section:
          else_section:
            drop: true
          if_section:
            condition: destination in A_RANDOM_POLICY
            pass: true
            set:
              community:
                additive: true
                community_name: (101010:1)
        if_section:
          condition: as-path in (ios-regex '_3117_', ios-regex '_600_')
          drop: true
        name: COMPLEX_ROUTE_POLICY
      - else_section:
          global:
            pass: true
        if_section:
          condition: community matches-any (9119:1001) or community matches-any (11100:1001)
          drop: true
        name: COMPLEX_CONDITION_ROUTE_POLICY

# Task Output
# -----------
#
# rendered:
# - route-policy SIMPLE_GLOBAL_ROUTE_POLICY
# - apply A_NEW_ROUTE_POLICY
# - set community (11011:1001) additive
# - set weight 20000
# - end-policy
# - route-policy SIMPLE_CONDITION_ROUTE_POLICY
# - if destination in SIMPLE_CONDITION_ROUTE_POLICY then
# - pass
# - else
# - drop
# - endif
# - end-policy
# - route-policy COMPLEX_ROUTE_POLICY
# - if as-path in (ios-regex '_3117_', ios-regex '_600_') then
# - drop
# - else
# - if destination in A_RANDOM_POLICY then
# - pass
# - set community (101010:1) additive
# - else
# - drop
# - endif
# - endif
# - end-policy
# - route-policy COMPLEX_CONDITION_ROUTE_POLICY
# - if community matches-any (9119:1001) or community matches-any (11100:1001) then
# - drop
# - else
# - pass
# - endif
# - end-policy

# Using parsed

# File: parsed.cfg
# ----------------
#
# route-policy SIMPLE_GLOBAL_ROUTE_POLICY
#   set weight 20000
#   set local-preference 200
#   set community (11011:1001) additive
#   apply A_NEW_ROUTE_POLICY
# end-policy
# !
# route-policy SIMPLE_CONDITION_ROUTE_POLICY
#   if destination in SIMPLE_CONDITION_ROUTE_POLICY then
#     pass
#   else
#     drop
#   endif
# end-policy
# !
# route-policy COMPLEX_ROUTE_POLICY
#   if as-path in (ios-regex '_3117_', ios-regex '_600_') then
#     drop
#   else
#     if destination in A_RANDOM_POLICY then
#       pass
#       set community (101010:1) additive
#       set local-preference 200
#     else
#       drop
#     endif
#   endif
# end-policy
# !
# route-policy COMPLEX_CONDITION_ROUTE_POLICY
#   if community matches-any (9119:1001) or community matches-any (11100:1001) then
#     drop
#   else
#     pass
#   endif
# end-policy

- name: Parse the provided configuration
  cisco.iosxr.iosxr_route_maps:
    running_config: "{{ lookup('file', 'iosxr_route_maps_conf.cfg') }}"
    state: parsed

# Task Output
# -----------
#
# parsed:
# - global:
#     apply:
#     - route_policy: A_NEW_ROUTE_POLICY
#     set:
#       community:
#         additive: true
#         community_name: (11011:1001)
#       weight: 20000
#   name: SIMPLE_GLOBAL_ROUTE_POLICY
# - else_section:
#     global:
#       drop: true
#   if_section:
#     condition: destination in SIMPLE_CONDITION_ROUTE_POLICY
#     pass: true
#   name: SIMPLE_CONDITION_ROUTE_POLICY
# - else_section:
#     else_section:
#       drop: true
#     if_section:
#       condition: destination in A_RANDOM_POLICY
#       pass: true
#       set:
#         community:
#           additive: true
#           community_name: (101010:1)
#   if_section:
#     condition: as-path in (ios-regex '_3117_', ios-regex '_600_')
#     drop: true
#   name: COMPLEX_ROUTE_POLICY
# - else_section:
#     global:
#       pass: true
#   if_section:
#     condition: community matches-any (9119:1001) or community matches-any (11100:1001)
#     drop: true
#   name: COMPLEX_CONDITION_ROUTE_POLICY
"""

RETURN = """
before:
  description: The configuration prior to the module execution.
  returned: when I(state) is C(merged), C(replaced), C(overridden), C(purged) or C(purged)
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
  returned: when I(state) is C(merged), C(replaced), C(overridden), C(purged) or C(purged)
  type: list
  sample:
    - route-policy APPLY_TEST_ROUTE_POLICY_COMPLEX
    - if destination in DEFAULT then
    - pass
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - route-policy APPLY_TEST_ROUTE_POLICY_COMPLEX
    - if destination in DEFAULT then
    - pass
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

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.route_maps.route_maps import (
    Route_mapsArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.config.route_maps.route_maps import (
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
