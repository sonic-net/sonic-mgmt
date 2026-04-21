#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for nxos_bgp_address_family
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: nxos_bgp_address_family
short_description: BGP Address Family resource module.
description:
- This module manages BGP Address Family configuration on devices running Cisco NX-OS.
version_added: 2.0.0
notes:
- Tested against NX-OS 9.3.6.
- Unsupported for Cisco MDS
- For managing BGP neighbor address family configurations please use
  the M(cisco.nxos.nxos_bgp_neighbor_address_family) module.
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
    description: A list of BGP process configuration.
    type: dict
    suboptions:
      as_number:
        description: Autonomous System Number of the router.
        type: str
      address_family:
        description: Address Family related configurations.
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
          additional_paths:
            description: Additional paths configuration.
            type: dict
            suboptions:
              install_backup:
                description: Install backup path.
                type: bool
              receive:
                description: Additional paths Receive capability.
                type: bool
              selection:
                description: Additional paths selection
                type: dict
                suboptions:
                  route_map:
                    description: Route-map for additional paths selection
                    type: str
              send:
                description: Additional paths Send capability
                type: bool
          advertise_pip:
            description: Advertise physical ip for type-5 route.
            type: bool
          advertise_l2vpn_evpn:
            description: Enable advertising EVPN routes.
            type: bool
          advertise_system_mac:
            description: Advertise extra EVPN RT-2 with system MAC.
            type: bool
          allow_vni_in_ethertag:
            description: Allow VNI in Ethernet Tag field in EVPN route.
            type: bool
          aggregate_address:
            description: Configure BGP aggregate prefixes
            type: list
            elements: dict
            suboptions:
              prefix:
                description: Aggregate prefix.
                type: str
              advertise_map:
                description: Select attribute information from specific routes.
                type: str
              as_set:
                description: Generate AS-SET information.
                type: bool
              attribute_map:
                description: Set attribute information of aggregate.
                type: str
              summary_only:
                description: Do not advertise more specifics.
                type: bool
              suppress_map:
                description: Conditionally filter more specific routes.
                type: str
          client_to_client:
            description: Configure client-to-client route reflection.
            type: dict
            suboptions:
              no_reflection:
                description: Reflection of routes permitted.
                type: bool
          dampen_igp_metric:
            description: Dampen IGP metric-related changes.
            type: int
          dampening:
            description: Configure route flap dampening.
            type: dict
            suboptions:
              set:
                description: Set route flap dampening.
                type: bool
              decay_half_life:
                description: Decay half life.
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
              route_map:
                description: Apply route-map to specify dampening criteria.
                type: str
          default_information:
            description: Control distribution of default information.
            type: dict
            suboptions:
              originate:
                description: Distribute a default route.
                type: bool
          default_metric:
            description: Set metric of redistributed routes.
            type: int
          distance:
            description: Configure administrative distance.
            type: dict
            suboptions:
              ebgp_routes:
                description: Distance for EBGP routes.
                type: int
              ibgp_routes:
                description: Distance for IBGP routes.
                type: int
              local_routes:
                description: Distance for local routes.
                type: int
          export_gateway_ip:
            description: Export Gateway IP to Type-5 EVPN routes for VRF
            type: bool
          inject_map:
            description: Routemap which specifies prefixes to inject.
            type: list
            elements: dict
            suboptions:
              route_map:
                description: Route-map name.
                type: str
              exist_map:
                description: Routemap which specifies exist condition.
                type: str
              copy_attributes:
                description: Copy attributes from aggregate.
                type: bool
          maximum_paths:
            description: Forward packets over multipath paths.
            type: dict
            suboptions:
              parallel_paths:
                description: Number of parallel paths.
                type: int
              ibgp:
                description: Configure multipath for IBGP paths.
                type: dict
                suboptions:
                  parallel_paths:
                    description:  Number of parallel paths.
                    type: int
              eibgp:
                description: Configure multipath for both EBGP and IBGP paths.
                type: dict
                suboptions:
                  parallel_paths:
                    description:  Number of parallel paths.
                    type: int
              local:
                description: Configure multipath for local paths.
                type: dict
                suboptions:
                  parallel_paths:
                    description:  Number of parallel paths.
                    type: int
              mixed:
                description: Configure multipath for local and remote paths.
                type: dict
                suboptions:
                  parallel_paths:
                    description:  Number of parallel paths.
                    type: int
          networks:
            description: Configure an IP prefix to advertise.
            type: list
            elements: dict
            suboptions:
              prefix:
                description: IP prefix in CIDR format.
                type: str
              route_map:
                description: Route-map name.
                type: str
          nexthop:
            description: Nexthop tracking.
            type: dict
            suboptions:
              route_map:
                description: Route-map name.
                type: str
              trigger_delay:
                description: Set the delay to trigger nexthop tracking.
                type: dict
                suboptions:
                  critical_delay:
                    description:
                    - Nexthop changes affecting reachability.
                    - Delay value (miliseconds).
                    type: int
                  non_critical_delay:
                    description:
                    - Other nexthop changes.
                    - Delay value (miliseconds).
                    type: int
          redistribute:
            description: Configure redistribution.
            type: list
            elements: dict
            suboptions:
              protocol:
                description:
                - The name of the protocol.
                type: str
                choices: ["am", "direct", "eigrp", "isis", "lisp", "ospf", "ospfv3", "rip", "static", "hmm"]
                required: true
              id:
                description:
                - The identifier for the protocol specified.
                type: str
              route_map:
                description:
                - The route map policy to constrain redistribution.
                type: str
                required: true
          retain:
            description: Retain the routes based on Target VPN Extended Communities.
            type: dict
            suboptions:
              route_target:
                description: Specify Target VPN Extended Communities
                type: dict
                suboptions:
                  retain_all:
                    description: All the routes regardless of Target-VPN community
                    type: bool
                  route_map:
                    description: Apply route-map to filter routes.
                    type: str
          suppress_inactive:
            description: Advertise only active routes to peers.
            type: bool
          table_map:
            description:
            - Policy for filtering/modifying OSPF routes before sending them to RIB.
            type: dict
            suboptions:
              name:
                description:
                - The Route Map name.
                type: str
                required: true
              filter:
                description:
                - Block the OSPF routes from being sent to RIB.
                type: bool
          timers:
            description: Configure bgp related timers.
            type: dict
            suboptions:
              bestpath_defer:
                description: Configure bestpath defer timer value for batch prefix processing.
                type: dict
                suboptions:
                  defer_time:
                    description: Bestpath defer time (mseconds).
                    type: int
                  maximum_defer_time:
                    description: Maximum bestpath defer time (mseconds).
                    type: int
          wait_igp_convergence:
            description: Delay initial bestpath until redistributed IGPs have converged.
            type: bool
          vrf:
            description: Virtual Router Context.
            type: str
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
  cisco.nxos.nxos_bgp_address_family:
    config:
      as_number: 65536
      address_family:
        - afi: ipv4
          safi: multicast
          networks:
            - prefix: 192.0.2.32/27
            - prefix: 192.0.2.64/27
              route_map: rmap1
          nexthop:
            route_map: rmap2
            trigger_delay:
              critical_delay: 120
              non_critical_delay: 180
        - afi: ipv4
          safi: unicast
          vrf: site-1
          default_information:
            originate: true
          aggregate_address:
            - prefix: 203.0.113.0/24
              as_set: true
              summary_only: true
        - afi: ipv6
          safi: multicast
          vrf: site-1
          redistribute:
            - protocol: ospfv3
              id: 100
              route_map: rmap-ospf-1
            - protocol: eigrp
              id: 101
              route_map: rmap-eigrp-1

# Task output:
# ------------
#  before: {}
#
#  commands:
#  - router bgp 65536
#  - address-family ipv4 multicast
#  - nexthop route-map rmap2
#  - nexthop trigger-delay critical 120 non-critical 180
#  - network 192.0.2.32/27
#  - network 192.0.2.64/27 route-map rmap1
#  - vrf site-1
#  - address-family ipv4 unicast
#  - default-information originate
#  - aggregate-address 203.0.113.0/24 as-set summary-only
#  - address-family ipv6 multicast
#  - redistribute ospfv3 100 route-map rmap-ospf-1
#  - redistribute eigrp 101 route-map rmap-eigrp-1
#
#  after:
#    as_number: "65536"
#    address_family:
#      - afi: ipv4
#        safi: multicast
#        networks:
#          - prefix: 192.0.2.32/27
#          - prefix: 192.0.2.64/27
#            route_map: rmap1
#        nexthop:
#          route_map: rmap2
#          trigger_delay:
#            critical_delay: 120
#            non_critical_delay: 180
#      - afi: ipv4
#        safi: unicast
#        vrf: site-1
#        default_information:
#          originate: true
#        aggregate_address:
#          - prefix: 203.0.113.0/24
#            as_set: true
#            summary_only: true
#      - afi: ipv6
#        safi: multicast
#        vrf: site-1
#        redistribute:
#          - id: "100"
#            protocol: ospfv3
#            route_map: rmap-ospf-1
#          - id: "101"
#            protocol: eigrp
#            route_map: rmap-eigrp-1

# After state:
# ------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65536
#   address-family ipv4 multicast
#     nexthop route-map rmap2
#     nexthop trigger-delay critical 120 non-critical 180
#     network 192.0.2.32/27
#     network 192.0.2.64/27 route-map rmap1
#   vrf site-1
#     address-family ipv4 unicast
#       default-information originate
#       aggregate-address 203.0.113.0/24 as-set summary-only
#     address-family ipv6 multicast
#       redistribute ospfv3 100 route-map rmap-ospf-1
#       redistribute eigrp 101 route-map rmap-eigrp-1
#

# Using replaced

# Before state:
# -------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65536
#   address-family ipv4 multicast
#     nexthop route-map rmap2
#     nexthop trigger-delay critical 120 non-critical 180
#     network 192.0.2.32/27
#     network 192.0.2.64/27 route-map rmap1
#   vrf site-1
#     address-family ipv4 unicast
#       default-information originate
#       aggregate-address 203.0.113.0/24 as-set summary-only
#     address-family ipv6 multicast
#       redistribute ospfv3 100 route-map rmap-ospf-1
#       redistribute eigrp 101 route-map rmap-eigrp-1

- name: Replace configuration of specified AFs
  cisco.nxos.nxos_bgp_address_family:
    config:
      as_number: 65536
      address_family:
        - afi: ipv4
          safi: multicast
          networks:
            - prefix: 192.0.2.64/27
              route_map: rmap1
          nexthop:
            route_map: rmap2
            trigger_delay:
              critical_delay: 120
              non_critical_delay: 180
          aggregate_address:
            - prefix: 203.0.113.0/24
              as_set: true
              summary_only: true
        - afi: ipv4
          safi: unicast
          vrf: site-1
    state: replaced

# Task output:
# ------------
#  before:
#    as_number: "65536"
#    address_family:
#      - afi: ipv4
#        safi: multicast
#        networks:
#          - prefix: 192.0.2.32/27
#          - prefix: 192.0.2.64/27
#            route_map: rmap1
#        nexthop:
#          route_map: rmap2
#          trigger_delay:
#            critical_delay: 120
#            non_critical_delay: 180
#      - afi: ipv4
#        safi: unicast
#        vrf: site-1
#        default_information:
#          originate: true
#        aggregate_address:
#          - prefix: 203.0.113.0/24
#            as_set: true
#            summary_only: true
#      - afi: ipv6
#        safi: multicast
#        vrf: site-1
#        redistribute:
#          - id: "100"
#            protocol: ospfv3
#            route_map: rmap-ospf-1
#          - id: "101"
#            protocol: eigrp
#            route_map: rmap-eigrp-1
#
#  commands:
#  - router bgp 65536
#  - address-family ipv4 multicast
#  - no network 192.0.2.32/27
#  - aggregate-address 203.0.113.0/24 as-set summary-only
#  - vrf site-1
#  - address-family ipv4 unicast
#  - no default-information originate
#  - no aggregate-address 203.0.113.0/24 as-set summary-only
#
#  after:
#    as_number: "65536"
#    address_family:
#      - afi: ipv4
#        safi: multicast
#        networks:
#          - prefix: 192.0.2.64/27
#            route_map: rmap1
#        nexthop:
#          route_map: rmap2
#          trigger_delay:
#            critical_delay: 120
#            non_critical_delay: 180
#        aggregate_address:
#          - prefix: 203.0.113.0/24
#            as_set: true
#            summary_only: true
#
#      - afi: ipv4
#        safi: unicast
#        vrf: site-1
#
#      - afi: ipv6
#        safi: multicast
#        vrf: site-1
#        redistribute:
#          - protocol: ospfv3
#            id: "100"
#            route_map: rmap-ospf-1
#          - protocol: eigrp
#            id: "101"
#            route_map: rmap-eigrp-1

# After state:
# ------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65536
#   address-family ipv4 multicast
#     nexthop route-map rmap2
#     nexthop trigger-delay critical 120 non-critical 180
#     network 192.0.2.64/27 route-map rmap1
#     aggregate-address 203.0.113.0/24 as-set summary-only
#   vrf site-1
#     address-family ipv4 unicast
#     address-family ipv6 multicast
#       redistribute ospfv3 100 route-map rmap-ospf-1
#       redistribute eigrp 101 route-map rmap-eigrp-1

# Using overridden

# Before state:
# -------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65536
#   address-family ipv4 multicast
#     nexthop route-map rmap2
#     nexthop trigger-delay critical 120 non-critical 180
#     network 192.0.2.32/27
#     network 192.0.2.64/27 route-map rmap1
#   vrf site-1
#     address-family ipv4 unicast
#       default-information originate
#       aggregate-address 203.0.113.0/24 as-set summary-only
#     address-family ipv6 multicast
#       redistribute ospfv3 100 route-map rmap-ospf-1
#       redistribute eigrp 101 route-map rmap-eigrp-1

- name: Override all BGP AF configuration with provided configuration
  cisco.nxos.nxos_bgp_address_family: &overridden
    config:
      as_number: 65536
      address_family:
        - afi: ipv4
          safi: multicast
          networks:
            - prefix: 192.0.2.64/27
              route_map: rmap1
          aggregate_address:
            - prefix: 203.0.113.0/24
              as_set: true
              summary_only: true
        - afi: ipv4
          safi: unicast
          vrf: site-1
    state: overridden

# Task output:
# ------------
#  before:
#    as_number: "65536"
#    address_family:
#      - afi: ipv4
#        safi: multicast
#        networks:
#          - prefix: 192.0.2.32/27
#          - prefix: 192.0.2.64/27
#            route_map: rmap1
#        nexthop:
#          route_map: rmap2
#          trigger_delay:
#            critical_delay: 120
#            non_critical_delay: 180
#      - afi: ipv4
#        safi: unicast
#        vrf: site-1
#        default_information:
#          originate: true
#        aggregate_address:
#          - prefix: 203.0.113.0/24
#            as_set: true
#            summary_only: true
#      - afi: ipv6
#        safi: multicast
#        vrf: site-1
#        redistribute:
#          - id: "100"
#            protocol: ospfv3
#            route_map: rmap-ospf-1
#          - id: "101"
#            protocol: eigrp
#            route_map: rmap-eigrp-1
#
#  commands:
#  - router bgp 65536
#  - vrf site-1
#  - no address-family ipv6 multicast
#  - exit
#  - address-family ipv4 multicast
#  - no nexthop route-map rmap2
#  - no nexthop trigger-delay critical 120 non-critical 180
#  - aggregate-address 203.0.113.0/24 as-set summary-only
#  - no network 192.0.2.32/27
#  - vrf site-1
#  - address-family ipv4 unicast
#  - no default-information originate
#  - no aggregate-address 203.0.113.0/24 as-set summary-only
#
#  after:
#    as_number: "65536"
#    address_family:
#      - afi: ipv4
#        safi: multicast
#        networks:
#          - prefix: 192.0.2.64/27
#            route_map: rmap1
#        aggregate_address:
#          - prefix: 203.0.113.0/24
#            as_set: true
#            summary_only: true
#      - afi: ipv4
#        safi: unicast
#        vrf: site-1

#
# After state:
# ------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65536
#   address-family ipv4 multicast
#     network 192.0.2.64/27 route-map rmap1
#     aggregate-address 203.0.113.0/24 as-set summary-only
#   vrf site-1
#     address-family ipv4 unicast
#

# Using deleted to remove specified AFs

# Before state:
# -------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65536
#   address-family ipv4 multicast
#     nexthop route-map rmap2
#     nexthop trigger-delay critical 120 non-critical 180
#     network 192.0.2.32/27
#     network 192.0.2.64/27 route-map rmap1
#   vrf site-1
#     address-family ipv4 unicast
#       default-information originate
#       aggregate-address 203.0.113.0/24 as-set summary-only
#     address-family ipv6 multicast
#       redistribute ospfv3 100 route-map rmap-ospf-1
#       redistribute eigrp 101 route-map rmap-eigrp-1

- name: Delete specified BGP AFs
  cisco.nxos.nxos_bgp_address_family:
    config:
      as_number: 65536
      address_family:
        - afi: ipv4
          safi: multicast
        - vrf: site-1
          afi: ipv6
          safi: multicast
    state: deleted

# Task output:
# ------------
#  before:
#    as_number: "65536"
#    address_family:
#      - afi: ipv4
#        safi: multicast
#        networks:
#          - prefix: 192.0.2.32/27
#          - prefix: 192.0.2.64/27
#            route_map: rmap1
#        nexthop:
#          route_map: rmap2
#          trigger_delay:
#            critical_delay: 120
#            non_critical_delay: 180
#      - afi: ipv4
#        safi: unicast
#        vrf: site-1
#        default_information:
#          originate: true
#        aggregate_address:
#          - prefix: 203.0.113.0/24
#            as_set: true
#            summary_only: true
#      - afi: ipv6
#        safi: multicast
#        vrf: site-1
#        redistribute:
#          - id: "100"
#            protocol: ospfv3
#            route_map: rmap-ospf-1
#          - id: "101"
#            protocol: eigrp
#            route_map: rmap-eigrp-1
#
#  commands:
#  - router bgp 65563
#  - no address-family ipv4 multicast
#  - vrf site-1
#  - no address-family ipv6 multicast
#
#  after:
#    as_number: "65536"
#    address_family:
#      - afi: ipv4
#        safi: unicast
#        vrf: site-1
#        default_information:
#          originate: true
#        aggregate_address:
#          - prefix: 203.0.113.0/24
#            as_set: true
#            summary_only: true

# After state:
# ------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65536
#   vrf site-1
#     address-family ipv4 unicast
#       default-information originate
#       aggregate-address 203.0.113.0/24 as-set summary-only

# Using deleted to remove all BGP AFs

# Before state:
# -------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65536
#   address-family ipv4 multicast
#     nexthop route-map rmap2
#     nexthop trigger-delay critical 120 non-critical 180
#     network 192.0.2.32/27
#     network 192.0.2.64/27 route-map rmap1
#   vrf site-1
#     address-family ipv4 unicast
#       default-information originate
#       aggregate-address 203.0.113.0/24 as-set summary-only
#     address-family ipv6 multicast
#       redistribute ospfv3 100 route-map rmap-ospf-1
#       redistribute eigrp 101 route-map rmap-eigrp-1

- name: Delete all BGP AFs
  cisco.nxos.nxos_bgp_address_family:
    state: deleted

# Task output:
# ------------
#  before:
#    as_number: "65536"
#    address_family:
#      - afi: ipv4
#        safi: multicast
#        networks:
#          - prefix: 192.0.2.32/27
#          - prefix: 192.0.2.64/27
#            route_map: rmap1
#        nexthop:
#          route_map: rmap2
#          trigger_delay:
#            critical_delay: 120
#            non_critical_delay: 180
#      - afi: ipv4
#        safi: unicast
#        vrf: site-1
#        default_information:
#          originate: true
#        aggregate_address:
#          - prefix: 203.0.113.0/24
#            as_set: true
#            summary_only: true
#      - afi: ipv6
#        safi: multicast
#        vrf: site-1
#        redistribute:
#          - id: "100"
#            protocol: ospfv3
#            route_map: rmap-ospf-1
#          - id: "101"
#            protocol: eigrp
#            route_map: rmap-eigrp-1
#
#  commands:
#  - router bgp 65563
#  - no address-family ipv4 multicast
#  - vrf site-1
#  - no address-family ipv4 unicast
#  - no address-family ipv6 multicast
#
#  after:
#    as_number: "65536"

# After state:
# ------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65536
# Nexus9000v#

# Using rendered

- name: Render platform specific configuration lines with state rendered (without connecting to the device)
  cisco.nxos.nxos_bgp_address_family:
    config:
      as_number: 65536
      address_family:
        - afi: ipv4
          safi: multicast
          networks:
            - prefix: 192.0.2.32/27
            - prefix: 192.0.2.64/27
              route_map: rmap1
          nexthop:
            route_map: rmap2
            trigger_delay:
              critical_delay: 120
              non_critical_delay: 180
        - afi: ipv4
          safi: unicast
          vrf: site-1
          default_information:
            originate: true
          aggregate_address:
            - prefix: 203.0.113.0/24
              as_set: true
              summary_only: true
        - afi: ipv6
          safi: multicast
          vrf: site-1
          redistribute:
            - protocol: ospfv3
              id: 100
              route_map: rmap-ospf-1
            - protocol: eigrp
              id: 101
              route_map: rmap-eigrp-1
    state: rendered

# Task Output:
# ------------
# rendered:
# - router bgp 65536
# - address-family ipv4 multicast
# - nexthop route-map rmap2
# - nexthop trigger-delay critical 120 non-critical 180
# - network 192.0.2.32/27
# - network 192.0.2.64/27 route-map rmap1
# - vrf site-1
# - address-family ipv4 unicast
# - default-information originate
# - aggregate-address 203.0.113.0/24 as-set summary-only
# - address-family ipv6 multicast
# - redistribute ospfv3 100 route-map rmap-ospf-1
# - redistribute eigrp 101 route-map rmap-eigrp-1

# Using parsed

# parsed.cfg
# ------------
# router bgp 65536
#   address-family ipv4 multicast
#     nexthop route-map rmap2
#     nexthop trigger-delay critical 120 non-critical 180
#     network 192.0.2.32/27
#    network 192.0.2.64/27 route-map rmap1
#  vrf site-1
#    address-family ipv4 unicast
#      default-information originate
#      aggregate-address 203.0.113.0/24 as-set summary-only
#    address-family ipv6 multicast
#      redistribute ospfv3 100 route-map rmap-ospf-1
#      redistribute eigrp 101 route-map rmap-eigrp-1

- name: Parse externally provided BGP AF config
  cisco.nxos.nxos_bgp_address_family:
    running_config: "{{ lookup('file', 'parsed.cfg') }}"
    state: parsed

# Task output:
# ------------
#  parsed:
#    as_number: "65536"
#    address_family:
#      - afi: ipv4
#        safi: multicast
#        networks:
#          - prefix: 192.0.2.32/27
#          - prefix: 192.0.2.64/27
#            route_map: rmap1
#        nexthop:
#          route_map: rmap2
#          trigger_delay:
#            critical_delay: 120
#            non_critical_delay: 180
#      - afi: ipv4
#        safi: unicast
#        vrf: site-1
#        default_information:
#          originate: true
#        aggregate_address:
#          - prefix: 203.0.113.0/24
#            as_set: true
#            summary_only: true
#      - afi: ipv6
#        safi: multicast
#        vrf: site-1
#        redistribute:
#          - id: "100"
#            protocol: ospfv3
#            route_map: rmap-ospf-1
#          - id: "101"
#            protocol: eigrp
#            route_map: rmap-eigrp-1
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
    - address-family ipv4 multicast
    - nexthop route-map rmap2
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - router bgp 65536
    - address-family ipv4 multicast
    - nexthop route-map rmap2
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

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.bgp_address_family.bgp_address_family import (
    Bgp_address_familyArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.config.bgp_address_family.bgp_address_family import (
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
