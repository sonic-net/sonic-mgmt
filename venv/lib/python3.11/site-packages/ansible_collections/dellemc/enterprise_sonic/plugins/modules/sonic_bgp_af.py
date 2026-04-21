#!/usr/bin/python
# -*- coding: utf-8 -*-
# © Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_bgp_af
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_bgp_af
version_added: 1.0.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
author: Niraimadaiselvam M (@niraimadaiselvamm)
short_description: Manage global BGP address-family and its parameters
description:
  - This module provides configuration management of global BGP_AF parameters on devices running Enterprise SONiC.
  - bgp_as and vrf_name must be created in advance on the device.
options:
  config:
    description:
      - Specifies the BGP_AF related configuration.
    type: list
    elements: dict
    suboptions:
      bgp_as:
        description:
          - Specifies the BGP autonomous system (AS) number which is already configured on the device.
        type: str
        required: true
      vrf_name:
        description:
          - Specifies the VRF name which is already configured on the device.
        type: str
        default: 'default'
      address_family:
        description:
          - Specifies BGP address family related configurations.
        type: dict
        suboptions:
          afis:
            description:
              - List of address families, such as ipv4, ipv6, and l2vpn.
              - afi and safi are required together.
            type: list
            elements: dict
            suboptions:
              afi:
                description:
                  - Type of address family to configure.
                type: str
                choices:
                  - ipv4
                  - ipv6
                  - l2vpn
                required: true
              safi:
                description:
                  - Specifies the type of communication for the address family.
                type: str
                choices:
                  - unicast
                  - evpn
                default: unicast
              dampening:
                description:
                  - Enable route flap dampening if set to true
                type: bool
              network:
                description:
                  - Enable routing on an IP network for each prefix provided in the network
                type: list
                elements: str
              redistribute:
                description:
                  - Specifies the redistribute information from another routing protocol.
                type: list
                elements: dict
                suboptions:
                  protocol:
                    description:
                      - Specifies the protocol for configuring redistribute information.
                    type: str
                    choices: ['ospf', 'static', 'connected']
                    required: true
                  metric:
                    description:
                      - Specifies the metric for redistributed routes.
                    type: str
                  route_map:
                    description:
                      - Specifies the route map reference.
                    type: str
              import:
                description:
                  - Specifies the routes to be imported to this address family.
                version_added: '2.5.0'
                type: dict
                suboptions:
                  vrf:
                    description:
                      - Import routes from other VRFs.
                    type: dict
                    suboptions:
                      vrf_list:
                        description:
                          - Specifies the VRFs to import routes from.
                        type: list
                        elements: str
                      route_map:
                        description:
                          - Specifies the route-map.
                        type: str
              advertise_pip:
                description:
                  - Enables advertise PIP
                type: bool
              advertise_pip_ip:
                description:
                  - PIP IPv4 address
                type: str
              advertise_pip_peer_ip:
                description:
                  - PIP peer IPv4 address
                type: str
              advertise_svi_ip:
                description:
                  - Enables advertise SVI MACIP routes
                type: bool
              route_advertise_list:
                description:
                  - List of advertise routes
                type: list
                elements: dict
                suboptions:
                  advertise_afi:
                    required: true
                    type: str
                    choices:
                      - ipv4
                      - ipv6
                    description:
                      - Specifies the address family
                  route_map:
                    type: str
                    description:
                      - Specifies the route-map reference
              advertise_default_gw:
                description:
                  - Specifies the advertise default gateway flag.
                type: bool
              advertise_all_vni:
                description:
                  - Specifies the advertise all vni flag.
                type: bool
              dup_addr_detection:
                description:
                  - Duplicate address detection configuration.
                  - I(max_moves) and I(time) are required together.
                version_added: '3.1.0'
                type: dict
                suboptions:
                  enabled:
                    description:
                      - Enable duplicate address detection.
                    type: bool
                  freeze:
                    description:
                      - Specifies duplicate address detection freeze.
                      - Value can be C(permanent) or time in the range 30 to 3600.
                      - C(permanent) - Enable permanent freeze.
                    type: str
                  max_moves:
                    description:
                      - Specifies the max allowed moves before address is detected as duplicate.
                      - The range is from 2 to 1000.
                    type: int
                  time:
                    description:
                      - Specifies the duplicate address detection time.
                      - The range is from 2 to 1800.
                    type: int
              max_path:
                description:
                  - Specifies the maximum paths of ibgp and ebgp count.
                type: dict
                suboptions:
                  ibgp:
                    description:
                      - Specifies the count of the ibgp multipaths count.
                    type: int
                  ebgp:
                    description:
                      - Specifies the count of the ebgp multipaths count.
                    type: int
              rd:
                description:
                  - Specifies the route distiguisher to be used by the VRF instance.
                type: str
              rt_in:
                description:
                  - Route-targets to be imported.
                type: list
                elements: str
              rt_out:
                description:
                  - Route-targets to be exported.
                type: list
                elements: str
              vnis:
                description:
                  - VNI configuration for the EVPN.
                type: list
                elements: dict
                suboptions:
                  vni_number:
                    description:
                      - Specifies the VNI number.
                    type: int
                    required: true
                  advertise_default_gw:
                    description:
                      - Specifies the advertise default gateway flag.
                    type: bool
                  advertise_svi_ip:
                    description:
                      - Enables advertise SVI MACIP routes
                    type: bool
                  rd:
                    description:
                      - Specifies the route distiguisher to be used by the VRF instance.
                    type: str
                  rt_in:
                    description:
                      - Route-targets to be imported.
                    type: list
                    elements: str
                  rt_out:
                    description:
                      - Route-targets to be exported.
                    type: list
                    elements: str
              aggregate_address_config:
                description:
                  - Aggregate address configuration
                version_added: 2.5.0
                type: list
                elements: dict
                suboptions:
                  prefix:
                    description:
                      - Aggregate address prefix
                    type: str
                    required: true
                  as_set:
                    description:
                      - Enables/disables generation of AS set path information
                    type: bool
                  policy_name:
                    description:
                      - Preconfigured routing policy (route map name) to be applied to aggregate network
                    type: str
                  summary_only:
                    description:
                      - Enables/disables restriction of route information included in updates
                    type: bool
  state:
    description:
      - Specifies the operation to be performed on the BGP_AF process configured on the device.
      - In case of merged, the input configuration is merged with the existing BGP_AF configuration on the device.
      - In case of deleted, the existing BGP_AF configuration is removed from the device.
      - In case of replaced, the existing BGP_AF of specified BGP AS will be replaced with provided configuration.
      - In case of overridden, the existing BGP_AF configuration will be overridden with the provided configuration.
    default: merged
    choices: ['merged', 'deleted', 'overridden', 'replaced']
    type: str
"""

EXAMPLES = """
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration bgp
# !
# router bgp 51 vrf VrfReg1
#  log-neighbor-changes
#  timers 60 180
#  !
#  address-family ipv4 unicast
#   maximum-paths 1
#   maximum-paths ibgp 1
#   network 3.3.3.3/16
#   aggregate-address 1.1.1.1/1
#   aggregate-address 5.5.5.5/5 as-set summary-only route-map rmap-1
#   dampening
#   import vrf route-map rmap-1
#   import vrf default
# !
# router bgp 51
#  router-id 111.2.2.41
#  timers 60 180
#  !
#  address-family ipv4 unicast
#   maximum-paths 1
#   maximum-paths ibgp 1
#   dampening
#  !
#  address-family ipv6 unicast
#   redistribute connected route-map bb metric 21
#   redistribute ospf route-map aa metric 27
#   redistribute static route-map bb metric 26
#   maximum-paths 4
#   maximum-paths ibgp 5
#  !
#  address-family l2vpn evpn
#   advertise-svi-ip
#   advertise ipv6 unicast route-map aa
#   rd 3.3.3.3:33
#   route-target import 22:22
#   route-target export 33:33
#   dup-addr-detection
#   advertise-pip ip 1.1.1.1 peer-ip 2.2.2.2
#   !
#   vni 1
#    advertise-default-gw
#    advertise-svi-ip
#    rd 5.5.5.5:55
#    route-target import 88:88
#    route-target export 77:77
#

- name: Delete BGP Address family configuration from the device
  dellemc.enterprise_sonic.sonic_bgp_af:
    config:
      - bgp_as: 51
        address_family:
          afis:
            - afi: l2vpn
              safi: evpn
              advertise_pip: true
              advertise_pip_ip: "1.1.1.1"
              advertise_pip_peer_ip: "2.2.2.2"
              advertise_svi_ip: true
              advertise_all_vni: false
              advertise_default_gw: false
              route_advertise_list:
                - advertise_afi: ipv6
                  route_map: aa
              rd: "3.3.3.3:33"
              rt_in:
                - "22:22"
              rt_out:
                - "33:33"
              vnis:
                - vni_number: 1
            - afi: ipv4
              safi: unicast
            - afi: ipv6
              safi: unicast
              max_path:
                ebgp: 2
                ibgp: 5
              redistribute:
                - metric: "21"
                  protocol: connected
                  route_map: bb
                - metric: "27"
                  protocol: ospf
                  route_map: aa
                - metric: "26"
                  protocol: static
                  route_map: bb
      - bgp_as: 51
        vrf_name: VrfReg1
        address_family:
          afis:
            - afi: ipv4
              safi: unicast
              import:
                vrf:
                  vrf_list:
                    - default
                  route_map: rmap-1
              aggregate_address_config:
                - prefix: "1.1.1.1/1"
                - prefix: "5.5.5.5/5"
                  as_set: true
                  policy_name: rmap-1
                  summary_only: true
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration bgp
# !
# router bgp 51 vrf VrfReg1
#  log-neighbor-changes
#  timers 60 180
#  !
#  address-family ipv4 unicast
#   maximum-paths 1
#   maximum-paths ibgp 1
#   network 3.3.3.3/16
#   aggregate-address 5.5.5.5/5
#   dampening
# !
# router bgp 51
#  router-id 111.2.2.41
#  timers 60 180
#  !
#  address-family ipv6 unicast
#  !
#  address-family l2vpn evpn
#   dup-addr-detection
#

#  Using "deleted" state
#
#  Before state:
#  -------------
#
# sonic# show running-configuration bgp
# !
# router bgp 51 vrf VrfReg1
#  log-neighbor-changes
#  timers 60 180
#  !
#  address-family ipv4 unicast
#   maximum-paths 1
#   maximum-paths ibgp 1
#   network 3.3.3.3/16
#   aggregate-address 5.5.5.5/5 as-set summary-only route-map rmap-1
#   dampening
#   import vrf route-map rmap-1
#   import vrf default
# !
# router bgp 51
#  router-id 111.2.2.41
#  timers 60 180
#  !
#  address-family ipv6 unicast
#  !
#  address-family l2vpn evpn
#

- name: Delete All BGP address family configurations
  dellemc.enterprise_sonic.sonic_bgp_af:
    config:
    state: deleted


# After state:
# ------------
#
# sonic# show running-configuration bgp
# !
# router bgp 51 vrf VrfReg1
#  log-neighbor-changes
#  timers 60 180
# !
# router bgp 51
#  router-id 111.2.2.41
#  timers 60 180
#

#  Using "merged" state
#
#  Before state:
#  -------------
#
# sonic# show running-configuration bgp
# !
# router bgp 51 vrf VrfReg1
#  log-neighbor-changes
#  timers 60 180
# !
# router bgp 51
#  router-id 111.2.2.41
#  timers 60 180
#  !
#  address-family l2vpn evpn
#   dup-addr-detection
#

- name: Merge provided BGP address family configuration on the device.
  dellemc.enterprise_sonic.sonic_bgp_af:
    config:
      - bgp_as: 51
        address_family:
          afis:
            - afi: l2vpn
              safi: evpn
              advertise_pip: true
              advertise_pip_ip: "3.3.3.3"
              advertise_pip_peer_ip: "4.4.4.4"
              advertise_svi_ip: true
              advertise_all_vni: false
              advertise_default_gw: false
              dup_addr_detection:
                freeze: permanent
                max_moves: 10
                time: 600
              route_advertise_list:
                - advertise_afi: ipv4
                  route_map: bb
              rd: "1.1.1.1:11"
              rt_in:
                - "12:12"
              rt_out:
                - "13:13"
              vnis:
                - vni_number: 1
                  advertise_default_gw: true
                  advertise_svi_ip: true
                  rd: "5.5.5.5:55"
                  rt_in:
                    - "88:88"
                  rt_out:
                    - "77:77"
            - afi: ipv4
              safi: unicast
              network:
                - 2.2.2.2/16
                - 192.168.10.1/32
              dampening: true
              aggregate_address_config:
                - prefix: 1.1.1.1/1
                  as_set: true
                  policy_name: bb
                  summary_only: true
            - afi: ipv6
              safi: unicast
              max_path:
                ebgp: 4
                ibgp: 5
              redistribute:
                - metric: "21"
                  protocol: connected
                  route_map: bb
                - metric: "27"
                  protocol: ospf
                  route_map: aa
                - metric: "26"
                  protocol: static
                  route_map: bb
      - bgp_as: 51
        vrf_name: VrfReg1
        address_family:
          afis:
            - afi: ipv4
              safi: unicast
              import:
                vrf:
                  vrf_list:
                    - default
                  route_map: rmap-1
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration bgp
# !
# router bgp 51 vrf VrfReg1
#  log-neighbor-changes
#  timers 60 180
#  !
#  address-family ipv4 unicast
#   maximum-paths 1
#   maximum-paths ibgp 1
#   import vrf route-map rmap-1
#   import vrf default
# !
# router bgp 51
#  router-id 111.2.2.41
#  timers 60 180
#  !
#  address-family ipv4 unicast
#   network 2.2.2.2/16
#   network 192.168.10.1/32
#   aggregate-address 1.1.1.1/1 as-set summary-only route-map bb
#   dampening
#  !
#  address-family ipv6 unicast
#   redistribute connected route-map bb metric 21
#   redistribute ospf route-map aa metric 27
#   redistribute static route-map bb metric 26
#   maximum-paths 4
#   maximum-paths ibgp 5
#  !
#  address-family l2vpn evpn
#   advertise-svi-ip
#   advertise ipv4 unicast route-map bb
#   rd 1.1.1.1:11
#   route-target import 12:12
#   route-target import 13:13
#   dup-addr-detection max-moves 10 time 600
#   dup-addr-detection freeze permanent
#   advertise-pip ip 3.3.3.3 peer-ip 4.4.4.4
#   !
#   vni 1
#    advertise-default-gw
#    advertise-svi-ip
#    rd 5.5.5.5:55
#    route-target import 88:88
#    route-target export 77:77
#

# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration bgp
# !
# router bgp 51 vrf VrfReg1
#  log-neighbor-changes
#  timers 60 180
#  !
#  address-family ipv4 unicast
#   maximum-paths 1
#   maximum-paths ibgp 1
#   network 3.3.3.3/16
#   dampening
# !
# router bgp 51 vrf VrfReg2
#  log-neighbor-changes
#  timers 60 180
#  !
#  address-family ipv4 unicast
#   maximum-paths 1
#   maximum-paths ibgp 1
#   import vrf route-map rmap-1
#   import vrf default
# !
# router bgp 51
#  router-id 111.2.2.41
#  log-neighbor-changes
#  timers 60 180
#  !
#  address-family ipv4 unicast
#   redistribute connected route-map bb metric 21
#   redistribute ospf route-map bb metric 27
#   maximum-paths 1
#   maximum-paths ibgp 1
#   network 2.2.2.2/16
#   network 192.168.10.1/32
#   aggregate-address 5.5.5.5/5 as-set summary-only route-map bb
#   dampening
#  !
#  address-family ipv6 unicast
#   redistribute static route-map aa metric 26
#   maximum-paths 4
#   maximum-paths ibgp 5
#  !
#  address-family l2vpn evpn
#   advertise-all-vni
#   advertise-svi-ip
#   advertise ipv4 unicast route-map bb
#   rd 1.1.1.1:11
#   route-target import 12:12
#   route-target export 13:13
#   advertise-pip ip 3.3.3.3 peer-ip 4.4.4.4
#   no dup-addr-detection
#   !
#   vni 1
#    advertise-default-gw
#    advertise-svi-ip
#    rd 5.5.5.5:55
#    route-target import 88:88
#    route-target export 77:77
#

- name: Replace device configuration of address families of specified BGP AS with provided configuration.
  dellemc.enterprise_sonic.sonic_bgp_af:
    config:
      - bgp_as: 51
        address_family:
          afis:
            - afi: l2vpn
              safi: evpn
              advertise_pip: true
              advertise_pip_ip: "3.3.3.3"
              advertise_pip_peer_ip: "4.4.4.4"
              advertise_svi_ip: true
              advertise_all_vni: true
              advertise_default_gw: false
              route_advertise_list:
                - advertise_afi: ipv4
                  route_map: bb
              rd: "1.1.1.1:11"
              rt_in:
                - "22:22"
              rt_out:
                - "13:13"
              vnis:
                - vni_number: 5
                  advertise_default_gw: true
                  advertise_svi_ip: true
                  rd: "10.10.10.10:55"
                  rt_in:
                    - "88:88"
                  rt_out:
                    - "77:77"
            - afi: ipv4
              safi: unicast
              network:
                - 2.2.2.2/16
                - 192.168.10.1/32
              dampening: true
              redistribute:
                - protocol: connected
                - protocol: ospf
                  metric: 30
              aggregate-address-config:
                - prefix: '5.5.5.5/5'
                  as_set: true
      - bgp_as: 51
        vrf_name: VrfReg2
        address_family:
          afis:
            - afi: ipv4
              safi: unicast
              import:
                vrf:
                  vrf_list:
                    - VrfReg1
                  route_map: rmap-reg1
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration bgp
# !
# router bgp 51 vrf VrfReg1
#  log-neighbor-changes
#  timers 60 180
#  !
#  address-family ipv4 unicast
#   maximum-paths 1
#   maximum-paths ibgp 1
#   network 3.3.3.3/16
#   dampening
# !
# router bgp 51 vrf VrfReg2
#  log-neighbor-changes
#  timers 60 180
#  !
#  address-family ipv4 unicast
#   maximum-paths 1
#   maximum-paths ibgp 1
#   import vrf route-map rmap-reg1
#   import vrf VrfReg1
# !
# router bgp 51
#  router-id 111.2.2.41
#  log-neighbor-changes
#  timers 60 180
#  !
#  address-family ipv4 unicast
#   redistribute connected
#   redistribute ospf metric 30
#   maximum-paths 1
#   maximum-paths ibgp 1
#   network 2.2.2.2/16
#   network 192.168.10.1/32
#   aggregate-address 5.5.5.5/5 as-set
#   dampening
#  !
#  address-family ipv6 unicast
#   redistribute static route-map aa metric 26
#   maximum-paths 4
#   maximum-paths ibgp 5
#  !
#  address-family l2vpn evpn
#   advertise-all-vni
#   advertise-svi-ip
#   advertise ipv4 unicast route-map bb
#   rd 1.1.1.1:11
#   route-target import 22:22
#   route-target export 13:13
#   dup-addr-detection
#   advertise-pip ip 3.3.3.3 peer-ip 4.4.4.4
#   !
#   vni 5
#    advertise-default-gw
#    advertise-svi-ip
#    rd 10.10.10.10:55
#    route-target import 88:88
#    route-target export 77:77
#

# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show running-configuration bgp
# !
# router bgp 51 vrf VrfReg1
#  log-neighbor-changes
#  timers 60 180
#  !
#  address-family ipv4 unicast
#   maximum-paths 1
#   maximum-paths ibgp 1
#   network 3.3.3.3/16
#   dampening
#   import vrf route-map rmap-1
#   import vrf default
# !
# router bgp 51
#  router-id 111.2.2.41
#  log-neighbor-changes
#  timers 60 180
#  !
#  address-family ipv4 unicast
#   redistribute connected route-map bb metric 21
#   redistribute ospf route-map bb metric 27
#   maximum-paths 1
#   maximum-paths ibgp 1
#   network 2.2.2.2/16
#   network 192.168.10.1/32
#   dampening
#  !
#  address-family ipv6 unicast
#   redistribute static route-map aa metric 26
#   maximum-paths 4
#   maximum-paths ibgp 5
#  !
#  address-family l2vpn evpn
#   advertise-all-vni
#   advertise-svi-ip
#   advertise ipv4 unicast route-map bb
#   rd 1.1.1.1:11
#   route-target import 12:12
#   route-target export 13:13
#   dup-addr-detection max-moves 10 time 600
#   dup-addr-detection freeze permanent
#   advertise-pip ip 3.3.3.3 peer-ip 4.4.4.4
#   !
#   vni 1
#    advertise-default-gw
#    advertise-svi-ip
#    rd 5.5.5.5:55
#    route-target import 88:88
#    route-target export 77:77
#

- name: Override device configuration of BGP address families with provided configuration.
  dellemc.enterprise_sonic.sonic_bgp_af:
    config:
      - bgp_as: 51
        address_family:
          afis:
            - afi: l2vpn
              safi: evpn
              advertise_pip: true
              advertise_pip_ip: "3.3.3.3"
              advertise_pip_peer_ip: "4.4.4.4"
              advertise_svi_ip: true
              advertise_all_vni: true
              advertise_default_gw: false
              dup_addr_detection:
                freeze: '600'
              route_advertise_list:
                - advertise_afi: ipv4
                  route_map: bb
              rd: "1.1.1.1:11"
              rt_in:
                - "22:22"
              rt_out:
                - "13:13"
              vnis:
                - vni_number: 5
                  advertise_default_gw: true
                  advertise_svi_ip: true
                  rd: "10.10.10.10:55"
                  rt_in:
                    - "88:88"
                  rt_out:
                    - "77:77"
            - afi: ipv4
              safi: unicast
              network:
                - 2.2.2.2/16
                - 192.168.10.1/32
              dampening: true
              redistribute:
                - protocol: connected
                - protocol: ospf
                  metric: 30
              aggregate_address_config:
                - prefix: 4.4.4.4/4
                  as_set: true
                  policy_name: bb
                  summary_only: true
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration bgp
# !
# router bgp 51 vrf VrfReg1
#  log-neighbor-changes
#  timers 60 180
# !
# router bgp 51
#  router-id 111.2.2.41
#  log-neighbor-changes
#  timers 60 180
#  !
#  address-family ipv4 unicast
#   redistribute connected
#   redistribute ospf metric 30
#   maximum-paths 1
#   maximum-paths ibgp 1
#   network 2.2.2.2/16
#   network 192.168.10.1/32
#   aggregate-address 4.4.4.4/4 as-set summary-only route-map bb
#   dampening
#  !
#  address-family l2vpn evpn
#   advertise-all-vni
#   advertise-svi-ip
#   advertise ipv4 unicast route-map bb
#   rd 1.1.1.1:11
#   route-target import 22:22
#   route-target export 13:13
#   dup-addr-detection
#   dup-addr-detection freeze 600
#   advertise-pip ip 3.3.3.3 peer-ip 4.4.4.4
#   !
#   vni 5
#    advertise-default-gw
#    advertise-svi-ip
#    rd 10.10.10.10:55
#    route-target import 88:88
#    route-target export 77:77
#
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: list
  sample: >
    The configuration returned is always in the same format
    as the parameters above.
after:
  description: The resulting configuration module invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned always in the same format
    as the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.bgp_af.bgp_af import Bgp_afArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.bgp_af.bgp_af import Bgp_af


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Bgp_afArgs.argument_spec,
                           supports_check_mode=True)

    result = Bgp_af(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
