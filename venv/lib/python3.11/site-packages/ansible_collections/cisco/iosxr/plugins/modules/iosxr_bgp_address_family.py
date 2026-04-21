#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for iosxr_bgp_address_family
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: iosxr_bgp_address_family
short_description: Resource module to configure BGP Address family.
description:
- This module configures and manages the attributes of BGP address family on Cisco IOS-XR platforms.
version_added: 2.0.0
author: Ashwini Mhatre (@amhatre)
notes:
- This module works with connection C(network_cli).
options:
    config:
      description: A list of configurations for BGP address family.
      type: dict
      suboptions:
        as_number:
          description: Autonomous system number.
          type: str
        address_family:
          description: Enable address family and enter its config mode
          type: list
          elements: dict
          suboptions:
            afi:
              description: address family.
              type: str
              choices: ['ipv4', 'ipv6', 'l2vpn', 'link-state', 'vpnv4', 'vpnv6']
            safi:
              description: Address Family modifier
              type: str
              choices: [ 'flowspec', 'mdt', 'multicast', 'mvpn', 'rt-filter', 'tunnel', 'unicast', 'evpn', 'mspw', 'vpls-vpws', 'link-state' ]
            vrf:
              description: VRF name.
              type: str
            additional_paths: &additional_paths
              description: BGP additional-paths commands
              type: str
              choices: [ 'send', 'receive' ]
            advertise_best_external: &advertise
              description: Advertise best-external path.
              type: bool
            aggregate_address:
              description: Configure BGP aggregate entries.
              type: list
              elements: dict
              suboptions:
                value:
                  type: str
                  description: IPv4 Aggregate address and mask or masklength.
                as_set:
                  type: bool
                  description: Generate AS set path information.
                as_confed_set:
                  type: bool
                  description: Generate AS confed set path information.
                summary_only:
                  type: bool
                  description: Filter more specific routes from updates.
                route_policy:
                  description: Policy to condition advertisement, suppression, and attributes.
                  type: str
            allocate_label:
              type: dict
              description: Allocate labels.
              suboptions:
                all:
                  type: bool
                  description:  Allocate labels for all prefixes.
                route_policy:
                  description: Use a route policy to select prefixes for label allocation.
                  type: str
            as_path_loopcheck_out_disable:
              type: bool
              description: Configure AS Path loop checking for outbound updates.
            bgp:
              type: dict
              description: BGP Commands.
              suboptions:
                attribute_download: &attribute_download
                  type: bool
                  description: Configure attribute download for this address-family.
                bestpath:
                  type: dict
                  description: Change default route selection criteria.
                  suboptions:
                    origin_as:
                      description: BGP origin-AS knobs.
                      type: dict
                      suboptions:
                        use:
                          description: BGP origin-AS knobs.
                          type: dict
                          suboptions:
                            validity:
                              description: BGP bestpath selection will use origin-AS validity
                              type: bool
                        allow:
                          description: BGP origin-AS knobs.
                          type: dict
                          suboptions:
                            invalid:
                              description: BGP bestpath selection will allow 'invalid' origin-AS
                              type: bool
                client_to_client:
                  type: dict
                  description: Configure client to client route reflection.
                  suboptions:
                    reflection:
                      type: dict
                      description: disable client to client reflection of cluster id.
                      suboptions:
                        cluster_id_disable:
                          type: dict
                          description: ID of Cluster for which reflection is to be disabled.
                          suboptions:
                            cluster_id:
                              type: str
                              description: ID of Cluster for which reflection is to be disabled.
                            disable:
                              type: bool
                              description: disable cluster id.
                        disable:
                          type: bool
                          description: disable reflection.
                dampening:
                  type: dict
                  description: Enable route-flap dampening
                  suboptions:
                    set:
                      type: bool
                      description: Enable dampening.
                    value:
                      type: int
                      description: Half-life time for the penalty
                    route_policy:
                      description: Route policy to specify criteria for dampening.
                      type: str
                label_delay:
                  type: dict
                  description: Specify delay for batching label processing
                  suboptions:
                    delay_second_parts:
                      type: int
                      description: Delay, seconds part <0-10>.
                    delay_ms_parts:
                      type: int
                      description: milliseconds part <0-999>.
                import_delay:
                  type: dict
                  description: Specify delay for batching import processing.
                  suboptions:
                    delay_second_parts:
                      type: int
                      description: Delay, seconds part <0-10>.
                    delay_ms_parts:
                      type: int
                      description: milliseconds part <0-999>.
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
                        signal:
                          description: Signal origin-AS validity towards peers.
                          type: dict
                          suboptions:
                            ibgp:
                              description: Signal origin-AS validity towards iBGP peers
                              type: bool
                scan_time:
                  description: Configure background scanner interval for this address-family Example- <5-3600>.
                  type: int
            default_martian_check_disable:
              type: bool
              description: Martian check default
            distance: &distance
              type: dict
              description: Define an administrative distance.
              suboptions:
                routes_external_to_as:
                  type: int
                  description: Distance for routes external to the AS <1-255>.
                routes_internal_to_as:
                  type: int
                  description: Distance for routes internal to the AS <1-255>.
                local_routes:
                  type: int
                  description: Distance for local routes <1-255>.
            dynamic_med:
              type: int
              description: Dynamic MED Interval.
            maximum_paths:
              type: dict
              description: Forward packets over multiple paths.
              suboptions:
                ibgp:
                  type: dict
                  description: iBGP-multipath.
                  suboptions:
                    max_path_value:
                      type: int
                      description: <2-64>  Number of paths (limit includes backup path).
                    order_igp_metric:
                      description: Order candidate multipaths for selection as per configured number(cisco-support).
                      type: bool
                    selective_order_igp_metric:
                      description: Allow multipaths only from marked neighbors
                      type: bool
                    unequal_cost:
                      type: dict
                      description: Allow multipaths to have different BGP nexthop IGP metrics.
                      suboptions:
                        set:
                          type: bool
                          description: set unequal_cost.
                        order_igp_metric:
                          description: Order candidate multipaths for selection as per configured number(cisco-support).
                          type: bool
                        selective_order_igp_metric:
                          description: Allow multipaths only from marked neighbors
                          type: bool
                ebgp:
                  type: dict
                  description: ebgp-multipath.
                  suboptions:
                    max_path_value:
                      type: int
                      description: <2-64>  Number of paths (limit includes backup path).
                    order_igp_metric:
                      description: Order candidate multipaths for selection as per configured number(cisco-support).
                      type: bool
                    selective_order_igp_metric:
                      description: Allow multipaths only from marked neighbors
                      type: bool
                eibgp:
                  type: dict
                  description: eiBGP-multipath.
                  suboptions:
                    max_path_value:
                      type: int
                      description: <2-64>  Number of paths (limit includes backup path).
                    order_igp_metric:
                      description: Order candidate multipaths for selection as per configured number(cisco-support).
                      type: bool
                    selective_order_igp_metric:
                      description: Allow multipaths only from marked neighbors
                      type: bool
            networks:
              type: list
              description: Specify a network to announce via BGP.
              elements: dict
              suboptions:
                network:
                  type: str
                  description: Specify a network to announce via BGP.
                backdoor_route_policy:
                  type: str
                  description: Specify a BGP backdoor route.
                route_policy:
                  type: str
                  description: Route-policy to modify the attributes.
            nexthop:
              type: dict
              description: Nexthop
              suboptions:
                resolution_prefix_length_minimum:
                  type: int
                  description: Set minimum prefix-length for nexthop resolution.
                  choices: [0,32]
                route_policy:
                  type: str
                  description: Policy to filter out nexthop notification.
                trigger_delay_critical:
                  description: For critical notification
                  type: int
                trigger_delay_non_critical:
                  type: int
                  description: For non critical notification.
            optimal_route_reflection:
              type: dict
              description: Configure optimal-route-reflection group.
              suboptions:
                group_name:
                  type: str
                  description: ORR group name - maximum 32 characters.
                primary_address:
                  type: str
                  description: IPv4 primary address.
                secondary_address:
                  type: str
                  description: IPv4 secondary address
            permanent_network_route_policy:
              type: str
              description: Name of the policy.
            retain_local_label:
              type: int
              description: Label retention time in minutes <3-60>.
            table_policy:
              type: str
              description: Configure policy for installation of routes to RIB.
            update:
              type: dict
              description: BGP Update generation configuration.
              suboptions:
                limit:
                  type: dict
                  description: Update limit.
                  suboptions:
                    sub_group:
                      type: dict
                      description: Update limit for address-family.
                      suboptions:
                        ibgp:
                          type: int
                          description: Update limit for iBGP sub-groups<1-512.
                        ebgp:
                          type: int
                          description: Update limit for eBGP sub-groups<1-512.
                    address_family:
                      type: int
                      description: Update limit for sub-groups.
                wait_install:
                  type: bool
                  description: Wait for route install.
            redistribute:
              type: list
              elements: dict
              description: Redistribute information from another routing protocol.
              suboptions:
                protocol:
                  description: Specifies the protocol for configuring redistribute information.
                  type: str
                  choices:
                    - ospf
                    - application
                    - eigrp
                    - isis
                    - static
                    - connected
                    - lisp
                    - mobile
                    - rip
                    - subscriber
                  required: true
                id:
                  type: str
                  description:
                    - Identifier for the routing protocol for configuring redistribute
                      information. Example-application name, eigrp/is-is instance name, ospf tag
                    - Valid for protocols 'ospf', 'eigrp', 'isis' and 'application'.
                metric:
                  description:
                    - Specifies the metric for redistributed routes.
                  type: int
                route_policy:
                    description:
                      - Specifies the route policy reference.
                    type: str
                internal:
                  type: bool
                  description: Redistribute EIGRP internal routes.applicable for eigrp.
                external:
                  type: bool
                  description: Redistribute EIGRP external routes.applicable for eigrp.
                level:
                  type: str
                  description:
                    - Redistribute routes from the specified ISIS levels.
                    - Redistribute ISIS level 1 routes
                    - Redistribute ISIS level 1 inter-area routes
                    - Redistribute ISIS level 2 ISIS routes
                  choices: [ '1', '2', '1-inter-area' ]
                nssa_external:
                  type: bool
                  description: Redistribute OSPF NSSA external routes.applicable for ospf.
                external_ospf:
                    type: int
                    description: Redistribute OSPF external routes.applicable for ospf.
                    choices: [ 1, 2 ]
            inter_as_install:
              type: bool
              description: Install remote mvpn routes in default vrf.This is applicable for mvpn afi.
            segmented_multicast:
              type: bool
              description:  Enable segmented multicast.This is applicable for mvpn afi.
            global_table_multicast:
              type: bool
              description: Enable global table multicast.
            vrf_all_conf:
              type: dict
              description: configuration is for all vrfs and its applicable for afi vpn6 and modifier unicast.
              suboptions:
                source_rt_import_policy:
                  type: bool
                  description: Source import route-targets from import-policy.
                table_policy:
                  type: str
                  description: Configure policy for installation of routes to RIB.
                label_mode:
                  type: dict
                  description: Label-related configuration.
                  suboptions:
                    per_ce: &per_ce
                      type: bool
                      description: Set per CE label mode
                    per_vrf: &per_vrf
                      type: bool
                      description: Set per VRF label mode.
                    route_policy: &route_policy
                      type: str
                      description: Use a route policy to select prefixes for label allocation mode.
            weight: &wt
              type: dict
              description: Define or modify weight.
              suboptions:
                reset_on_import_disable:
                  type: bool
                  description: disable reset_on_import.
                reset_on_import:
                  type: bool
                  description: set reset_on_import.
            allow_vpn_default_originate:
              type: bool
              description: Allow sending default originate route to VPN neighbor.
            label_mode:
              type: dict
              description: label configuration.
              suboptions:
                per_ce: *per_ce
                per_vrf: *per_vrf
                route_policy: *route_policy
                per_prefix:
                  type: bool
                  description: Set per perfix label mode.
            mvpn_single_forwarder_selection_all:
              type: bool
              description: Enable single forwarder selection  for all
            mvpn_single_forwarder_selection_highest_ip_address:
              type: bool
              description: Enable single forwarder selection  for PE with highest ip address.
            route_target_download:
              description: Route target RIB installation.
              type: bool
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
#  address-family vpnv4 unicast
#  vrf vrf1
#   rd auto
- name: Merge the provided configuration with the existing running configuration
  cisco.iosxr.iosxr_bgp_address_family:
    state: merged
    config:
      as_number: '65536'
      address_family:
        - afi: ipv4
          safi: unicast
          vrf: vrf1
          dynamic_med: 9
          redistribute:
            - protocol: connected
              metric: 10
        - afi: ipv4
          safi: unicast
          dynamic_med: 10
          redistribute:
            - protocol: application
              id: test1
              metric: 10
          bgp:
            scan_time: 20
            attribute_download: true
          advertise_best_external: true
          allocate_label:
            all: true
# Task output
# -------------
# commands:
# - router bgp 65536
# - address-family ipv4 unicast
# - advertise best-external
# - allocate-label all
# - bgp attribute-download
# - bgp scan-time 20
# - dynamic-med interval 10
# - redistribute application test1 metric 10
# - vrf vrf1
# - address-family ipv4 unicast
# - dynamic-med interval 9
# - redistribute connected metric 10
#
#
# after:
#   as_number: "65536"
#   address_family:
#     - afi: "ipv4"
#       safi: "unicast"
#       vrf: vrf1
#       dynamic_med: 9
#       redistribute:
#         - protocol: connected
#           metric: 10
#     - afi: "ipv4"
#       safi: "unicast"
#       dynamic_med: 10
#       redistribute:
#         - protocol: application
#           id: "test1"
#           metric: 10
#       bgp:
#         scan_time: 20
#         attribute_download: true
#       advertise_best_external: true
#       allocate_label:
#         all: true
#
# After state:
# -------------
# RP/0/0/CPU0:iosxr-02#show running-config router bgp
# Sat Feb 20 03:49:43.618 UTC
# router bgp 65536
#  bgp router-id 192.0.1.1
#  address-family ipv4 unicast
#    advertise best-external
#    allocate-label all
#    bgp attribute-download
#    bgp scan-time 20
#  address-family vpnv4 unicast
#  vrf vrf1
#   rd auto
#   address-family ipv4 unicast
#     dynamic-med interval 9
#     redistribute connected metric 10
#
# Using replaced
# Before state:
# -------------
# RP/0/0/CPU0:iosxr-02#show running-config router bgp
# Sat Feb 20 03:49:43.618 UTC
# router bgp 65536
#  bgp router-id 192.0.1.1
#  address-family ipv4 unicast
#    advertise best-external
#    allocate-label all
#    bgp attribute-download
#    bgp scan-time 20
#  address-family vpnv4 unicast
#  vrf vrf1
#   rd auto
#   address-family ipv4 unicast
#     dynamic-med interval 9
#     redistribute connected metric 10
#
#
- name: Replace the provided configuration with the existing running configuration
  cisco.iosxr.iosxr_bgp_address_family:
    state: replaced
    config:
      as_number: '65536'
      address_family:
        - afi: ipv4
          safi: unicast
          vrf: vrf1
          dynamic_med: 10
# Task output
# -------------
# commands:
# - router bgp 65536
# - vrf vrf1
# - address-family ipv4 unicast
# - dynamic-med interval 10
# - no redistribute connected metric 10
#
# after:
#   as_number: "65536"
#   address_family:
#     - afi: "ipv4"
#       safi: "unicast"
#       vrf: vrf1
#       dynamic_med: 10
#     - afi: "ipv4"
#       safi: "unicast"
#       dynamic_med: 10
#       redistribute:
#         - protocol: application
#           id: "test1"
#           metric: 10
#       bgp:
#         scan_time: 20
#         attribute_download: true
#       advertise_best_external: true
#       allocate_label:
#         all: true
# After state:
# -------------
# RP/0/0/CPU0:iosxr-02#show running-config router bgp
# Sat Feb 20 03:49:43.618 UTC
# router bgp 65536
#  bgp router-id 192.0.1.1
#  address-family ipv4 unicast
#    advertise best-external
#    allocate-label all
#    bgp attribute-download
#    bgp scan-time 20
#  address-family vpnv4 unicast
#  vrf vrf1
#   rd auto
#   address-family ipv4 unicast
#     dynamic-med interval 10
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
#    advertise best-external
#    allocate-label all
#    bgp attribute-download
#    bgp scan-time 20
#  address-family vpnv4 unicast
#  vrf vrf1
#   rd auto
#   address-family ipv4 unicast
#     dynamic-med interval 9
#     redistribute connected metric 10
#
#
- name: Override the provided configuration with the existing running configuration
  cisco.iosxr.iosxr_bgp_address_family:
    state: overridden
    config:
      as_number: '65536'
      address_family:
        - afi: ipv4
          safi: unicast
          vrf: vrf1
          dynamic_med: 10

# Task output
# -------------
# commands:
# - router bgp 65536
# - no address-family ipv4 unicast
# - vrf vrf1
# - address-family ipv4 unicast
# - dynamic-med interval 10
# - no redistribute connected metric 10
#
#
# after:
#   as_number: "65536"
#   address_family:
#     - afi: "ipv4"
#       safi: "unicast"
#       vrf: vrf1
#       dynamic_med: 10
#
# After state:
# -------------
# RP/0/0/CPU0:iosxr-02#show running-config router bgp
# Sat Feb 20 03:49:43.618 UTC
# router bgp 65536
#  bgp router-id 192.0.1.1
#  address-family vpnv4 unicast
#  vrf vrf1
#   rd auto
#   address-family ipv4 unicast
#     dynamic-med interval 10
#
#
# Using deleted
# Before state:
# -------------
# RP/0/0/CPU0:iosxr-02#show running-config router bgp
# Sat Feb 20 03:49:43.618 UTC
# router bgp 65536
#  bgp router-id 192.0.1.1
#  address-family ipv4 unicast
#    advertise best-external
#    allocate-label all
#    bgp attribute-download
#    bgp scan-time 20
#  address-family vpnv4 unicast
#  vrf vrf1
#   rd auto
#   address-family ipv4 unicast
#     dynamic-med interval 9
#     redistribute connected metric 10
#
#
- name: Delete the provided configuration
  cisco.iosxr.iosxr_bgp_address_family:
    state: deleted
    config:

# Task output
# -------------
# commands:
# - router bgp 65536
# - no address-family ipv4 unicast
# - vrf vrf1
# - no address-family ipv4 unicast
#
#
# after:
#   as_number: "65536"
#
#
# After state:
# -------------
# RP/0/0/CPU0:iosxr-02#show running-config router bgp
# Sat Feb 20 03:49:43.618 UTC
# router bgp 65536
#  bgp router-id 192.0.1.1
#  address-family vpnv4 unicast
#  vrf vrf1
#   rd auto
#
# Using rendered
# -------------
#
- name: rendered state example
  cisco.iosxr.iosxr_bgp_address_family:
    state: rendered
    config:
      as_number: '65536'
      address_family:
        - afi: ipv4
          safi: unicast
          vrf: vrf1
          dynamic_med: 9
          redistribute:
            - protocol: connected
              metric: 10
        - afi: ipv4
          safi: unicast
          dynamic_med: 10
          redistribute:
            - protocol: application
              id: test1
              metric: 10
          bgp:
            scan_time: 20
            attribute_download: true
          advertise_best_external: true
          allocate_label:
            all: true
# Task output
# -------------
# commands:
# - router bgp 65536
# - address-family ipv4 unicast
# - advertise best-external
# - allocate-label all
# - bgp attribute-download
# - bgp scan-time 20
# - dynamic-med interval 10
# - redistribute application test1 metric 10
# - vrf vrf1
# - address-family ipv4 unicast
# - dynamic-med interval 9
# - redistribute connected metric 10
#
# Using gathered
# -------------
- name: Gather existing running configuration
  cisco.iosxr.iosxr_bgp_address_family:
    state: gathered
    config:
      as_number: '65536'
      address_family:
        - afi: ipv4
          safi: unicast
          vrf: vrf1
          dynamic_med: 9
          redistribute:
            - protocol: connected
              metric: 10
        - afi: ipv4
          safi: unicast
          dynamic_med: 10
          redistribute:
            - protocol: application
              id: test1
              metric: 10
          bgp:
            scan_time: 20
            attribute_download: true
          advertise_best_external: true
          allocate_label:
            all: true
# gathered:
#   as_number: "65536"
#   address_family:
#     - afi: "ipv4"
#       safi: "unicast"
#       vrf: vrf1
#       dynamic_med: 9
#       redistribute:
#         - protocol: connected
#           metric: 10
#     - afi: "ipv4"
#       safi: "unicast"
#       dynamic_med: 10
#       redistribute:
#         - protocol: application
#           id: "test1"
#           metric: 10
#       bgp:
#         scan_time: 20
#         attribute_download: true
#       advertise_best_external: true
#       allocate_label:
#         all: true
#
# Using parsed
#
# parsed.cfg
# ------------
# router bgp 65536
#  bgp router-id 192.0.1.1
#  address-family ipv4 unicast
#    advertise best-external
#    allocate-label all
#    bgp attribute-download
#    bgp scan-time 20
#  address-family vpnv4 unicast
#  vrf vrf1
#   rd auto
#   address-family ipv4 unicast
#     dynamic-med interval 9
#     redistribute connected metric 10
#
- name: Parse externally provided BGP neighbor AF config
  cisco.iosxr.iosxr_bgp_address_family:
    running_config: "{{ lookup('file', 'parsed.cfg') }}"
    state: parsed

# Task output (redacted)
# -----------------------
# parsed:
#   as_number: "65536"
#   address_family:
#     - afi: "ipv4"
#       safi: "unicast"
#       vrf: vrf1
#       dynamic_med: 9
#       redistribute:
#         - protocol: connected
#           metric: 10
#     - afi: "ipv4"
#       safi: "unicast"
#       dynamic_med: 10
#       redistribute:
#         - protocol: application
#           id: "test1"
#           metric: 10
#       bgp:
#         scan_time: 20
#         attribute_download: true
#       advertise_best_external: true
#       allocate_label:
#         all: true
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.bgp_address_family.bgp_address_family import (
    Bgp_address_familyArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.config.bgp_address_family.bgp_address_family import (
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
