#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright: (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
---
module: fortios_router_bgp
short_description: Configure BGP in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify router feature and bgp category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks

    - The module supports check_mode.

requirements:
    - ansible>=2.15
options:
    access_token:
        description:
            - Token-based authentication.
              Generated from GUI of Fortigate.
        type: str
        required: false
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    member_path:
        type: str
        description:
            - Member attribute path to operate on.
            - Delimited by a slash character if there are more than one attribute.
            - Parameter marked with member_path is legitimate for doing member operation.
    member_state:
        type: str
        description:
            - Add or delete a member under specified attribute path.
            - When member_state is specified, the state option is ignored.
        choices:
            - 'present'
            - 'absent'

    router_bgp:
        description:
            - Configure BGP.
        default: null
        type: dict
        suboptions:
            additional_path:
                description:
                    - Enable/disable selection of BGP IPv4 additional paths.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            additional_path_select:
                description:
                    - Number of additional paths to be selected for each IPv4 NLRI.
                type: int
            additional_path_select_vpnv4:
                description:
                    - Number of additional paths to be selected for each VPNv4 NLRI.
                type: int
            additional_path_select_vpnv6:
                description:
                    - Number of additional paths to be selected for each VPNv6 NLRI.
                type: int
            additional_path_select6:
                description:
                    - Number of additional paths to be selected for each IPv6 NLRI.
                type: int
            additional_path_vpnv4:
                description:
                    - Enable/disable selection of BGP VPNv4 additional paths.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            additional_path_vpnv6:
                description:
                    - Enable/disable selection of BGP VPNv6 additional paths.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            additional_path6:
                description:
                    - Enable/disable selection of BGP IPv6 additional paths.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            admin_distance:
                description:
                    - Administrative distance modifications.
                type: list
                elements: dict
                suboptions:
                    distance:
                        description:
                            - Administrative distance to apply (1 - 255).
                        type: int
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    neighbour_prefix:
                        description:
                            - Neighbor address prefix.
                        type: str
                    route_list:
                        description:
                            - Access list of routes to apply new distance to. Source router.access-list.name.
                        type: str
            aggregate_address:
                description:
                    - BGP aggregate address table.
                type: list
                elements: dict
                suboptions:
                    as_set:
                        description:
                            - Enable/disable generate AS set path information.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    prefix:
                        description:
                            - Aggregate prefix.
                        type: str
                    summary_only:
                        description:
                            - Enable/disable filter more specific routes from updates.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            aggregate_address6:
                description:
                    - BGP IPv6 aggregate address table.
                type: list
                elements: dict
                suboptions:
                    as_set:
                        description:
                            - Enable/disable generate AS set path information.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    prefix6:
                        description:
                            - Aggregate IPv6 prefix.
                        type: str
                    summary_only:
                        description:
                            - Enable/disable filter more specific routes from updates.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            always_compare_med:
                description:
                    - Enable/disable always compare MED.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            as:
                description:
                    - Router AS number, asplain/asdot/asdot+ format, 0 to disable BGP.
                type: str
            bestpath_as_path_ignore:
                description:
                    - Enable/disable ignore AS path.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bestpath_cmp_confed_aspath:
                description:
                    - Enable/disable compare federation AS path length.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bestpath_cmp_routerid:
                description:
                    - Enable/disable compare router ID for identical EBGP paths.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bestpath_med_confed:
                description:
                    - Enable/disable compare MED among confederation paths.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bestpath_med_missing_as_worst:
                description:
                    - Enable/disable treat missing MED as least preferred.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            client_to_client_reflection:
                description:
                    - Enable/disable client-to-client route reflection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            cluster_id:
                description:
                    - Route reflector cluster ID.
                type: str
            confederation_identifier:
                description:
                    - Confederation identifier.
                type: int
            confederation_peers:
                description:
                    - Confederation peers.
                type: list
                elements: dict
                suboptions:
                    peer:
                        description:
                            - Peer ID.
                        required: true
                        type: str
            cross_family_conditional_adv:
                description:
                    - Enable/disable cross address family conditional advertisement.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dampening:
                description:
                    - Enable/disable route-flap dampening.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dampening_max_suppress_time:
                description:
                    - Maximum minutes a route can be suppressed.
                type: int
            dampening_reachability_half_life:
                description:
                    - Reachability half-life time for penalty (min).
                type: int
            dampening_reuse:
                description:
                    - Threshold to reuse routes.
                type: int
            dampening_route_map:
                description:
                    - Criteria for dampening. Source router.route-map.name.
                type: str
            dampening_suppress:
                description:
                    - Threshold to suppress routes.
                type: int
            dampening_unreachability_half_life:
                description:
                    - Unreachability half-life time for penalty (min).
                type: int
            default_local_preference:
                description:
                    - Default local preference.
                type: int
            deterministic_med:
                description:
                    - Enable/disable enforce deterministic comparison of MED.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            distance_external:
                description:
                    - Distance for routes external to the AS.
                type: int
            distance_internal:
                description:
                    - Distance for routes internal to the AS.
                type: int
            distance_local:
                description:
                    - Distance for routes local to the AS.
                type: int
            ebgp_multipath:
                description:
                    - Enable/disable EBGP multi-path.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            enforce_first_as:
                description:
                    - Enable/disable enforce first AS for EBGP routes.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fast_external_failover:
                description:
                    - Enable/disable reset peer BGP session if link goes down.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            graceful_end_on_timer:
                description:
                    - Enable/disable to exit graceful restart on timer only.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            graceful_restart:
                description:
                    - Enable/disable BGP graceful restart capabilities.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            graceful_restart_time:
                description:
                    - Time needed for neighbors to restart (sec).
                type: int
            graceful_stalepath_time:
                description:
                    - Time to hold stale paths of restarting neighbor (sec).
                type: int
            graceful_update_delay:
                description:
                    - Route advertisement/selection delay after restart (sec).
                type: int
            holdtime_timer:
                description:
                    - Number of seconds to mark peer as dead.
                type: int
            ibgp_multipath:
                description:
                    - Enable/disable IBGP multi-path.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ignore_optional_capability:
                description:
                    - Do not send unknown optional capability notification message.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            keepalive_timer:
                description:
                    - Frequency to send keep alive requests.
                type: int
            log_neighbour_changes:
                description:
                    - Log BGP neighbor changes.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            multipath_recursive_distance:
                description:
                    - Enable/disable use of recursive distance to select multipath.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            neighbor:
                description:
                    - BGP neighbor table.
                type: list
                elements: dict
                suboptions:
                    activate:
                        description:
                            - Enable/disable address family IPv4 for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    activate_evpn:
                        description:
                            - Enable/disable address family L2VPN EVPN for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    activate_vpnv4:
                        description:
                            - Enable/disable address family VPNv4 for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    activate_vpnv6:
                        description:
                            - Enable/disable address family VPNv6 for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    activate6:
                        description:
                            - Enable/disable address family IPv6 for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    additional_path:
                        description:
                            - Enable/disable IPv4 additional-path capability.
                        type: str
                        choices:
                            - 'send'
                            - 'receive'
                            - 'both'
                            - 'disable'
                    additional_path_vpnv4:
                        description:
                            - Enable/disable VPNv4 additional-path capability.
                        type: str
                        choices:
                            - 'send'
                            - 'receive'
                            - 'both'
                            - 'disable'
                    additional_path_vpnv6:
                        description:
                            - Enable/disable VPNv6 additional-path capability.
                        type: str
                        choices:
                            - 'send'
                            - 'receive'
                            - 'both'
                            - 'disable'
                    additional_path6:
                        description:
                            - Enable/disable IPv6 additional-path capability.
                        type: str
                        choices:
                            - 'send'
                            - 'receive'
                            - 'both'
                            - 'disable'
                    adv_additional_path:
                        description:
                            - Number of IPv4 additional paths that can be advertised to this neighbor.
                        type: int
                    adv_additional_path_vpnv4:
                        description:
                            - Number of VPNv4 additional paths that can be advertised to this neighbor.
                        type: int
                    adv_additional_path_vpnv6:
                        description:
                            - Number of VPNv6 additional paths that can be advertised to this neighbor.
                        type: int
                    adv_additional_path6:
                        description:
                            - Number of IPv6 additional paths that can be advertised to this neighbor.
                        type: int
                    advertisement_interval:
                        description:
                            - Minimum interval (sec) between sending updates.
                        type: int
                    allowas_in:
                        description:
                            - IPv4 The maximum number of occurrence of my AS number allowed.
                        type: int
                    allowas_in_enable:
                        description:
                            - Enable/disable IPv4 Enable to allow my AS in AS path.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    allowas_in_enable_evpn:
                        description:
                            - Enable/disable to allow my AS in AS path for L2VPN EVPN route.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    allowas_in_enable_vpnv4:
                        description:
                            - Enable/disable to allow my AS in AS path for VPNv4 route.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    allowas_in_enable_vpnv6:
                        description:
                            - Enable/disable use of my AS in AS path for VPNv6 route.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    allowas_in_enable6:
                        description:
                            - Enable/disable IPv6 Enable to allow my AS in AS path.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    allowas_in_evpn:
                        description:
                            - The maximum number of occurrence of my AS number allowed for L2VPN EVPN route.
                        type: int
                    allowas_in_vpnv4:
                        description:
                            - The maximum number of occurrence of my AS number allowed for VPNv4 route.
                        type: int
                    allowas_in_vpnv6:
                        description:
                            - The maximum number of occurrence of my AS number allowed for VPNv6 route.
                        type: int
                    allowas_in6:
                        description:
                            - IPv6 The maximum number of occurrence of my AS number allowed.
                        type: int
                    as_override:
                        description:
                            - Enable/disable replace peer AS with own AS for IPv4.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    as_override6:
                        description:
                            - Enable/disable replace peer AS with own AS for IPv6.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    attribute_unchanged:
                        description:
                            - IPv4 List of attributes that should be unchanged.
                        type: list
                        elements: str
                        choices:
                            - 'as-path'
                            - 'med'
                            - 'next-hop'
                    attribute_unchanged_vpnv4:
                        description:
                            - List of attributes that should be unchanged for VPNv4 route.
                        type: list
                        elements: str
                        choices:
                            - 'as-path'
                            - 'med'
                            - 'next-hop'
                    attribute_unchanged_vpnv6:
                        description:
                            - List of attributes that should not be changed for VPNv6 route.
                        type: list
                        elements: str
                        choices:
                            - 'as-path'
                            - 'med'
                            - 'next-hop'
                    attribute_unchanged6:
                        description:
                            - IPv6 List of attributes that should be unchanged.
                        type: list
                        elements: str
                        choices:
                            - 'as-path'
                            - 'med'
                            - 'next-hop'
                    auth_options:
                        description:
                            - Key-chain name for TCP authentication options. Source router.key-chain.name.
                        type: str
                    bfd:
                        description:
                            - Enable/disable BFD for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_default_originate:
                        description:
                            - Enable/disable advertise default IPv4 route to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_default_originate6:
                        description:
                            - Enable/disable advertise default IPv6 route to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_dynamic:
                        description:
                            - Enable/disable advertise dynamic capability to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_graceful_restart:
                        description:
                            - Enable/disable advertise IPv4 graceful restart capability to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_graceful_restart_evpn:
                        description:
                            - Enable/disable advertisement of L2VPN EVPN graceful restart capability to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_graceful_restart_vpnv4:
                        description:
                            - Enable/disable advertise VPNv4 graceful restart capability to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_graceful_restart_vpnv6:
                        description:
                            - Enable/disable advertisement of VPNv6 graceful restart capability to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_graceful_restart6:
                        description:
                            - Enable/disable advertise IPv6 graceful restart capability to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_orf:
                        description:
                            - Accept/Send IPv4 ORF lists to/from this neighbor.
                        type: str
                        choices:
                            - 'none'
                            - 'receive'
                            - 'send'
                            - 'both'
                    capability_orf6:
                        description:
                            - Accept/Send IPv6 ORF lists to/from this neighbor.
                        type: str
                        choices:
                            - 'none'
                            - 'receive'
                            - 'send'
                            - 'both'
                    capability_route_refresh:
                        description:
                            - Enable/disable advertise route refresh capability to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    conditional_advertise:
                        description:
                            - Conditional advertisement.
                        type: list
                        elements: dict
                        suboptions:
                            advertise_routemap:
                                description:
                                    - Name of advertising route map. Source router.route-map.name.
                                required: true
                                type: str
                            condition_routemap:
                                description:
                                    - List of conditional route maps. Source router.route-map.name.
                                type: list
                                elements: dict
                                suboptions:
                                    name:
                                        description:
                                            - Route map. Source router.route-map.name.
                                        required: true
                                        type: str
                            condition_type:
                                description:
                                    - Type of condition.
                                type: str
                                choices:
                                    - 'exist'
                                    - 'non-exist'
                    conditional_advertise6:
                        description:
                            - IPv6 conditional advertisement.
                        type: list
                        elements: dict
                        suboptions:
                            advertise_routemap:
                                description:
                                    - Name of advertising route map. Source router.route-map.name.
                                required: true
                                type: str
                            condition_routemap:
                                description:
                                    - List of conditional route maps. Source router.route-map.name.
                                type: list
                                elements: dict
                                suboptions:
                                    name:
                                        description:
                                            - Route map. Source router.route-map.name.
                                        required: true
                                        type: str
                            condition_type:
                                description:
                                    - Type of condition.
                                type: str
                                choices:
                                    - 'exist'
                                    - 'non-exist'
                    connect_timer:
                        description:
                            - Interval (sec) for connect timer.
                        type: int
                    default_originate_routemap:
                        description:
                            - Route map to specify criteria to originate IPv4 default. Source router.route-map.name.
                        type: str
                    default_originate_routemap6:
                        description:
                            - Route map to specify criteria to originate IPv6 default. Source router.route-map.name.
                        type: str
                    description:
                        description:
                            - Description.
                        type: str
                    distribute_list_in:
                        description:
                            - Filter for IPv4 updates from this neighbor. Source router.access-list.name.
                        type: str
                    distribute_list_in_vpnv4:
                        description:
                            - Filter for VPNv4 updates from this neighbor. Source router.access-list.name.
                        type: str
                    distribute_list_in_vpnv6:
                        description:
                            - Filter for VPNv6 updates from this neighbor. Source router.access-list6.name.
                        type: str
                    distribute_list_in6:
                        description:
                            - Filter for IPv6 updates from this neighbor. Source router.access-list6.name.
                        type: str
                    distribute_list_out:
                        description:
                            - Filter for IPv4 updates to this neighbor. Source router.access-list.name.
                        type: str
                    distribute_list_out_vpnv4:
                        description:
                            - Filter for VPNv4 updates to this neighbor. Source router.access-list.name.
                        type: str
                    distribute_list_out_vpnv6:
                        description:
                            - Filter for VPNv6 updates to this neighbor. Source router.access-list6.name.
                        type: str
                    distribute_list_out6:
                        description:
                            - Filter for IPv6 updates to this neighbor. Source router.access-list6.name.
                        type: str
                    dont_capability_negotiate:
                        description:
                            - Do not negotiate capabilities with this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ebgp_enforce_multihop:
                        description:
                            - Enable/disable allow multi-hop EBGP neighbors.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ebgp_multihop_ttl:
                        description:
                            - EBGP multihop TTL for this peer.
                        type: int
                    filter_list_in:
                        description:
                            - BGP filter for IPv4 inbound routes. Source router.aspath-list.name.
                        type: str
                    filter_list_in_vpnv4:
                        description:
                            - BGP filter for VPNv4 inbound routes. Source router.aspath-list.name.
                        type: str
                    filter_list_in_vpnv6:
                        description:
                            - BGP filter for VPNv6 inbound routes. Source router.aspath-list.name.
                        type: str
                    filter_list_in6:
                        description:
                            - BGP filter for IPv6 inbound routes. Source router.aspath-list.name.
                        type: str
                    filter_list_out:
                        description:
                            - BGP filter for IPv4 outbound routes. Source router.aspath-list.name.
                        type: str
                    filter_list_out_vpnv4:
                        description:
                            - BGP filter for VPNv4 outbound routes. Source router.aspath-list.name.
                        type: str
                    filter_list_out_vpnv6:
                        description:
                            - BGP filter for VPNv6 outbound routes. Source router.aspath-list.name.
                        type: str
                    filter_list_out6:
                        description:
                            - BGP filter for IPv6 outbound routes. Source router.aspath-list.name.
                        type: str
                    holdtime_timer:
                        description:
                            - Interval (sec) before peer considered dead.
                        type: int
                    interface:
                        description:
                            - Specify outgoing interface for peer connection. For IPv6 peer, the interface should have link-local address. Source system
                              .interface.name.
                        type: str
                    ip:
                        description:
                            - IP/IPv6 address of neighbor.
                        required: true
                        type: str
                    keep_alive_timer:
                        description:
                            - Keep alive timer interval (sec).
                        type: int
                    link_down_failover:
                        description:
                            - Enable/disable failover upon link down.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    local_as:
                        description:
                            - Local AS number of neighbor.
                        type: str
                    local_as_no_prepend:
                        description:
                            - Do not prepend local-as to incoming updates.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    local_as_replace_as:
                        description:
                            - Replace real AS with local-as in outgoing updates.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    maximum_prefix:
                        description:
                            - Maximum number of IPv4 prefixes to accept from this peer.
                        type: int
                    maximum_prefix_evpn:
                        description:
                            - Maximum number of L2VPN EVPN prefixes to accept from this peer.
                        type: int
                    maximum_prefix_threshold:
                        description:
                            - Maximum IPv4 prefix threshold value (1 - 100 percent).
                        type: int
                    maximum_prefix_threshold_evpn:
                        description:
                            - Maximum L2VPN EVPN prefix threshold value (1 - 100 percent).
                        type: int
                    maximum_prefix_threshold_vpnv4:
                        description:
                            - Maximum VPNv4 prefix threshold value (1 - 100 percent).
                        type: int
                    maximum_prefix_threshold_vpnv6:
                        description:
                            - Maximum VPNv6 prefix threshold value (1 - 100 percent).
                        type: int
                    maximum_prefix_threshold6:
                        description:
                            - Maximum IPv6 prefix threshold value (1 - 100 percent).
                        type: int
                    maximum_prefix_vpnv4:
                        description:
                            - Maximum number of VPNv4 prefixes to accept from this peer.
                        type: int
                    maximum_prefix_vpnv6:
                        description:
                            - Maximum number of VPNv6 prefixes to accept from this peer.
                        type: int
                    maximum_prefix_warning_only:
                        description:
                            - Enable/disable IPv4 Only give warning message when limit is exceeded.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    maximum_prefix_warning_only_evpn:
                        description:
                            - Enable/disable only sending warning message when exceeding limit of L2VPN EVPN routes.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    maximum_prefix_warning_only_vpnv4:
                        description:
                            - Enable/disable only giving warning message when limit is exceeded for VPNv4 routes.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    maximum_prefix_warning_only_vpnv6:
                        description:
                            - Enable/disable warning message when limit is exceeded for VPNv6 routes.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    maximum_prefix_warning_only6:
                        description:
                            - Enable/disable IPv6 Only give warning message when limit is exceeded.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    maximum_prefix6:
                        description:
                            - Maximum number of IPv6 prefixes to accept from this peer.
                        type: int
                    next_hop_self:
                        description:
                            - Enable/disable IPv4 next-hop calculation for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    next_hop_self_rr:
                        description:
                            - Enable/disable setting nexthop"s address to interface"s IPv4 address for route-reflector routes.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    next_hop_self_rr6:
                        description:
                            - Enable/disable setting nexthop"s address to interface"s IPv6 address for route-reflector routes.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    next_hop_self_vpnv4:
                        description:
                            - Enable/disable setting VPNv4 next-hop to interface"s IP address for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    next_hop_self_vpnv6:
                        description:
                            - Enable/disable use of outgoing interface"s IP address as VPNv6 next-hop for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    next_hop_self6:
                        description:
                            - Enable/disable IPv6 next-hop calculation for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_capability:
                        description:
                            - Enable/disable override result of capability negotiation.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    passive:
                        description:
                            - Enable/disable sending of open messages to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    password:
                        description:
                            - Password used in MD5 authentication.
                        type: str
                    prefix_list_in:
                        description:
                            - IPv4 Inbound filter for updates from this neighbor. Source router.prefix-list.name.
                        type: str
                    prefix_list_in_vpnv4:
                        description:
                            - Inbound filter for VPNv4 updates from this neighbor. Source router.prefix-list.name.
                        type: str
                    prefix_list_in_vpnv6:
                        description:
                            - Inbound filter for VPNv6 updates from this neighbor. Source router.prefix-list6.name.
                        type: str
                    prefix_list_in6:
                        description:
                            - IPv6 Inbound filter for updates from this neighbor. Source router.prefix-list6.name.
                        type: str
                    prefix_list_out:
                        description:
                            - IPv4 Outbound filter for updates to this neighbor. Source router.prefix-list.name.
                        type: str
                    prefix_list_out_vpnv4:
                        description:
                            - Outbound filter for VPNv4 updates to this neighbor. Source router.prefix-list.name.
                        type: str
                    prefix_list_out_vpnv6:
                        description:
                            - Outbound filter for VPNv6 updates to this neighbor. Source router.prefix-list6.name.
                        type: str
                    prefix_list_out6:
                        description:
                            - IPv6 Outbound filter for updates to this neighbor. Source router.prefix-list6.name.
                        type: str
                    remote_as:
                        description:
                            - AS number of neighbor.
                        type: str
                    remove_private_as:
                        description:
                            - Enable/disable remove private AS number from IPv4 outbound updates.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    remove_private_as_evpn:
                        description:
                            - Enable/disable removing private AS number from L2VPN EVPN outbound updates.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    remove_private_as_vpnv4:
                        description:
                            - Enable/disable remove private AS number from VPNv4 outbound updates.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    remove_private_as_vpnv6:
                        description:
                            - Enable/disable to remove private AS number from VPNv6 outbound updates.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    remove_private_as6:
                        description:
                            - Enable/disable remove private AS number from IPv6 outbound updates.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    restart_time:
                        description:
                            - Graceful restart delay time (sec, 0 = global default).
                        type: int
                    retain_stale_time:
                        description:
                            - Time to retain stale routes.
                        type: int
                    route_map_in:
                        description:
                            - IPv4 Inbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_in_evpn:
                        description:
                            - L2VPN EVPN inbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_in_vpnv4:
                        description:
                            - VPNv4 inbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_in_vpnv6:
                        description:
                            - VPNv6 inbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_in6:
                        description:
                            - IPv6 Inbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_out:
                        description:
                            - IPv4 outbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_out_evpn:
                        description:
                            - L2VPN EVPN outbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_out_preferable:
                        description:
                            - IPv4 outbound route map filter if the peer is preferred. Source router.route-map.name.
                        type: str
                    route_map_out_vpnv4:
                        description:
                            - VPNv4 outbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_out_vpnv4_preferable:
                        description:
                            - VPNv4 outbound route map filter if the peer is preferred. Source router.route-map.name.
                        type: str
                    route_map_out_vpnv6:
                        description:
                            - VPNv6 outbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_out_vpnv6_preferable:
                        description:
                            - VPNv6 outbound route map filter if this neighbor is preferred. Source router.route-map.name.
                        type: str
                    route_map_out6:
                        description:
                            - IPv6 Outbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_out6_preferable:
                        description:
                            - IPv6 outbound route map filter if the peer is preferred. Source router.route-map.name.
                        type: str
                    route_reflector_client:
                        description:
                            - Enable/disable IPv4 AS route reflector client.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_reflector_client_evpn:
                        description:
                            - Enable/disable L2VPN EVPN AS route reflector client for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_reflector_client_vpnv4:
                        description:
                            - Enable/disable VPNv4 AS route reflector client for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_reflector_client_vpnv6:
                        description:
                            - Enable/disable VPNv6 AS route reflector client for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_reflector_client6:
                        description:
                            - Enable/disable IPv6 AS route reflector client.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_server_client:
                        description:
                            - Enable/disable IPv4 AS route server client.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_server_client_evpn:
                        description:
                            - Enable/disable L2VPN EVPN AS route server client for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_server_client_vpnv4:
                        description:
                            - Enable/disable VPNv4 AS route server client for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_server_client_vpnv6:
                        description:
                            - Enable/disable VPNv6 AS route server client for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_server_client6:
                        description:
                            - Enable/disable IPv6 AS route server client.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    rr_attr_allow_change:
                        description:
                            - Enable/disable allowing change of route attributes when advertising to IPv4 route reflector clients.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    rr_attr_allow_change_evpn:
                        description:
                            - Enable/disable allowing change of route attributes when advertising to L2VPN EVPN route reflector clients.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    rr_attr_allow_change_vpnv4:
                        description:
                            - Enable/disable allowing change of route attributes when advertising to VPNv4 route reflector clients.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    rr_attr_allow_change_vpnv6:
                        description:
                            - Enable/disable allowing change of route attributes when advertising to VPNv6 route reflector clients.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    rr_attr_allow_change6:
                        description:
                            - Enable/disable allowing change of route attributes when advertising to IPv6 route reflector clients.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    send_community:
                        description:
                            - IPv4 Send community attribute to neighbor.
                        type: str
                        choices:
                            - 'standard'
                            - 'extended'
                            - 'both'
                            - 'disable'
                    send_community_evpn:
                        description:
                            - Enable/disable sending community attribute to neighbor for L2VPN EVPN address family.
                        type: str
                        choices:
                            - 'standard'
                            - 'extended'
                            - 'both'
                            - 'disable'
                    send_community_vpnv4:
                        description:
                            - Send community attribute to neighbor for VPNv4 address family.
                        type: str
                        choices:
                            - 'standard'
                            - 'extended'
                            - 'both'
                            - 'disable'
                    send_community_vpnv6:
                        description:
                            - Enable/disable sending community attribute to this neighbor for VPNv6 address family.
                        type: str
                        choices:
                            - 'standard'
                            - 'extended'
                            - 'both'
                            - 'disable'
                    send_community6:
                        description:
                            - IPv6 Send community attribute to neighbor.
                        type: str
                        choices:
                            - 'standard'
                            - 'extended'
                            - 'both'
                            - 'disable'
                    shutdown:
                        description:
                            - Enable/disable shutdown this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    soft_reconfiguration:
                        description:
                            - Enable/disable allow IPv4 inbound soft reconfiguration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    soft_reconfiguration_evpn:
                        description:
                            - Enable/disable L2VPN EVPN inbound soft reconfiguration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    soft_reconfiguration_vpnv4:
                        description:
                            - Enable/disable allow VPNv4 inbound soft reconfiguration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    soft_reconfiguration_vpnv6:
                        description:
                            - Enable/disable VPNv6 inbound soft reconfiguration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    soft_reconfiguration6:
                        description:
                            - Enable/disable allow IPv6 inbound soft reconfiguration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    stale_route:
                        description:
                            - Enable/disable stale route after neighbor down.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    strict_capability_match:
                        description:
                            - Enable/disable strict capability matching.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    unsuppress_map:
                        description:
                            - IPv4 Route map to selectively unsuppress suppressed routes. Source router.route-map.name.
                        type: str
                    unsuppress_map6:
                        description:
                            - IPv6 Route map to selectively unsuppress suppressed routes. Source router.route-map.name.
                        type: str
                    update_source:
                        description:
                            - Interface to use as source IP/IPv6 address of TCP connections. Source system.interface.name.
                        type: str
                    weight:
                        description:
                            - Neighbor weight.
                        type: int
            neighbor_group:
                description:
                    - BGP neighbor group table.
                type: list
                elements: dict
                suboptions:
                    activate:
                        description:
                            - Enable/disable address family IPv4 for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    activate_evpn:
                        description:
                            - Enable/disable address family L2VPN EVPN for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    activate_vpnv4:
                        description:
                            - Enable/disable address family VPNv4 for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    activate_vpnv6:
                        description:
                            - Enable/disable address family VPNv6 for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    activate6:
                        description:
                            - Enable/disable address family IPv6 for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    additional_path:
                        description:
                            - Enable/disable IPv4 additional-path capability.
                        type: str
                        choices:
                            - 'send'
                            - 'receive'
                            - 'both'
                            - 'disable'
                    additional_path_vpnv4:
                        description:
                            - Enable/disable VPNv4 additional-path capability.
                        type: str
                        choices:
                            - 'send'
                            - 'receive'
                            - 'both'
                            - 'disable'
                    additional_path_vpnv6:
                        description:
                            - Enable/disable VPNv6 additional-path capability.
                        type: str
                        choices:
                            - 'send'
                            - 'receive'
                            - 'both'
                            - 'disable'
                    additional_path6:
                        description:
                            - Enable/disable IPv6 additional-path capability.
                        type: str
                        choices:
                            - 'send'
                            - 'receive'
                            - 'both'
                            - 'disable'
                    adv_additional_path:
                        description:
                            - Number of IPv4 additional paths that can be advertised to this neighbor.
                        type: int
                    adv_additional_path_vpnv4:
                        description:
                            - Number of VPNv4 additional paths that can be advertised to this neighbor.
                        type: int
                    adv_additional_path_vpnv6:
                        description:
                            - Number of VPNv6 additional paths that can be advertised to this neighbor.
                        type: int
                    adv_additional_path6:
                        description:
                            - Number of IPv6 additional paths that can be advertised to this neighbor.
                        type: int
                    advertisement_interval:
                        description:
                            - Minimum interval (sec) between sending updates.
                        type: int
                    allowas_in:
                        description:
                            - IPv4 The maximum number of occurrence of my AS number allowed.
                        type: int
                    allowas_in_enable:
                        description:
                            - Enable/disable IPv4 Enable to allow my AS in AS path.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    allowas_in_enable_evpn:
                        description:
                            - Enable/disable to allow my AS in AS path for L2VPN EVPN route.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    allowas_in_enable_vpnv4:
                        description:
                            - Enable/disable to allow my AS in AS path for VPNv4 route.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    allowas_in_enable_vpnv6:
                        description:
                            - Enable/disable use of my AS in AS path for VPNv6 route.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    allowas_in_enable6:
                        description:
                            - Enable/disable IPv6 Enable to allow my AS in AS path.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    allowas_in_evpn:
                        description:
                            - The maximum number of occurrence of my AS number allowed for L2VPN EVPN route.
                        type: int
                    allowas_in_vpnv4:
                        description:
                            - The maximum number of occurrence of my AS number allowed for VPNv4 route.
                        type: int
                    allowas_in_vpnv6:
                        description:
                            - The maximum number of occurrence of my AS number allowed for VPNv6 route.
                        type: int
                    allowas_in6:
                        description:
                            - IPv6 The maximum number of occurrence of my AS number allowed.
                        type: int
                    as_override:
                        description:
                            - Enable/disable replace peer AS with own AS for IPv4.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    as_override6:
                        description:
                            - Enable/disable replace peer AS with own AS for IPv6.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    attribute_unchanged:
                        description:
                            - IPv4 List of attributes that should be unchanged.
                        type: list
                        elements: str
                        choices:
                            - 'as-path'
                            - 'med'
                            - 'next-hop'
                    attribute_unchanged_vpnv4:
                        description:
                            - List of attributes that should be unchanged for VPNv4 route.
                        type: list
                        elements: str
                        choices:
                            - 'as-path'
                            - 'med'
                            - 'next-hop'
                    attribute_unchanged_vpnv6:
                        description:
                            - List of attributes that should not be changed for VPNv6 route.
                        type: list
                        elements: str
                        choices:
                            - 'as-path'
                            - 'med'
                            - 'next-hop'
                    attribute_unchanged6:
                        description:
                            - IPv6 List of attributes that should be unchanged.
                        type: list
                        elements: str
                        choices:
                            - 'as-path'
                            - 'med'
                            - 'next-hop'
                    auth_options:
                        description:
                            - Key-chain name for TCP authentication options. Source router.key-chain.name.
                        type: str
                    bfd:
                        description:
                            - Enable/disable BFD for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_default_originate:
                        description:
                            - Enable/disable advertise default IPv4 route to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_default_originate6:
                        description:
                            - Enable/disable advertise default IPv6 route to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_dynamic:
                        description:
                            - Enable/disable advertise dynamic capability to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_graceful_restart:
                        description:
                            - Enable/disable advertise IPv4 graceful restart capability to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_graceful_restart_evpn:
                        description:
                            - Enable/disable advertisement of L2VPN EVPN graceful restart capability to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_graceful_restart_vpnv4:
                        description:
                            - Enable/disable advertise VPNv4 graceful restart capability to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_graceful_restart_vpnv6:
                        description:
                            - Enable/disable advertisement of VPNv6 graceful restart capability to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_graceful_restart6:
                        description:
                            - Enable/disable advertise IPv6 graceful restart capability to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    capability_orf:
                        description:
                            - Accept/Send IPv4 ORF lists to/from this neighbor.
                        type: str
                        choices:
                            - 'none'
                            - 'receive'
                            - 'send'
                            - 'both'
                    capability_orf6:
                        description:
                            - Accept/Send IPv6 ORF lists to/from this neighbor.
                        type: str
                        choices:
                            - 'none'
                            - 'receive'
                            - 'send'
                            - 'both'
                    capability_route_refresh:
                        description:
                            - Enable/disable advertise route refresh capability to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    connect_timer:
                        description:
                            - Interval (sec) for connect timer.
                        type: int
                    default_originate_routemap:
                        description:
                            - Route map to specify criteria to originate IPv4 default. Source router.route-map.name.
                        type: str
                    default_originate_routemap6:
                        description:
                            - Route map to specify criteria to originate IPv6 default. Source router.route-map.name.
                        type: str
                    description:
                        description:
                            - Description.
                        type: str
                    distribute_list_in:
                        description:
                            - Filter for IPv4 updates from this neighbor. Source router.access-list.name.
                        type: str
                    distribute_list_in_vpnv4:
                        description:
                            - Filter for VPNv4 updates from this neighbor. Source router.access-list.name.
                        type: str
                    distribute_list_in_vpnv6:
                        description:
                            - Filter for VPNv6 updates from this neighbor. Source router.access-list6.name.
                        type: str
                    distribute_list_in6:
                        description:
                            - Filter for IPv6 updates from this neighbor. Source router.access-list6.name.
                        type: str
                    distribute_list_out:
                        description:
                            - Filter for IPv4 updates to this neighbor. Source router.access-list.name.
                        type: str
                    distribute_list_out_vpnv4:
                        description:
                            - Filter for VPNv4 updates to this neighbor. Source router.access-list.name.
                        type: str
                    distribute_list_out_vpnv6:
                        description:
                            - Filter for VPNv6 updates to this neighbor. Source router.access-list6.name.
                        type: str
                    distribute_list_out6:
                        description:
                            - Filter for IPv6 updates to this neighbor. Source router.access-list6.name.
                        type: str
                    dont_capability_negotiate:
                        description:
                            - Do not negotiate capabilities with this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ebgp_enforce_multihop:
                        description:
                            - Enable/disable allow multi-hop EBGP neighbors.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ebgp_multihop_ttl:
                        description:
                            - EBGP multihop TTL for this peer.
                        type: int
                    filter_list_in:
                        description:
                            - BGP filter for IPv4 inbound routes. Source router.aspath-list.name.
                        type: str
                    filter_list_in_vpnv4:
                        description:
                            - BGP filter for VPNv4 inbound routes. Source router.aspath-list.name.
                        type: str
                    filter_list_in_vpnv6:
                        description:
                            - BGP filter for VPNv6 inbound routes. Source router.aspath-list.name.
                        type: str
                    filter_list_in6:
                        description:
                            - BGP filter for IPv6 inbound routes. Source router.aspath-list.name.
                        type: str
                    filter_list_out:
                        description:
                            - BGP filter for IPv4 outbound routes. Source router.aspath-list.name.
                        type: str
                    filter_list_out_vpnv4:
                        description:
                            - BGP filter for VPNv4 outbound routes. Source router.aspath-list.name.
                        type: str
                    filter_list_out_vpnv6:
                        description:
                            - BGP filter for VPNv6 outbound routes. Source router.aspath-list.name.
                        type: str
                    filter_list_out6:
                        description:
                            - BGP filter for IPv6 outbound routes. Source router.aspath-list.name.
                        type: str
                    holdtime_timer:
                        description:
                            - Interval (sec) before peer considered dead.
                        type: int
                    interface:
                        description:
                            - Specify outgoing interface for peer connection. For IPv6 peer, the interface should have link-local address. Source system
                              .interface.name.
                        type: str
                    keep_alive_timer:
                        description:
                            - Keep alive timer interval (sec).
                        type: int
                    link_down_failover:
                        description:
                            - Enable/disable failover upon link down.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    local_as:
                        description:
                            - Local AS number of neighbor.
                        type: str
                    local_as_no_prepend:
                        description:
                            - Do not prepend local-as to incoming updates.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    local_as_replace_as:
                        description:
                            - Replace real AS with local-as in outgoing updates.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    maximum_prefix:
                        description:
                            - Maximum number of IPv4 prefixes to accept from this peer.
                        type: int
                    maximum_prefix_evpn:
                        description:
                            - Maximum number of L2VPN EVPN prefixes to accept from this peer.
                        type: int
                    maximum_prefix_threshold:
                        description:
                            - Maximum IPv4 prefix threshold value (1 - 100 percent).
                        type: int
                    maximum_prefix_threshold_evpn:
                        description:
                            - Maximum L2VPN EVPN prefix threshold value (1 - 100 percent).
                        type: int
                    maximum_prefix_threshold_vpnv4:
                        description:
                            - Maximum VPNv4 prefix threshold value (1 - 100 percent).
                        type: int
                    maximum_prefix_threshold_vpnv6:
                        description:
                            - Maximum VPNv6 prefix threshold value (1 - 100 percent).
                        type: int
                    maximum_prefix_threshold6:
                        description:
                            - Maximum IPv6 prefix threshold value (1 - 100 percent).
                        type: int
                    maximum_prefix_vpnv4:
                        description:
                            - Maximum number of VPNv4 prefixes to accept from this peer.
                        type: int
                    maximum_prefix_vpnv6:
                        description:
                            - Maximum number of VPNv6 prefixes to accept from this peer.
                        type: int
                    maximum_prefix_warning_only:
                        description:
                            - Enable/disable IPv4 Only give warning message when limit is exceeded.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    maximum_prefix_warning_only_evpn:
                        description:
                            - Enable/disable only sending warning message when exceeding limit of L2VPN EVPN routes.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    maximum_prefix_warning_only_vpnv4:
                        description:
                            - Enable/disable only giving warning message when limit is exceeded for VPNv4 routes.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    maximum_prefix_warning_only_vpnv6:
                        description:
                            - Enable/disable warning message when limit is exceeded for VPNv6 routes.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    maximum_prefix_warning_only6:
                        description:
                            - Enable/disable IPv6 Only give warning message when limit is exceeded.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    maximum_prefix6:
                        description:
                            - Maximum number of IPv6 prefixes to accept from this peer.
                        type: int
                    name:
                        description:
                            - Neighbor group name.
                        required: true
                        type: str
                    next_hop_self:
                        description:
                            - Enable/disable IPv4 next-hop calculation for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    next_hop_self_rr:
                        description:
                            - Enable/disable setting nexthop"s address to interface"s IPv4 address for route-reflector routes.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    next_hop_self_rr6:
                        description:
                            - Enable/disable setting nexthop"s address to interface"s IPv6 address for route-reflector routes.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    next_hop_self_vpnv4:
                        description:
                            - Enable/disable setting VPNv4 next-hop to interface"s IP address for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    next_hop_self_vpnv6:
                        description:
                            - Enable/disable use of outgoing interface"s IP address as VPNv6 next-hop for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    next_hop_self6:
                        description:
                            - Enable/disable IPv6 next-hop calculation for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    override_capability:
                        description:
                            - Enable/disable override result of capability negotiation.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    passive:
                        description:
                            - Enable/disable sending of open messages to this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    password:
                        description:
                            - Password used in MD5 authentication.
                        type: str
                    prefix_list_in:
                        description:
                            - IPv4 Inbound filter for updates from this neighbor. Source router.prefix-list.name.
                        type: str
                    prefix_list_in_vpnv4:
                        description:
                            - Inbound filter for VPNv4 updates from this neighbor. Source router.prefix-list.name.
                        type: str
                    prefix_list_in_vpnv6:
                        description:
                            - Inbound filter for VPNv6 updates from this neighbor. Source router.prefix-list6.name.
                        type: str
                    prefix_list_in6:
                        description:
                            - IPv6 Inbound filter for updates from this neighbor. Source router.prefix-list6.name.
                        type: str
                    prefix_list_out:
                        description:
                            - IPv4 Outbound filter for updates to this neighbor. Source router.prefix-list.name.
                        type: str
                    prefix_list_out_vpnv4:
                        description:
                            - Outbound filter for VPNv4 updates to this neighbor. Source router.prefix-list.name.
                        type: str
                    prefix_list_out_vpnv6:
                        description:
                            - Outbound filter for VPNv6 updates to this neighbor. Source router.prefix-list6.name.
                        type: str
                    prefix_list_out6:
                        description:
                            - IPv6 Outbound filter for updates to this neighbor. Source router.prefix-list6.name.
                        type: str
                    remote_as:
                        description:
                            - AS number of neighbor.
                        type: str
                    remote_as_filter:
                        description:
                            - BGP filter for remote AS. Source router.aspath-list.name.
                        type: str
                    remove_private_as:
                        description:
                            - Enable/disable remove private AS number from IPv4 outbound updates.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    remove_private_as_evpn:
                        description:
                            - Enable/disable removing private AS number from L2VPN EVPN outbound updates.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    remove_private_as_vpnv4:
                        description:
                            - Enable/disable remove private AS number from VPNv4 outbound updates.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    remove_private_as_vpnv6:
                        description:
                            - Enable/disable to remove private AS number from VPNv6 outbound updates.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    remove_private_as6:
                        description:
                            - Enable/disable remove private AS number from IPv6 outbound updates.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    restart_time:
                        description:
                            - Graceful restart delay time (sec, 0 = global default).
                        type: int
                    retain_stale_time:
                        description:
                            - Time to retain stale routes.
                        type: int
                    route_map_in:
                        description:
                            - IPv4 Inbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_in_evpn:
                        description:
                            - L2VPN EVPN inbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_in_vpnv4:
                        description:
                            - VPNv4 inbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_in_vpnv6:
                        description:
                            - VPNv6 inbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_in6:
                        description:
                            - IPv6 Inbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_out:
                        description:
                            - IPv4 outbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_out_evpn:
                        description:
                            - L2VPN EVPN outbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_out_preferable:
                        description:
                            - IPv4 outbound route map filter if the peer is preferred. Source router.route-map.name.
                        type: str
                    route_map_out_vpnv4:
                        description:
                            - VPNv4 outbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_out_vpnv4_preferable:
                        description:
                            - VPNv4 outbound route map filter if the peer is preferred. Source router.route-map.name.
                        type: str
                    route_map_out_vpnv6:
                        description:
                            - VPNv6 outbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_out_vpnv6_preferable:
                        description:
                            - VPNv6 outbound route map filter if this neighbor is preferred. Source router.route-map.name.
                        type: str
                    route_map_out6:
                        description:
                            - IPv6 Outbound route map filter. Source router.route-map.name.
                        type: str
                    route_map_out6_preferable:
                        description:
                            - IPv6 outbound route map filter if the peer is preferred. Source router.route-map.name.
                        type: str
                    route_reflector_client:
                        description:
                            - Enable/disable IPv4 AS route reflector client.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_reflector_client_evpn:
                        description:
                            - Enable/disable L2VPN EVPN AS route reflector client for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_reflector_client_vpnv4:
                        description:
                            - Enable/disable VPNv4 AS route reflector client for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_reflector_client_vpnv6:
                        description:
                            - Enable/disable VPNv6 AS route reflector client for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_reflector_client6:
                        description:
                            - Enable/disable IPv6 AS route reflector client.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_server_client:
                        description:
                            - Enable/disable IPv4 AS route server client.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_server_client_evpn:
                        description:
                            - Enable/disable L2VPN EVPN AS route server client for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_server_client_vpnv4:
                        description:
                            - Enable/disable VPNv4 AS route server client for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_server_client_vpnv6:
                        description:
                            - Enable/disable VPNv6 AS route server client for this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    route_server_client6:
                        description:
                            - Enable/disable IPv6 AS route server client.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    rr_attr_allow_change:
                        description:
                            - Enable/disable allowing change of route attributes when advertising to IPv4 route reflector clients.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    rr_attr_allow_change_evpn:
                        description:
                            - Enable/disable allowing change of route attributes when advertising to L2VPN EVPN route reflector clients.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    rr_attr_allow_change_vpnv4:
                        description:
                            - Enable/disable allowing change of route attributes when advertising to VPNv4 route reflector clients.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    rr_attr_allow_change_vpnv6:
                        description:
                            - Enable/disable allowing change of route attributes when advertising to VPNv6 route reflector clients.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    rr_attr_allow_change6:
                        description:
                            - Enable/disable allowing change of route attributes when advertising to IPv6 route reflector clients.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    send_community:
                        description:
                            - IPv4 Send community attribute to neighbor.
                        type: str
                        choices:
                            - 'standard'
                            - 'extended'
                            - 'both'
                            - 'disable'
                    send_community_evpn:
                        description:
                            - Enable/disable sending community attribute to neighbor for L2VPN EVPN address family.
                        type: str
                        choices:
                            - 'standard'
                            - 'extended'
                            - 'both'
                            - 'disable'
                    send_community_vpnv4:
                        description:
                            - Send community attribute to neighbor for VPNv4 address family.
                        type: str
                        choices:
                            - 'standard'
                            - 'extended'
                            - 'both'
                            - 'disable'
                    send_community_vpnv6:
                        description:
                            - Enable/disable sending community attribute to this neighbor for VPNv6 address family.
                        type: str
                        choices:
                            - 'standard'
                            - 'extended'
                            - 'both'
                            - 'disable'
                    send_community6:
                        description:
                            - IPv6 Send community attribute to neighbor.
                        type: str
                        choices:
                            - 'standard'
                            - 'extended'
                            - 'both'
                            - 'disable'
                    shutdown:
                        description:
                            - Enable/disable shutdown this neighbor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    soft_reconfiguration:
                        description:
                            - Enable/disable allow IPv4 inbound soft reconfiguration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    soft_reconfiguration_evpn:
                        description:
                            - Enable/disable L2VPN EVPN inbound soft reconfiguration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    soft_reconfiguration_vpnv4:
                        description:
                            - Enable/disable allow VPNv4 inbound soft reconfiguration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    soft_reconfiguration_vpnv6:
                        description:
                            - Enable/disable VPNv6 inbound soft reconfiguration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    soft_reconfiguration6:
                        description:
                            - Enable/disable allow IPv6 inbound soft reconfiguration.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    stale_route:
                        description:
                            - Enable/disable stale route after neighbor down.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    strict_capability_match:
                        description:
                            - Enable/disable strict capability matching.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    unsuppress_map:
                        description:
                            - IPv4 Route map to selectively unsuppress suppressed routes. Source router.route-map.name.
                        type: str
                    unsuppress_map6:
                        description:
                            - IPv6 Route map to selectively unsuppress suppressed routes. Source router.route-map.name.
                        type: str
                    update_source:
                        description:
                            - Interface to use as source IP/IPv6 address of TCP connections. Source system.interface.name.
                        type: str
                    weight:
                        description:
                            - Neighbor weight.
                        type: int
            neighbor_range:
                description:
                    - BGP neighbor range table.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Neighbor range ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    max_neighbor_num:
                        description:
                            - Maximum number of neighbors.
                        type: int
                    neighbor_group:
                        description:
                            - Neighbor group name. Source router.bgp.neighbor-group.name.
                        type: str
                    prefix:
                        description:
                            - Neighbor range prefix.
                        type: str
            neighbor_range6:
                description:
                    - BGP IPv6 neighbor range table.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - IPv6 neighbor range ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    max_neighbor_num:
                        description:
                            - Maximum number of neighbors.
                        type: int
                    neighbor_group:
                        description:
                            - Neighbor group name. Source router.bgp.neighbor-group.name.
                        type: str
                    prefix6:
                        description:
                            - IPv6 prefix.
                        type: str
            network:
                description:
                    - BGP network table.
                type: list
                elements: dict
                suboptions:
                    backdoor:
                        description:
                            - Enable/disable route as backdoor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    network_import_check:
                        description:
                            - Configure insurance of BGP network route existence in IGP.
                        type: str
                        choices:
                            - 'global'
                            - 'enable'
                            - 'disable'
                    prefix:
                        description:
                            - Network prefix.
                        type: str
                    prefix_name:
                        description:
                            - Name of firewall address or address group. Source firewall.address.name firewall.addrgrp.name.
                        type: str
                    route_map:
                        description:
                            - Route map to modify generated route. Source router.route-map.name.
                        type: str
            network_import_check:
                description:
                    - Enable/disable ensure BGP network route exists in IGP.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            network6:
                description:
                    - BGP IPv6 network table.
                type: list
                elements: dict
                suboptions:
                    backdoor:
                        description:
                            - Enable/disable route as backdoor.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    network_import_check:
                        description:
                            - Configure insurance of BGP network route existence in IGP.
                        type: str
                        choices:
                            - 'global'
                            - 'enable'
                            - 'disable'
                    prefix6:
                        description:
                            - Network IPv6 prefix.
                        type: str
                    route_map:
                        description:
                            - Route map to modify generated route. Source router.route-map.name.
                        type: str
            recursive_inherit_priority:
                description:
                    - Enable/disable priority inheritance for recursive resolution.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            recursive_next_hop:
                description:
                    - Enable/disable recursive resolution of next-hop using BGP route.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            redistribute:
                description:
                    - BGP IPv4 redistribute table.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Distribute list entry name.
                        required: true
                        type: str
                    route_map:
                        description:
                            - Route map name. Source router.route-map.name.
                        type: str
                    status:
                        description:
                            - Status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            redistribute6:
                description:
                    - BGP IPv6 redistribute table.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Distribute list entry name.
                        required: true
                        type: str
                    route_map:
                        description:
                            - Route map name. Source router.route-map.name.
                        type: str
                    status:
                        description:
                            - Status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            router_id:
                description:
                    - Router ID.
                type: str
            scan_time:
                description:
                    - Background scanner interval (sec), 0 to disable it.
                type: int
            synchronization:
                description:
                    - Enable/disable only advertise routes from iBGP if routes present in an IGP.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tag_resolve_mode:
                description:
                    - Configure tag-match mode. Resolves BGP routes with other routes containing the same tag.
                type: str
                choices:
                    - 'disable'
                    - 'preferred'
                    - 'merge'
                    - 'merge-all'
            vrf:
                description:
                    - BGP VRF leaking table.
                type: list
                elements: dict
                suboptions:
                    export_rt:
                        description:
                            - List of export route target.
                        type: list
                        elements: dict
                        suboptions:
                            route_target:
                                description:
                                    - 'Attribute: AA:NN|A.B.C.D:NN.'
                                required: true
                                type: str
                    import_route_map:
                        description:
                            - Import route map. Source router.route-map.name.
                        type: str
                    import_rt:
                        description:
                            - List of import route target.
                        type: list
                        elements: dict
                        suboptions:
                            route_target:
                                description:
                                    - 'Attribute: AA:NN|A.B.C.D:NN'
                                required: true
                                type: str
                    leak_target:
                        description:
                            - Target VRF table.
                        type: list
                        elements: dict
                        suboptions:
                            interface:
                                description:
                                    - Interface which is used to leak routes to target VRF. Source system.interface.name.
                                type: str
                            route_map:
                                description:
                                    - Route map of VRF leaking. Source router.route-map.name.
                                type: str
                            vrf:
                                description:
                                    - Target VRF ID <0-511>.
                                required: true
                                type: str
                    rd:
                        description:
                            - 'Route Distinguisher: AA:NN|A.B.C.D:NN.'
                        type: str
                    role:
                        description:
                            - VRF role.
                        type: str
                        choices:
                            - 'standalone'
                            - 'ce'
                            - 'pe'
                    vrf:
                        description:
                            - Origin VRF ID <0-511>.
                        required: true
                        type: str
            vrf_leak:
                description:
                    - BGP VRF leaking table.
                type: list
                elements: dict
                suboptions:
                    target:
                        description:
                            - Target VRF table.
                        type: list
                        elements: dict
                        suboptions:
                            interface:
                                description:
                                    - Interface which is used to leak routes to target VRF. Source system.interface.name.
                                type: str
                            route_map:
                                description:
                                    - Route map of VRF leaking. Source router.route-map.name.
                                type: str
                            vrf:
                                description:
                                    - Target VRF ID (0 - 31).
                                required: true
                                type: str
                    vrf:
                        description:
                            - Origin VRF ID (0 - 31).
                        required: true
                        type: str
            vrf_leak6:
                description:
                    - BGP IPv6 VRF leaking table.
                type: list
                elements: dict
                suboptions:
                    target:
                        description:
                            - Target VRF table.
                        type: list
                        elements: dict
                        suboptions:
                            interface:
                                description:
                                    - Interface which is used to leak routes to target VRF. Source system.interface.name.
                                type: str
                            route_map:
                                description:
                                    - Route map of VRF leaking. Source router.route-map.name.
                                type: str
                            vrf:
                                description:
                                    - Target VRF ID (0 - 31).
                                required: true
                                type: str
                    vrf:
                        description:
                            - Origin VRF ID (0 - 31).
                        required: true
                        type: str
            vrf6:
                description:
                    - BGP IPv6 VRF leaking table.
                type: list
                elements: dict
                suboptions:
                    export_rt:
                        description:
                            - List of export route target.
                        type: list
                        elements: dict
                        suboptions:
                            route_target:
                                description:
                                    - 'Attribute: AA:NN|A.B.C.D:NN.'
                                required: true
                                type: str
                    import_route_map:
                        description:
                            - Import route map. Source router.route-map.name.
                        type: str
                    import_rt:
                        description:
                            - List of import route target.
                        type: list
                        elements: dict
                        suboptions:
                            route_target:
                                description:
                                    - 'Attribute: AA:NN|A.B.C.D:NN'
                                required: true
                                type: str
                    leak_target:
                        description:
                            - Target VRF table.
                        type: list
                        elements: dict
                        suboptions:
                            interface:
                                description:
                                    - Interface which is used to leak routes to target VRF. Source system.interface.name.
                                type: str
                            route_map:
                                description:
                                    - Route map of VRF leaking. Source router.route-map.name.
                                type: str
                            vrf:
                                description:
                                    - Target VRF ID <0-511>.
                                required: true
                                type: str
                    rd:
                        description:
                            - 'Route Distinguisher: AA:NN|A.B.C.D:NN.'
                        type: str
                    role:
                        description:
                            - VRF role.
                        type: str
                        choices:
                            - 'standalone'
                            - 'ce'
                            - 'pe'
                    vrf:
                        description:
                            - Origin VRF ID <0-511>.
                        required: true
                        type: str
"""

EXAMPLES = """
- name: Configure BGP.
  fortinet.fortios.fortios_router_bgp:
      vdom: "{{ vdom }}"
      router_bgp:
          additional_path: "enable"
          additional_path_select: "2"
          additional_path_select_vpnv4: "2"
          additional_path_select_vpnv6: "2"
          additional_path_select6: "2"
          additional_path_vpnv4: "enable"
          additional_path_vpnv6: "enable"
          additional_path6: "enable"
          admin_distance:
              -
                  distance: "0"
                  id: "13"
                  neighbour_prefix: "<your_own_value>"
                  route_list: "<your_own_value> (source router.access-list.name)"
          aggregate_address:
              -
                  as_set: "enable"
                  id: "18"
                  prefix: "<your_own_value>"
                  summary_only: "enable"
          aggregate_address6:
              -
                  as_set: "enable"
                  id: "23"
                  prefix6: "<your_own_value>"
                  summary_only: "enable"
          always_compare_med: "enable"
          as: "<your_own_value>"
          bestpath_as_path_ignore: "enable"
          bestpath_cmp_confed_aspath: "enable"
          bestpath_cmp_routerid: "enable"
          bestpath_med_confed: "enable"
          bestpath_med_missing_as_worst: "enable"
          client_to_client_reflection: "enable"
          cluster_id: "<your_own_value>"
          confederation_identifier: "0"
          confederation_peers:
              -
                  peer: "<your_own_value>"
          cross_family_conditional_adv: "enable"
          dampening: "enable"
          dampening_max_suppress_time: "60"
          dampening_reachability_half_life: "15"
          dampening_reuse: "750"
          dampening_route_map: "<your_own_value> (source router.route-map.name)"
          dampening_suppress: "2000"
          dampening_unreachability_half_life: "15"
          default_local_preference: "100"
          deterministic_med: "enable"
          distance_external: "20"
          distance_internal: "200"
          distance_local: "200"
          ebgp_multipath: "enable"
          enforce_first_as: "enable"
          fast_external_failover: "enable"
          graceful_end_on_timer: "enable"
          graceful_restart: "enable"
          graceful_restart_time: "120"
          graceful_stalepath_time: "360"
          graceful_update_delay: "120"
          holdtime_timer: "180"
          ibgp_multipath: "enable"
          ignore_optional_capability: "enable"
          keepalive_timer: "60"
          log_neighbour_changes: "enable"
          multipath_recursive_distance: "enable"
          neighbor:
              -
                  activate: "enable"
                  activate_evpn: "enable"
                  activate_vpnv4: "enable"
                  activate_vpnv6: "enable"
                  activate6: "enable"
                  additional_path: "send"
                  additional_path_vpnv4: "send"
                  additional_path_vpnv6: "send"
                  additional_path6: "send"
                  adv_additional_path: "2"
                  adv_additional_path_vpnv4: "2"
                  adv_additional_path_vpnv6: "2"
                  adv_additional_path6: "2"
                  advertisement_interval: "30"
                  allowas_in: "3"
                  allowas_in_enable: "enable"
                  allowas_in_enable_evpn: "enable"
                  allowas_in_enable_vpnv4: "enable"
                  allowas_in_enable_vpnv6: "enable"
                  allowas_in_enable6: "enable"
                  allowas_in_evpn: "3"
                  allowas_in_vpnv4: "3"
                  allowas_in_vpnv6: "3"
                  allowas_in6: "3"
                  as_override: "enable"
                  as_override6: "enable"
                  attribute_unchanged: "as-path"
                  attribute_unchanged_vpnv4: "as-path"
                  attribute_unchanged_vpnv6: "as-path"
                  attribute_unchanged6: "as-path"
                  auth_options: "<your_own_value> (source router.key-chain.name)"
                  bfd: "enable"
                  capability_default_originate: "enable"
                  capability_default_originate6: "enable"
                  capability_dynamic: "enable"
                  capability_graceful_restart: "enable"
                  capability_graceful_restart_evpn: "enable"
                  capability_graceful_restart_vpnv4: "enable"
                  capability_graceful_restart_vpnv6: "enable"
                  capability_graceful_restart6: "enable"
                  capability_orf: "none"
                  capability_orf6: "none"
                  capability_route_refresh: "enable"
                  conditional_advertise:
                      -
                          advertise_routemap: "<your_own_value> (source router.route-map.name)"
                          condition_routemap:
                              -
                                  name: "default_name_112 (source router.route-map.name)"
                          condition_type: "exist"
                  conditional_advertise6:
                      -
                          advertise_routemap: "<your_own_value> (source router.route-map.name)"
                          condition_routemap:
                              -
                                  name: "default_name_117 (source router.route-map.name)"
                          condition_type: "exist"
                  connect_timer: "4294967295"
                  default_originate_routemap: "<your_own_value> (source router.route-map.name)"
                  default_originate_routemap6: "<your_own_value> (source router.route-map.name)"
                  description: "<your_own_value>"
                  distribute_list_in: "<your_own_value> (source router.access-list.name)"
                  distribute_list_in_vpnv4: "<your_own_value> (source router.access-list.name)"
                  distribute_list_in_vpnv6: "<your_own_value> (source router.access-list6.name)"
                  distribute_list_in6: "<your_own_value> (source router.access-list6.name)"
                  distribute_list_out: "<your_own_value> (source router.access-list.name)"
                  distribute_list_out_vpnv4: "<your_own_value> (source router.access-list.name)"
                  distribute_list_out_vpnv6: "<your_own_value> (source router.access-list6.name)"
                  distribute_list_out6: "<your_own_value> (source router.access-list6.name)"
                  dont_capability_negotiate: "enable"
                  ebgp_enforce_multihop: "enable"
                  ebgp_multihop_ttl: "255"
                  filter_list_in: "<your_own_value> (source router.aspath-list.name)"
                  filter_list_in_vpnv4: "<your_own_value> (source router.aspath-list.name)"
                  filter_list_in_vpnv6: "<your_own_value> (source router.aspath-list.name)"
                  filter_list_in6: "<your_own_value> (source router.aspath-list.name)"
                  filter_list_out: "<your_own_value> (source router.aspath-list.name)"
                  filter_list_out_vpnv4: "<your_own_value> (source router.aspath-list.name)"
                  filter_list_out_vpnv6: "<your_own_value> (source router.aspath-list.name)"
                  filter_list_out6: "<your_own_value> (source router.aspath-list.name)"
                  holdtime_timer: "4294967295"
                  interface: "<your_own_value> (source system.interface.name)"
                  ip: "<your_own_value>"
                  keep_alive_timer: "4294967295"
                  link_down_failover: "enable"
                  local_as: "<your_own_value>"
                  local_as_no_prepend: "enable"
                  local_as_replace_as: "enable"
                  maximum_prefix: "0"
                  maximum_prefix_evpn: "0"
                  maximum_prefix_threshold: "75"
                  maximum_prefix_threshold_evpn: "75"
                  maximum_prefix_threshold_vpnv4: "75"
                  maximum_prefix_threshold_vpnv6: "75"
                  maximum_prefix_threshold6: "75"
                  maximum_prefix_vpnv4: "0"
                  maximum_prefix_vpnv6: "0"
                  maximum_prefix_warning_only: "enable"
                  maximum_prefix_warning_only_evpn: "enable"
                  maximum_prefix_warning_only_vpnv4: "enable"
                  maximum_prefix_warning_only_vpnv6: "enable"
                  maximum_prefix_warning_only6: "enable"
                  maximum_prefix6: "0"
                  next_hop_self: "enable"
                  next_hop_self_rr: "enable"
                  next_hop_self_rr6: "enable"
                  next_hop_self_vpnv4: "enable"
                  next_hop_self_vpnv6: "enable"
                  next_hop_self6: "enable"
                  override_capability: "enable"
                  passive: "enable"
                  password: "<your_own_value>"
                  prefix_list_in: "<your_own_value> (source router.prefix-list.name)"
                  prefix_list_in_vpnv4: "<your_own_value> (source router.prefix-list.name)"
                  prefix_list_in_vpnv6: "<your_own_value> (source router.prefix-list6.name)"
                  prefix_list_in6: "<your_own_value> (source router.prefix-list6.name)"
                  prefix_list_out: "<your_own_value> (source router.prefix-list.name)"
                  prefix_list_out_vpnv4: "<your_own_value> (source router.prefix-list.name)"
                  prefix_list_out_vpnv6: "<your_own_value> (source router.prefix-list6.name)"
                  prefix_list_out6: "<your_own_value> (source router.prefix-list6.name)"
                  remote_as: "<your_own_value>"
                  remove_private_as: "enable"
                  remove_private_as_evpn: "enable"
                  remove_private_as_vpnv4: "enable"
                  remove_private_as_vpnv6: "enable"
                  remove_private_as6: "enable"
                  restart_time: "0"
                  retain_stale_time: "0"
                  route_map_in: "<your_own_value> (source router.route-map.name)"
                  route_map_in_evpn: "<your_own_value> (source router.route-map.name)"
                  route_map_in_vpnv4: "<your_own_value> (source router.route-map.name)"
                  route_map_in_vpnv6: "<your_own_value> (source router.route-map.name)"
                  route_map_in6: "<your_own_value> (source router.route-map.name)"
                  route_map_out: "<your_own_value> (source router.route-map.name)"
                  route_map_out_evpn: "<your_own_value> (source router.route-map.name)"
                  route_map_out_preferable: "<your_own_value> (source router.route-map.name)"
                  route_map_out_vpnv4: "<your_own_value> (source router.route-map.name)"
                  route_map_out_vpnv4_preferable: "<your_own_value> (source router.route-map.name)"
                  route_map_out_vpnv6: "<your_own_value> (source router.route-map.name)"
                  route_map_out_vpnv6_preferable: "<your_own_value> (source router.route-map.name)"
                  route_map_out6: "<your_own_value> (source router.route-map.name)"
                  route_map_out6_preferable: "<your_own_value> (source router.route-map.name)"
                  route_reflector_client: "enable"
                  route_reflector_client_evpn: "enable"
                  route_reflector_client_vpnv4: "enable"
                  route_reflector_client_vpnv6: "enable"
                  route_reflector_client6: "enable"
                  route_server_client: "enable"
                  route_server_client_evpn: "enable"
                  route_server_client_vpnv4: "enable"
                  route_server_client_vpnv6: "enable"
                  route_server_client6: "enable"
                  rr_attr_allow_change: "enable"
                  rr_attr_allow_change_evpn: "enable"
                  rr_attr_allow_change_vpnv4: "enable"
                  rr_attr_allow_change_vpnv6: "enable"
                  rr_attr_allow_change6: "enable"
                  send_community: "standard"
                  send_community_evpn: "standard"
                  send_community_vpnv4: "standard"
                  send_community_vpnv6: "standard"
                  send_community6: "standard"
                  shutdown: "enable"
                  soft_reconfiguration: "enable"
                  soft_reconfiguration_evpn: "enable"
                  soft_reconfiguration_vpnv4: "enable"
                  soft_reconfiguration_vpnv6: "enable"
                  soft_reconfiguration6: "enable"
                  stale_route: "enable"
                  strict_capability_match: "enable"
                  unsuppress_map: "<your_own_value> (source router.route-map.name)"
                  unsuppress_map6: "<your_own_value> (source router.route-map.name)"
                  update_source: "<your_own_value> (source system.interface.name)"
                  weight: "4294967295"
          neighbor_group:
              -
                  activate: "enable"
                  activate_evpn: "enable"
                  activate_vpnv4: "enable"
                  activate_vpnv6: "enable"
                  activate6: "enable"
                  additional_path: "send"
                  additional_path_vpnv4: "send"
                  additional_path_vpnv6: "send"
                  additional_path6: "send"
                  adv_additional_path: "2"
                  adv_additional_path_vpnv4: "2"
                  adv_additional_path_vpnv6: "2"
                  adv_additional_path6: "2"
                  advertisement_interval: "30"
                  allowas_in: "3"
                  allowas_in_enable: "enable"
                  allowas_in_enable_evpn: "enable"
                  allowas_in_enable_vpnv4: "enable"
                  allowas_in_enable_vpnv6: "enable"
                  allowas_in_enable6: "enable"
                  allowas_in_evpn: "3"
                  allowas_in_vpnv4: "3"
                  allowas_in_vpnv6: "3"
                  allowas_in6: "3"
                  as_override: "enable"
                  as_override6: "enable"
                  attribute_unchanged: "as-path"
                  attribute_unchanged_vpnv4: "as-path"
                  attribute_unchanged_vpnv6: "as-path"
                  attribute_unchanged6: "as-path"
                  auth_options: "<your_own_value> (source router.key-chain.name)"
                  bfd: "enable"
                  capability_default_originate: "enable"
                  capability_default_originate6: "enable"
                  capability_dynamic: "enable"
                  capability_graceful_restart: "enable"
                  capability_graceful_restart_evpn: "enable"
                  capability_graceful_restart_vpnv4: "enable"
                  capability_graceful_restart_vpnv6: "enable"
                  capability_graceful_restart6: "enable"
                  capability_orf: "none"
                  capability_orf6: "none"
                  capability_route_refresh: "enable"
                  connect_timer: "4294967295"
                  default_originate_routemap: "<your_own_value> (source router.route-map.name)"
                  default_originate_routemap6: "<your_own_value> (source router.route-map.name)"
                  description: "<your_own_value>"
                  distribute_list_in: "<your_own_value> (source router.access-list.name)"
                  distribute_list_in_vpnv4: "<your_own_value> (source router.access-list.name)"
                  distribute_list_in_vpnv6: "<your_own_value> (source router.access-list6.name)"
                  distribute_list_in6: "<your_own_value> (source router.access-list6.name)"
                  distribute_list_out: "<your_own_value> (source router.access-list.name)"
                  distribute_list_out_vpnv4: "<your_own_value> (source router.access-list.name)"
                  distribute_list_out_vpnv6: "<your_own_value> (source router.access-list6.name)"
                  distribute_list_out6: "<your_own_value> (source router.access-list6.name)"
                  dont_capability_negotiate: "enable"
                  ebgp_enforce_multihop: "enable"
                  ebgp_multihop_ttl: "255"
                  filter_list_in: "<your_own_value> (source router.aspath-list.name)"
                  filter_list_in_vpnv4: "<your_own_value> (source router.aspath-list.name)"
                  filter_list_in_vpnv6: "<your_own_value> (source router.aspath-list.name)"
                  filter_list_in6: "<your_own_value> (source router.aspath-list.name)"
                  filter_list_out: "<your_own_value> (source router.aspath-list.name)"
                  filter_list_out_vpnv4: "<your_own_value> (source router.aspath-list.name)"
                  filter_list_out_vpnv6: "<your_own_value> (source router.aspath-list.name)"
                  filter_list_out6: "<your_own_value> (source router.aspath-list.name)"
                  holdtime_timer: "4294967295"
                  interface: "<your_own_value> (source system.interface.name)"
                  keep_alive_timer: "4294967295"
                  link_down_failover: "enable"
                  local_as: "<your_own_value>"
                  local_as_no_prepend: "enable"
                  local_as_replace_as: "enable"
                  maximum_prefix: "0"
                  maximum_prefix_evpn: "0"
                  maximum_prefix_threshold: "75"
                  maximum_prefix_threshold_evpn: "75"
                  maximum_prefix_threshold_vpnv4: "75"
                  maximum_prefix_threshold_vpnv6: "75"
                  maximum_prefix_threshold6: "75"
                  maximum_prefix_vpnv4: "0"
                  maximum_prefix_vpnv6: "0"
                  maximum_prefix_warning_only: "enable"
                  maximum_prefix_warning_only_evpn: "enable"
                  maximum_prefix_warning_only_vpnv4: "enable"
                  maximum_prefix_warning_only_vpnv6: "enable"
                  maximum_prefix_warning_only6: "enable"
                  maximum_prefix6: "0"
                  name: "default_name_325"
                  next_hop_self: "enable"
                  next_hop_self_rr: "enable"
                  next_hop_self_rr6: "enable"
                  next_hop_self_vpnv4: "enable"
                  next_hop_self_vpnv6: "enable"
                  next_hop_self6: "enable"
                  override_capability: "enable"
                  passive: "enable"
                  password: "<your_own_value>"
                  prefix_list_in: "<your_own_value> (source router.prefix-list.name)"
                  prefix_list_in_vpnv4: "<your_own_value> (source router.prefix-list.name)"
                  prefix_list_in_vpnv6: "<your_own_value> (source router.prefix-list6.name)"
                  prefix_list_in6: "<your_own_value> (source router.prefix-list6.name)"
                  prefix_list_out: "<your_own_value> (source router.prefix-list.name)"
                  prefix_list_out_vpnv4: "<your_own_value> (source router.prefix-list.name)"
                  prefix_list_out_vpnv6: "<your_own_value> (source router.prefix-list6.name)"
                  prefix_list_out6: "<your_own_value> (source router.prefix-list6.name)"
                  remote_as: "<your_own_value>"
                  remote_as_filter: "<your_own_value> (source router.aspath-list.name)"
                  remove_private_as: "enable"
                  remove_private_as_evpn: "enable"
                  remove_private_as_vpnv4: "enable"
                  remove_private_as_vpnv6: "enable"
                  remove_private_as6: "enable"
                  restart_time: "0"
                  retain_stale_time: "0"
                  route_map_in: "<your_own_value> (source router.route-map.name)"
                  route_map_in_evpn: "<your_own_value> (source router.route-map.name)"
                  route_map_in_vpnv4: "<your_own_value> (source router.route-map.name)"
                  route_map_in_vpnv6: "<your_own_value> (source router.route-map.name)"
                  route_map_in6: "<your_own_value> (source router.route-map.name)"
                  route_map_out: "<your_own_value> (source router.route-map.name)"
                  route_map_out_evpn: "<your_own_value> (source router.route-map.name)"
                  route_map_out_preferable: "<your_own_value> (source router.route-map.name)"
                  route_map_out_vpnv4: "<your_own_value> (source router.route-map.name)"
                  route_map_out_vpnv4_preferable: "<your_own_value> (source router.route-map.name)"
                  route_map_out_vpnv6: "<your_own_value> (source router.route-map.name)"
                  route_map_out_vpnv6_preferable: "<your_own_value> (source router.route-map.name)"
                  route_map_out6: "<your_own_value> (source router.route-map.name)"
                  route_map_out6_preferable: "<your_own_value> (source router.route-map.name)"
                  route_reflector_client: "enable"
                  route_reflector_client_evpn: "enable"
                  route_reflector_client_vpnv4: "enable"
                  route_reflector_client_vpnv6: "enable"
                  route_reflector_client6: "enable"
                  route_server_client: "enable"
                  route_server_client_evpn: "enable"
                  route_server_client_vpnv4: "enable"
                  route_server_client_vpnv6: "enable"
                  route_server_client6: "enable"
                  rr_attr_allow_change: "enable"
                  rr_attr_allow_change_evpn: "enable"
                  rr_attr_allow_change_vpnv4: "enable"
                  rr_attr_allow_change_vpnv6: "enable"
                  rr_attr_allow_change6: "enable"
                  send_community: "standard"
                  send_community_evpn: "standard"
                  send_community_vpnv4: "standard"
                  send_community_vpnv6: "standard"
                  send_community6: "standard"
                  shutdown: "enable"
                  soft_reconfiguration: "enable"
                  soft_reconfiguration_evpn: "enable"
                  soft_reconfiguration_vpnv4: "enable"
                  soft_reconfiguration_vpnv6: "enable"
                  soft_reconfiguration6: "enable"
                  stale_route: "enable"
                  strict_capability_match: "enable"
                  unsuppress_map: "<your_own_value> (source router.route-map.name)"
                  unsuppress_map6: "<your_own_value> (source router.route-map.name)"
                  update_source: "<your_own_value> (source system.interface.name)"
                  weight: "4294967295"
          neighbor_range:
              -
                  id: "399"
                  max_neighbor_num: "0"
                  neighbor_group: "<your_own_value> (source router.bgp.neighbor-group.name)"
                  prefix: "<your_own_value>"
          neighbor_range6:
              -
                  id: "404"
                  max_neighbor_num: "0"
                  neighbor_group: "<your_own_value> (source router.bgp.neighbor-group.name)"
                  prefix6: "<your_own_value>"
          network:
              -
                  backdoor: "enable"
                  id: "410"
                  network_import_check: "global"
                  prefix: "<your_own_value>"
                  prefix_name: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
                  route_map: "<your_own_value> (source router.route-map.name)"
          network_import_check: "enable"
          network6:
              -
                  backdoor: "enable"
                  id: "418"
                  network_import_check: "global"
                  prefix6: "<your_own_value>"
                  route_map: "<your_own_value> (source router.route-map.name)"
          recursive_inherit_priority: "enable"
          recursive_next_hop: "enable"
          redistribute:
              -
                  name: "default_name_425"
                  route_map: "<your_own_value> (source router.route-map.name)"
                  status: "enable"
          redistribute6:
              -
                  name: "default_name_429"
                  route_map: "<your_own_value> (source router.route-map.name)"
                  status: "enable"
          router_id: "<your_own_value>"
          scan_time: "60"
          synchronization: "enable"
          tag_resolve_mode: "disable"
          vrf:
              -
                  export_rt:
                      -
                          route_target: "<your_own_value>"
                  import_route_map: "<your_own_value> (source router.route-map.name)"
                  import_rt:
                      -
                          route_target: "<your_own_value>"
                  leak_target:
                      -
                          interface: "<your_own_value> (source system.interface.name)"
                          route_map: "<your_own_value> (source router.route-map.name)"
                          vrf: "<your_own_value>"
                  rd: "<your_own_value>"
                  role: "standalone"
                  vrf: "<your_own_value>"
          vrf_leak:
              -
                  target:
                      -
                          interface: "<your_own_value> (source system.interface.name)"
                          route_map: "<your_own_value> (source router.route-map.name)"
                          vrf: "<your_own_value>"
                  vrf: "<your_own_value>"
          vrf_leak6:
              -
                  target:
                      -
                          interface: "<your_own_value> (source system.interface.name)"
                          route_map: "<your_own_value> (source router.route-map.name)"
                          vrf: "<your_own_value>"
                  vrf: "<your_own_value>"
          vrf6:
              -
                  export_rt:
                      -
                          route_target: "<your_own_value>"
                  import_route_map: "<your_own_value> (source router.route-map.name)"
                  import_rt:
                      -
                          route_target: "<your_own_value>"
                  leak_target:
                      -
                          interface: "<your_own_value> (source system.interface.name)"
                          route_map: "<your_own_value> (source router.route-map.name)"
                          vrf: "<your_own_value>"
                  rd: "<your_own_value>"
                  role: "standalone"
                  vrf: "<your_own_value>"
"""

RETURN = """
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"
"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_legacy_fortiosapi,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    schema_to_module_spec,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_schema_versioning,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.data_post_processor import (
    remove_invalid_fields,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    is_same_comparison,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    serialize,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    find_current_values,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    unify_data_format,
)


def filter_router_bgp_data(json):
    option_list = [
        "additional_path",
        "additional_path_select",
        "additional_path_select_vpnv4",
        "additional_path_select_vpnv6",
        "additional_path_select6",
        "additional_path_vpnv4",
        "additional_path_vpnv6",
        "additional_path6",
        "admin_distance",
        "aggregate_address",
        "aggregate_address6",
        "always_compare_med",
        "as",
        "bestpath_as_path_ignore",
        "bestpath_cmp_confed_aspath",
        "bestpath_cmp_routerid",
        "bestpath_med_confed",
        "bestpath_med_missing_as_worst",
        "client_to_client_reflection",
        "cluster_id",
        "confederation_identifier",
        "confederation_peers",
        "cross_family_conditional_adv",
        "dampening",
        "dampening_max_suppress_time",
        "dampening_reachability_half_life",
        "dampening_reuse",
        "dampening_route_map",
        "dampening_suppress",
        "dampening_unreachability_half_life",
        "default_local_preference",
        "deterministic_med",
        "distance_external",
        "distance_internal",
        "distance_local",
        "ebgp_multipath",
        "enforce_first_as",
        "fast_external_failover",
        "graceful_end_on_timer",
        "graceful_restart",
        "graceful_restart_time",
        "graceful_stalepath_time",
        "graceful_update_delay",
        "holdtime_timer",
        "ibgp_multipath",
        "ignore_optional_capability",
        "keepalive_timer",
        "log_neighbour_changes",
        "multipath_recursive_distance",
        "neighbor",
        "neighbor_group",
        "neighbor_range",
        "neighbor_range6",
        "network",
        "network_import_check",
        "network6",
        "recursive_inherit_priority",
        "recursive_next_hop",
        "redistribute",
        "redistribute6",
        "router_id",
        "scan_time",
        "synchronization",
        "tag_resolve_mode",
        "vrf",
        "vrf_leak",
        "vrf_leak6",
        "vrf6",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_single_path(data, path, index):
    if (
        not data
        or index == len(path)
        or path[index] not in data
        or (not data[path[index]] and not isinstance(data[path[index]], list))
    ):
        return

    if index == len(path) - 1:
        data[path[index]] = " ".join(str(elem) for elem in data[path[index]])
        if len(data[path[index]]) == 0:
            data[path[index]] = None
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [
        ["neighbor", "attribute_unchanged"],
        ["neighbor", "attribute_unchanged6"],
        ["neighbor", "attribute_unchanged_vpnv4"],
        ["neighbor", "attribute_unchanged_vpnv6"],
        ["neighbor_group", "attribute_unchanged"],
        ["neighbor_group", "attribute_unchanged6"],
        ["neighbor_group", "attribute_unchanged_vpnv4"],
        ["neighbor_group", "attribute_unchanged_vpnv6"],
    ]

    for attr in multilist_attrs:
        flatten_single_path(data, attr, 0)

    return data


def underscore_to_hyphen(data):
    new_data = None
    if isinstance(data, list):
        new_data = []
        for i, elem in enumerate(data):
            new_data.append(underscore_to_hyphen(elem))
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
    else:
        return data
    return new_data


def router_bgp(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    router_bgp_data = data["router_bgp"]

    filtered_data = filter_router_bgp_data(router_bgp_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("router", "bgp", filtered_data, vdom=vdom)
        current_data = fos.get("router", "bgp", vdom=vdom, mkey=mkey)
        is_existed = (
            current_data
            and current_data.get("http_status") == 200
            and (
                mkeyname
                and isinstance(current_data.get("results"), list)
                and len(current_data["results"]) > 0
                or not mkeyname
                and current_data["results"]  # global object response
            )
        )

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == "present" or state is True or state is None:
            # for non global modules, mkeyname must exist and it's a new module when mkey is None
            if mkeyname is not None and mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            copied_filtered_data = filtered_data.copy()
            copied_filtered_data.pop(mkeyname, None)
            unified_filtered_data = unify_data_format(copied_filtered_data)

            current_data_results = current_data.get("results", {})
            current_config = (
                current_data_results[0]
                if mkeyname
                and isinstance(current_data_results, list)
                and len(current_data_results) > 0
                else current_data_results
            )
            if is_existed:
                unified_current_values = find_current_values(
                    unified_filtered_data,
                    unify_data_format(current_config),
                )

                is_same = is_same_comparison(
                    serialize(unified_current_values), serialize(unified_filtered_data)
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": unified_current_values, "after": unified_filtered_data},
                )

            # record does not exist
            return False, True, filtered_data, diff

        if state == "absent":
            if mkey is None:
                return (
                    False,
                    False,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )

            if is_existed:
                return (
                    False,
                    True,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )
            return False, False, filtered_data, {}

        return True, False, {"reason: ": "Must provide state parameter"}, {}
    # pass post processed data to member operations
    # no need to do underscore_to_hyphen since do_member_operation handles it by itself
    data_copy = data.copy()
    data_copy["router_bgp"] = filtered_data
    fos.do_member_operation(
        "router",
        "bgp",
        data_copy,
    )

    return fos.set("router", "bgp", data=converted_data, vdom=vdom)


def is_successful_status(resp):
    return (
        "status" in resp
        and resp["status"] == "success"
        or "http_status" in resp
        and resp["http_status"] == 200
        or "http_method" in resp
        and resp["http_method"] == "DELETE"
        and resp["http_status"] == 404
    )


def fortios_router(data, fos, check_mode):

    if data["router_bgp"]:
        resp = router_bgp(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("router_bgp"))
    if isinstance(resp, tuple) and len(resp) == 4:
        return resp
    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "v_range": [["v6.0.0", ""]],
    "type": "dict",
    "children": {
        "as": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "router_id": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "keepalive_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "holdtime_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "always_compare_med": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "bestpath_as_path_ignore": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "bestpath_cmp_confed_aspath": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "bestpath_cmp_routerid": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "bestpath_med_confed": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "bestpath_med_missing_as_worst": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "client_to_client_reflection": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dampening": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "deterministic_med": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ebgp_multipath": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ibgp_multipath": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "enforce_first_as": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fast_external_failover": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "log_neighbour_changes": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "network_import_check": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ignore_optional_capability": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "additional_path": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "additional_path6": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "additional_path_vpnv4": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "additional_path_vpnv6": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "multipath_recursive_distance": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "recursive_next_hop": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "recursive_inherit_priority": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "tag_resolve_mode": {
            "v_range": [["v7.0.4", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "preferred"},
                {"value": "merge"},
                {"value": "merge-all", "v_range": [["v7.6.0", ""]]},
            ],
        },
        "cluster_id": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "confederation_identifier": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "confederation_peers": {
            "type": "list",
            "elements": "dict",
            "children": {
                "peer": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "dampening_route_map": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dampening_reachability_half_life": {
            "v_range": [["v6.0.0", ""]],
            "type": "integer",
        },
        "dampening_reuse": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "dampening_suppress": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "dampening_max_suppress_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "dampening_unreachability_half_life": {
            "v_range": [["v6.0.0", ""]],
            "type": "integer",
        },
        "default_local_preference": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "scan_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "distance_external": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "distance_internal": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "distance_local": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "synchronization": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "graceful_restart": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "graceful_restart_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "graceful_stalepath_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "graceful_update_delay": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "graceful_end_on_timer": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "additional_path_select": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "additional_path_select6": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "additional_path_select_vpnv4": {
            "v_range": [["v7.2.0", ""]],
            "type": "integer",
        },
        "additional_path_select_vpnv6": {
            "v_range": [["v7.4.2", ""]],
            "type": "integer",
        },
        "cross_family_conditional_adv": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "aggregate_address": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "prefix": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "as_set": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "summary_only": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "aggregate_address6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "prefix6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "as_set": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "summary_only": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "neighbor": {
            "type": "list",
            "elements": "dict",
            "children": {
                "ip": {"v_range": [["v6.0.0", ""]], "type": "string", "required": True},
                "advertisement_interval": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "allowas_in_enable": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "allowas_in_enable6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "allowas_in_enable_vpnv4": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "allowas_in_enable_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "allowas_in_enable_evpn": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "allowas_in": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "allowas_in6": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "allowas_in_vpnv4": {"v_range": [["v7.2.0", ""]], "type": "integer"},
                "allowas_in_vpnv6": {"v_range": [["v7.4.2", ""]], "type": "integer"},
                "allowas_in_evpn": {"v_range": [["v7.4.0", ""]], "type": "integer"},
                "attribute_unchanged": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "as-path"},
                        {"value": "med"},
                        {"value": "next-hop"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "attribute_unchanged6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "as-path"},
                        {"value": "med"},
                        {"value": "next-hop"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "attribute_unchanged_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "as-path"},
                        {"value": "med"},
                        {"value": "next-hop"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "attribute_unchanged_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "list",
                    "options": [
                        {"value": "as-path"},
                        {"value": "med"},
                        {"value": "next-hop"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "activate": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "activate6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "activate_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "activate_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "activate_evpn": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "bfd": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "capability_dynamic": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "capability_orf": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "receive"},
                        {"value": "send"},
                        {"value": "both"},
                    ],
                },
                "capability_orf6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "receive"},
                        {"value": "send"},
                        {"value": "both"},
                    ],
                },
                "capability_graceful_restart": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "capability_graceful_restart6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "capability_graceful_restart_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "capability_graceful_restart_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "capability_graceful_restart_evpn": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "capability_route_refresh": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "capability_default_originate": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "capability_default_originate6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "dont_capability_negotiate": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ebgp_enforce_multihop": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "link_down_failover": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "stale_route": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "next_hop_self": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "next_hop_self6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "next_hop_self_rr": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "next_hop_self_rr6": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "next_hop_self_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "next_hop_self_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "override_capability": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "passive": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "remove_private_as": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "remove_private_as6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "remove_private_as_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "remove_private_as_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "remove_private_as_evpn": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_reflector_client": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_reflector_client6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_reflector_client_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_reflector_client_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_reflector_client_evpn": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_server_client": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_server_client6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_server_client_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_server_client_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_server_client_evpn": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "rr_attr_allow_change": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "rr_attr_allow_change6": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "rr_attr_allow_change_vpnv4": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "rr_attr_allow_change_vpnv6": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "rr_attr_allow_change_evpn": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "shutdown": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "soft_reconfiguration": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "soft_reconfiguration6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "soft_reconfiguration_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "soft_reconfiguration_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "soft_reconfiguration_evpn": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "as_override": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "as_override6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "strict_capability_match": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "default_originate_routemap": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                },
                "default_originate_routemap6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                },
                "description": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "distribute_list_in": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "distribute_list_in6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "distribute_list_in_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                },
                "distribute_list_in_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "distribute_list_out": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "distribute_list_out6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "distribute_list_out_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                },
                "distribute_list_out_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "ebgp_multihop_ttl": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "filter_list_in": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "filter_list_in6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "filter_list_in_vpnv4": {"v_range": [["v7.4.1", ""]], "type": "string"},
                "filter_list_in_vpnv6": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "filter_list_out": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "filter_list_out6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "filter_list_out_vpnv4": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                },
                "filter_list_out_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "interface": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "maximum_prefix": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "maximum_prefix6": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "maximum_prefix_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "integer",
                },
                "maximum_prefix_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "integer",
                },
                "maximum_prefix_evpn": {"v_range": [["v7.4.0", ""]], "type": "integer"},
                "maximum_prefix_threshold": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "maximum_prefix_threshold6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "maximum_prefix_threshold_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "integer",
                },
                "maximum_prefix_threshold_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "integer",
                },
                "maximum_prefix_threshold_evpn": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "integer",
                },
                "maximum_prefix_warning_only": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "maximum_prefix_warning_only6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "maximum_prefix_warning_only_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "maximum_prefix_warning_only_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "maximum_prefix_warning_only_evpn": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "prefix_list_in": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "prefix_list_in6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "prefix_list_in_vpnv4": {"v_range": [["v7.2.0", ""]], "type": "string"},
                "prefix_list_in_vpnv6": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "prefix_list_out": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "prefix_list_out6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "prefix_list_out_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                },
                "prefix_list_out_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "remote_as": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "local_as": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "local_as_no_prepend": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "local_as_replace_as": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "retain_stale_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "route_map_in": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "route_map_in6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "route_map_in_vpnv4": {"v_range": [["v7.2.0", ""]], "type": "string"},
                "route_map_in_vpnv6": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "route_map_in_evpn": {"v_range": [["v7.4.0", ""]], "type": "string"},
                "route_map_out": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "route_map_out_preferable": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                },
                "route_map_out6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "route_map_out6_preferable": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                },
                "route_map_out_vpnv4": {"v_range": [["v7.2.0", ""]], "type": "string"},
                "route_map_out_vpnv6": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "route_map_out_vpnv4_preferable": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                },
                "route_map_out_vpnv6_preferable": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "route_map_out_evpn": {"v_range": [["v7.4.0", ""]], "type": "string"},
                "send_community": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "standard"},
                        {"value": "extended"},
                        {"value": "both"},
                        {"value": "disable"},
                    ],
                },
                "send_community6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "standard"},
                        {"value": "extended"},
                        {"value": "both"},
                        {"value": "disable"},
                    ],
                },
                "send_community_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "standard"},
                        {"value": "extended"},
                        {"value": "both"},
                        {"value": "disable"},
                    ],
                },
                "send_community_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [
                        {"value": "standard"},
                        {"value": "extended"},
                        {"value": "both"},
                        {"value": "disable"},
                    ],
                },
                "send_community_evpn": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "standard"},
                        {"value": "extended"},
                        {"value": "both"},
                        {"value": "disable"},
                    ],
                },
                "keep_alive_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "holdtime_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "connect_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "unsuppress_map": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "unsuppress_map6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "update_source": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "weight": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "restart_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "additional_path": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "send"},
                        {"value": "receive"},
                        {"value": "both"},
                        {"value": "disable"},
                    ],
                },
                "additional_path6": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "send"},
                        {"value": "receive"},
                        {"value": "both"},
                        {"value": "disable"},
                    ],
                },
                "additional_path_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "send"},
                        {"value": "receive"},
                        {"value": "both"},
                        {"value": "disable"},
                    ],
                },
                "additional_path_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [
                        {"value": "send"},
                        {"value": "receive"},
                        {"value": "both"},
                        {"value": "disable"},
                    ],
                },
                "adv_additional_path": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "adv_additional_path6": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "integer",
                },
                "adv_additional_path_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "integer",
                },
                "adv_additional_path_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "integer",
                },
                "password": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "auth_options": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "conditional_advertise": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "advertise_routemap": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "condition_routemap": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "name": {
                                    "v_range": [["v7.0.4", ""]],
                                    "type": "string",
                                    "required": True,
                                }
                            },
                            "v_range": [["v6.0.0", ""]],
                        },
                        "condition_type": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "options": [{"value": "exist"}, {"value": "non-exist"}],
                        },
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "conditional_advertise6": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "advertise_routemap": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "condition_routemap": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "name": {
                                    "v_range": [["v7.0.4", ""]],
                                    "type": "string",
                                    "required": True,
                                }
                            },
                            "v_range": [["v7.0.1", ""]],
                        },
                        "condition_type": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "options": [{"value": "exist"}, {"value": "non-exist"}],
                        },
                    },
                    "v_range": [["v7.0.1", ""]],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "neighbor_group": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "advertisement_interval": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "allowas_in_enable": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "allowas_in_enable6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "allowas_in_enable_vpnv4": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "allowas_in_enable_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "allowas_in_enable_evpn": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "allowas_in": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "allowas_in6": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "allowas_in_vpnv4": {"v_range": [["v7.2.0", ""]], "type": "integer"},
                "allowas_in_vpnv6": {"v_range": [["v7.4.2", ""]], "type": "integer"},
                "allowas_in_evpn": {"v_range": [["v7.4.0", ""]], "type": "integer"},
                "attribute_unchanged": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "as-path"},
                        {"value": "med"},
                        {"value": "next-hop"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "attribute_unchanged6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "as-path"},
                        {"value": "med"},
                        {"value": "next-hop"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "attribute_unchanged_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "as-path"},
                        {"value": "med"},
                        {"value": "next-hop"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "attribute_unchanged_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "list",
                    "options": [
                        {"value": "as-path"},
                        {"value": "med"},
                        {"value": "next-hop"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "activate": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "activate6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "activate_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "activate_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "activate_evpn": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "bfd": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "capability_dynamic": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "capability_orf": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "receive"},
                        {"value": "send"},
                        {"value": "both"},
                    ],
                },
                "capability_orf6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "receive"},
                        {"value": "send"},
                        {"value": "both"},
                    ],
                },
                "capability_graceful_restart": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "capability_graceful_restart6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "capability_graceful_restart_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "capability_graceful_restart_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "capability_graceful_restart_evpn": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "capability_route_refresh": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "capability_default_originate": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "capability_default_originate6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "dont_capability_negotiate": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ebgp_enforce_multihop": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "link_down_failover": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "stale_route": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "next_hop_self": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "next_hop_self6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "next_hop_self_rr": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "next_hop_self_rr6": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "next_hop_self_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "next_hop_self_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "override_capability": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "passive": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "remove_private_as": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "remove_private_as6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "remove_private_as_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "remove_private_as_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "remove_private_as_evpn": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_reflector_client": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_reflector_client6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_reflector_client_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_reflector_client_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_reflector_client_evpn": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_server_client": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_server_client6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_server_client_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_server_client_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_server_client_evpn": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "rr_attr_allow_change": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "rr_attr_allow_change6": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "rr_attr_allow_change_vpnv4": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "rr_attr_allow_change_vpnv6": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "rr_attr_allow_change_evpn": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "shutdown": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "soft_reconfiguration": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "soft_reconfiguration6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "soft_reconfiguration_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "soft_reconfiguration_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "soft_reconfiguration_evpn": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "as_override": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "as_override6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "strict_capability_match": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "default_originate_routemap": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                },
                "default_originate_routemap6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                },
                "description": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "distribute_list_in": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "distribute_list_in6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "distribute_list_in_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                },
                "distribute_list_in_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "distribute_list_out": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "distribute_list_out6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "distribute_list_out_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                },
                "distribute_list_out_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "ebgp_multihop_ttl": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "filter_list_in": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "filter_list_in6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "filter_list_in_vpnv4": {"v_range": [["v7.4.1", ""]], "type": "string"},
                "filter_list_in_vpnv6": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "filter_list_out": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "filter_list_out6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "filter_list_out_vpnv4": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                },
                "filter_list_out_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "interface": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "maximum_prefix": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "maximum_prefix6": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "maximum_prefix_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "integer",
                },
                "maximum_prefix_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "integer",
                },
                "maximum_prefix_evpn": {"v_range": [["v7.4.0", ""]], "type": "integer"},
                "maximum_prefix_threshold": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "maximum_prefix_threshold6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "maximum_prefix_threshold_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "integer",
                },
                "maximum_prefix_threshold_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "integer",
                },
                "maximum_prefix_threshold_evpn": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "integer",
                },
                "maximum_prefix_warning_only": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "maximum_prefix_warning_only6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "maximum_prefix_warning_only_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "maximum_prefix_warning_only_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "maximum_prefix_warning_only_evpn": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "prefix_list_in": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "prefix_list_in6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "prefix_list_in_vpnv4": {"v_range": [["v7.2.0", ""]], "type": "string"},
                "prefix_list_in_vpnv6": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "prefix_list_out": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "prefix_list_out6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "prefix_list_out_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                },
                "prefix_list_out_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "remote_as": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "remote_as_filter": {"v_range": [["v7.4.4", ""]], "type": "string"},
                "local_as": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "local_as_no_prepend": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "local_as_replace_as": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "retain_stale_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "route_map_in": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "route_map_in6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "route_map_in_vpnv4": {"v_range": [["v7.2.0", ""]], "type": "string"},
                "route_map_in_vpnv6": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "route_map_in_evpn": {"v_range": [["v7.4.0", ""]], "type": "string"},
                "route_map_out": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "route_map_out_preferable": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                },
                "route_map_out6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "route_map_out6_preferable": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                },
                "route_map_out_vpnv4": {"v_range": [["v7.2.0", ""]], "type": "string"},
                "route_map_out_vpnv6": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "route_map_out_vpnv4_preferable": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                },
                "route_map_out_vpnv6_preferable": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                },
                "route_map_out_evpn": {"v_range": [["v7.4.0", ""]], "type": "string"},
                "send_community": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "standard"},
                        {"value": "extended"},
                        {"value": "both"},
                        {"value": "disable"},
                    ],
                },
                "send_community6": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "standard"},
                        {"value": "extended"},
                        {"value": "both"},
                        {"value": "disable"},
                    ],
                },
                "send_community_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "standard"},
                        {"value": "extended"},
                        {"value": "both"},
                        {"value": "disable"},
                    ],
                },
                "send_community_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [
                        {"value": "standard"},
                        {"value": "extended"},
                        {"value": "both"},
                        {"value": "disable"},
                    ],
                },
                "send_community_evpn": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "standard"},
                        {"value": "extended"},
                        {"value": "both"},
                        {"value": "disable"},
                    ],
                },
                "keep_alive_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "holdtime_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "connect_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "unsuppress_map": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "unsuppress_map6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "update_source": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "weight": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "restart_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "additional_path": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "send"},
                        {"value": "receive"},
                        {"value": "both"},
                        {"value": "disable"},
                    ],
                },
                "additional_path6": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "send"},
                        {"value": "receive"},
                        {"value": "both"},
                        {"value": "disable"},
                    ],
                },
                "additional_path_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "send"},
                        {"value": "receive"},
                        {"value": "both"},
                        {"value": "disable"},
                    ],
                },
                "additional_path_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [
                        {"value": "send"},
                        {"value": "receive"},
                        {"value": "both"},
                        {"value": "disable"},
                    ],
                },
                "adv_additional_path": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "adv_additional_path6": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "integer",
                },
                "adv_additional_path_vpnv4": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "integer",
                },
                "adv_additional_path_vpnv6": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "integer",
                },
                "password": {"v_range": [["v7.2.4", ""]], "type": "string"},
                "auth_options": {"v_range": [["v7.4.2", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "neighbor_range": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "prefix": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "max_neighbor_num": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "neighbor_group": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "neighbor_range6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "prefix6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "max_neighbor_num": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "neighbor_group": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "network": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "prefix": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "network_import_check": {
                    "v_range": [["v7.0.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "global"},
                        {"value": "enable"},
                        {"value": "disable"},
                    ],
                },
                "backdoor": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_map": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "prefix_name": {"v_range": [["v7.6.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "network6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "prefix6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "network_import_check": {
                    "v_range": [["v7.0.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "global"},
                        {"value": "enable"},
                        {"value": "disable"},
                    ],
                },
                "backdoor": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_map": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "admin_distance": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "neighbour_prefix": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "route_list": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "distance": {"v_range": [["v6.0.0", ""]], "type": "integer"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "vrf": {
            "type": "list",
            "elements": "dict",
            "children": {
                "vrf": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "role": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "standalone"},
                        {"value": "ce"},
                        {"value": "pe"},
                    ],
                },
                "rd": {"v_range": [["v7.2.0", ""]], "type": "string"},
                "export_rt": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "route_target": {
                            "v_range": [["v7.2.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.2.0", ""]],
                },
                "import_rt": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "route_target": {
                            "v_range": [["v7.2.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.2.0", ""]],
                },
                "import_route_map": {"v_range": [["v7.2.0", ""]], "type": "string"},
                "leak_target": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "vrf": {
                            "v_range": [["v7.2.0", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "route_map": {"v_range": [["v7.2.0", ""]], "type": "string"},
                        "interface": {"v_range": [["v7.2.0", ""]], "type": "string"},
                    },
                    "v_range": [["v7.2.0", ""]],
                },
            },
            "v_range": [["v7.2.0", ""]],
        },
        "vrf6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "vrf": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "role": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [
                        {"value": "standalone"},
                        {"value": "ce"},
                        {"value": "pe"},
                    ],
                },
                "rd": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "export_rt": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "route_target": {
                            "v_range": [["v7.4.2", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.4.2", ""]],
                },
                "import_rt": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "route_target": {
                            "v_range": [["v7.4.2", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.4.2", ""]],
                },
                "import_route_map": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "leak_target": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "vrf": {
                            "v_range": [["v7.2.0", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "route_map": {"v_range": [["v7.2.0", ""]], "type": "string"},
                        "interface": {"v_range": [["v7.2.0", ""]], "type": "string"},
                    },
                    "v_range": [["v7.2.0", ""]],
                },
            },
            "v_range": [["v7.2.0", ""]],
        },
        "redistribute": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                    "required": True,
                },
                "status": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_map": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                },
            },
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
        },
        "redistribute6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                    "required": True,
                },
                "status": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "route_map": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                },
            },
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
        },
        "vrf_leak": {
            "type": "list",
            "elements": "dict",
            "children": {
                "vrf": {
                    "v_range": [["v6.4.0", "v7.0.12"]],
                    "type": "string",
                    "required": True,
                },
                "target": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "vrf": {
                            "v_range": [["v6.4.0", "v7.0.12"]],
                            "type": "string",
                            "required": True,
                        },
                        "route_map": {
                            "v_range": [["v6.4.0", "v7.0.12"]],
                            "type": "string",
                        },
                        "interface": {
                            "v_range": [["v6.4.0", "v7.0.12"]],
                            "type": "string",
                        },
                    },
                    "v_range": [["v6.4.0", "v7.0.12"]],
                },
            },
            "v_range": [["v6.4.0", "v7.0.12"]],
        },
        "vrf_leak6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "vrf": {
                    "v_range": [["v7.0.1", "v7.0.12"]],
                    "type": "string",
                    "required": True,
                },
                "target": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "vrf": {
                            "v_range": [["v7.0.1", "v7.0.12"]],
                            "type": "string",
                            "required": True,
                        },
                        "route_map": {
                            "v_range": [["v7.0.1", "v7.0.12"]],
                            "type": "string",
                        },
                        "interface": {
                            "v_range": [["v7.0.1", "v7.0.12"]],
                            "type": "string",
                        },
                    },
                    "v_range": [["v7.0.1", "v7.0.12"]],
                },
            },
            "v_range": [["v7.0.1", "v7.0.12"]],
        },
    },
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = None
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": "bool", "default": False},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"],
        },
        "router_bgp": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["router_bgp"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["router_bgp"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    check_legacy_fortiosapi(module)

    is_error = False
    has_changed = False
    result = None
    diff = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "access_token" in module.params:
            connection.set_custom_option("access_token", module.params["access_token"])

        if "enable_log" in module.params:
            connection.set_custom_option("enable_log", module.params["enable_log"])
        else:
            connection.set_custom_option("enable_log", False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "router_bgp"
        )

        is_error, has_changed, result, diff = fortios_router(
            module.params, fos, module.check_mode
        )

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortOS system and your playbook, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
                diff=diff,
            )
        else:
            module.exit_json(changed=has_changed, meta=result, diff=diff)
    else:
        if versions_check_result and versions_check_result["matched"] is False:
            module.fail_json(
                msg="Error in repo",
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == "__main__":
    main()
