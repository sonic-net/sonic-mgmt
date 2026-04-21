#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_route_maps
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_route_maps
version_added: "2.1.0"
author: "Kerry Meyer (@kerry-meyer)"
notes:
  - Supports C(check_mode).
short_description: route map configuration handling for SONiC
description:
  - This module provides configuration management for route map parameters on devices running SONiC.
options:
  config:
    description:
      - Specifies a list of route map configuration dictionaries
    type: list
    elements: dict
    suboptions:
      map_name:
        description:
          - Name of a route map
        type: str
        required: true
      action:
        description:
          - action type for the route map (permit or deny)
          - This value is required for creation and modification of a route
          - map or route map attributes as well as for deletion of route map
          - attributes. It can be omitted only when requesting deletion of a
          - route map statement or all route map statements for a given route
          - map map_name.
        type: str
        choices:
          - permit
          - deny
      sequence_num:
        description:
          - "unique number in the range 1-66535 to specify priority of the map"
          - This value is required for creation and modification of a route
          - map or route map attributes as well as for deletion of route map
          - attributes. It can be omitted only when requesting deletion of all
          - route map "statements" for a given route map "map_name".
        type: int
      match:
        description: Criteria for matching the route map to a route
        type: dict
        suboptions:
          as_path:
            description:
              - Name of a configured BGP AS path list to be checked for
              - a match with the target route
            type: str
          community:
            description:
              - Name of a configured BGP "community" to be checked for
              - a match with the target route
            type: str
          evpn:
            description:
              - BGP Ethernet Virtual Private Network to be checked for
              - a match with the target route
            type: dict
            suboptions:
              default_route:
                description:
                  - "Default EVPN type-5 route"
                type: bool
              route_type:
                description:
                  - "Non-default route type: One of the following:"
                  - "mac-ip route, EVPN Type 3 Inclusive Multicast Ethernet"
                  - Tag (IMET) route, or prefix route
                type: str
                choices:
                  - macip
                  - multicast
                  - prefix
              vni:
                description:
                  - VNI ID to be checked for a match; specified by a value in the
                  - "range 1-16777215"
                type: int
          ext_comm:
            description:
              - Name of a configured BGP 'extended community' to be checked for
              - a match with the target route
            type: str
          interface:
            description:
              - Next hop interface name (type and number) to be checked for a
              - match with the target route. The interface type can be any
              - "of the following; 'Ethernet/Eth' interface or sub-interface,"
              - "'Loopback' interface, 'PortChannel' interface or"
              - "sub-interface, 'Vlan' interface."
            type: str
          ip:
            description:
              - IP addresses or IP next hops to be checked for a match with the
              - target route
            type: dict
            suboptions:
              address:
                description:
                  - name of an IPv4 prefix list containing a list of address
                  - prefixes to be checked for a match with the target route
                type: str
              next_hop:
                description:
                  - "name of a prefix list containing a list of next-hop"
                  - prefixes to be checked for a match with the target route
                type: str
          ipv6:
            description:
              - IPv6 addresses to be checked for a match with the
              - target route
            type: dict
            suboptions:
              address:
                description:
                  - name of an IPv6 prefix list containing a list of address
                  - prefixes to be checked for a match with the target route
                type: str
                required: true
          local_preference:
            description:
              - "local-preference value to be checked for a match with the"
              - "target route. This is a value in the range 0-4294967295."
            type: int
          metric:
            description:
              - metric value to be checked for a match with the target route.
              - "This is a value in the range 0-4294967295."
            type: int
          origin:
            description:
              - BGP origin to be checked for a match with the target route
            type: str
            choices:
              - egp
              - igp
              - incomplete
          peer:
            description:
              - BGP routing peer/neighbor required for a matching route
              - I(ip), I(ipv6), and I(interface) are mutually exclusive.
            type: dict
            suboptions:
              ip:
                description: IPv4 address of a BGP peer
                type: str
              ipv6:
                description: IPv6 address of a BGP peer
                type: str
              interface:
                description:
                  - Name (type and number) of a BGP peer interface
                  - Allowed interface types are Ethernet or Eth (depending
                  - "on the configured interface-naming mode),"
                  - Vlan, and Portchannel
                type: str
          source_protocol:
            description: Source protocol required for a matching route
            type: str
            choices:
              - bgp
              - connected
              - ospf
              - static
          source_vrf:
            description: Name of the source VRF required for a matching route
            type: str
          tag:
            description:
              - Tag value required for a matching route
              - "The value must be in the range 1-4294967295"
            type: int
      set:
        description: "Information to set into a matching route for re-distribution"
        type: dict
        suboptions:
          ars_object:
            description:
              - Adaptive Routing and Switching object
            type: str
            version_added: 3.1.0
          as_path_prepend:
            description:
              - "String specifying a comma-separated list of AS-path numbers"
              - "to prepend to the BGP AS-path attribute in a matched route."
              - "AS-path values in the list must be in the range"
              - "1-4294967295; for example, 2000,3000"
            type: str
          comm_list_delete:
            description:
              - String specifying the name of a BGP community list containing
              - BGP Community values to be deleted from matching routes.
            type: str
          community:
            description:
              - BGP community attributes to add to or replace the BGP
              - community attributes in a matching route. Specifying the
              - "'additive' attribute is allowed only if one of"
              - the other attributes (other than 'none') is specified.
              - It causes the specified 'set community' attributes
              - to be added to the already existing community
              - "attributes in the matching route. If the 'additive' attribute"
              - is not specified, the previously existing community attributes
              - in the matching route are replaced by the configured
              - "'set community' attributes. Specifying a 'set community' attribute"
              - of 'none' is mutually exclusive with setting of other community
              - attributes and causes any community attributes in the matching
              - route to be removed.
            type: dict
            suboptions:
              community_number:
                description:
                  - A list of one or more BGP community numbers in the
                  - "form AA:NN where AA and NN are integers in the range"
                  - "0-65535."
                  - "Note: Each community number in the list must be enclosed"
                  - in double quotes to avoid YAML parsing errors due to the
                  - "list values containing an embedded ':' character."
                type: list
                elements: str
              community_attributes:
                description:
                  - A list of one or more BGP community attributes. The allowed
                  - "values are the following:"
                  - local_as
                  -   Do not send outside local AS (well-known community)
                  - no_advertise
                  -   Do not advertise to any peer (well-known community)
                  - no_export
                  -   Do not export to next AS (well-known community)
                  - no_peer
                  -   "The route does not need to be advertised to peers."
                  -   (Advertisement of the route can be suppressed based
                  -   on other criteria.)
                  - additive
                  -   Add the configured 'set community' attributes to
                  -   "the matching route (if set to 'true'); Previously existing"
                  -   attributes in the matching route are, instead, replaced
                  -   by the configured attributes if this attribute is
                  -   not specified or if it is set to 'false'.
                  - none
                  -   Do not send any community attribute. This attribute
                  -   is mutually exclusive with all other 'set community'
                  -   attributes. It causes all attributes to be removed
                  -   from the matching route.
                  - "I(none) is mutually exclusive with all of the other attributes:"
                  - I(local_as), I(no_advertise), I(no_export), I(no_peer), I(additive),
                  - and I(additive).
                type: list
                elements: str
                choices:
                  - local_as
                  - no_advertise
                  - no_export
                  - no_peer
                  - additive
                  - none
          extcommunity:
            description:
              - BGP extended community attributes to set into a matching route.
            type: dict
            suboptions:
              rt:
                description:
                  - Route Target VPN extended communities in the format
                  - "ASN:NN or IP-ADDRESS:NN"
                  - "Note: Each rt value in the list must be enclosed"
                  - in double quotes to avoid YAML parsing errors due to the
                  - "list values containing an embedded ':' character."
                type: list
                elements: str
              soo:
                description:
                  - "Site-of-Origin VPN extended communities in the format"
                  - "ASN:NN or IP-ADDRESS:NN"
                  - "Note: Each rt value in the list must be enclosed"
                  - in double quotes to avoid YAML parsing errors due to the
                  - "list values containing an embedded ':' character."
                type: list
                elements: str
              bandwidth:
                version_added: "3.1.0"
                description:
                  - Link bandwidth extended community
                type: dict
                suboptions:
                  bandwidth_value:
                    description:
                      - "Options are one of the following values"
                      - "<1..4294967295>  Cumulative bandwidth of all multipaths (outbound-only)"
                      - "num-multipaths   Internally computed bandwidth based on number of multipaths (outbound-only)"
                    type: str
                    required: true
                  transitive_value:
                    description:
                      - The operational default is false if this option is not specified.
                      - True for transitive, false for non-transitive. If true, include the
                      - link bandwidth extcommunity in route advertisements sent to
                      - neighbors across AS boundaries (eBGP neighbors). If false,
                      - drop the link bandwidth extcommunity from route advertisements
                      - sent across AS boundaries.
                    type: bool
          ip_next_hop:
            description:
              - IPv4 next hop address attributes to set into a matching route
            type: dict
            suboptions:
              address:
                description:
                  - IPv4 next hop address to set into a matching route in the
                  - dotted decimal format A.B.C.D
                type: str
              native:
                description: Set native or underlay nexthop
                type: bool
          ipv6_next_hop:
            description:
              - IPv6 next hop address attributes to set into a matching route
            type: dict
            suboptions:
              global_addr:
                description:
                  - IPv6 global next hop address to set into a matching
                  - "route in the format A::B"
                type: str
              prefer_global:
                description:
                  - Set the corresponding attribute into a matching route
                  - if the value of this Ansible attribute is 'true'.
                  - The attribute indicates that the routing algorithm must
                  - "prefer the global next-hop address over the link-local"
                  - address if both exist.
                type: bool
              native:
                description: Set native or underlay nexthop
                type: bool
          local_preference:
            description:
                - "BGP local preference path attribute; integer value in"
                - "the range 0-4294967295"
            type: int
          metric:
            description:
              - route metric value actions
              - I(value) and I(rtt_action) are mutually exclusive.
            type: dict
            suboptions:
              value:
                description:
                  - "metric value to be set into a matching route;"
                  - "value in the range 0-4294967295"
                type: int
              rtt_action:
                description:
                  - Action to take for modifying the metric for a matched
                  - "route using the Round Trip Time (rtt);"
                  - C(set) causes the route metric to be set to the
                  - rtt value.
                  - C(add) causes the rtt value to be added
                  - to the route metric.
                  - C(subtract) causes the rtt value to be
                  - subtracted from route metric.
                type: str
                choices:
                  - set
                  - add
                  - subtract
          origin:
            description:
              - "BGP route origin; One of the following must be selected."
              - "egp (External; remote EGP)"
              - "igp (Internal; local IGP)"
              - incomplete (Unknown origin)
            type: str
            choices:
              - egp
              - igp
              - incomplete
          weight:
            description:
              - "BGP weight to be set for a matching route: The weight must be"
              - "an integer in the range 0-4294967295"
            type: int
          tag:
            description:
              - Tag value to be set for a matching route
              - "The value must be in the range 1-4294967295"
            type: int
      call:
        description:
          - Name of a route map to jump to after executing 'match' and 'set'
          - statements for the current route map.
        type: str

  state:
    description:
      - Specifies the type of configuration update to be performed on the device.
      - For C(merged), merge specified attributes with existing configured attributes.
      - For C(deleted), delete the specified attributes from existing configuration.
      - For C(replaced), replace each modified list or dictionary with the
      - specified items.
      - For C(overridden), replace all current configuration for this resource
      - module with the specified configuration.
    type: str
    choices:
      - merged
      - deleted
      - replaced
      - overridden
    default: merged
"""

EXAMPLES = """
# Using "merged" state to create initial configuration
#
# Before state:
# -------------
#
# sonic# show running-configuration route-map
# sonic#
# (No configuration present)
#
# -------------
#
- name: Merge initial route_maps configuration
  dellemc.enterprise_sonic.sonic_route_maps:
    config:
      - map_name: rm1
        action: permit
        sequence_num: 80
        match:
          as_path: bgp_as1
          community: bgp_comm_list1
          evpn:
            default_route: true
            vni: 735
          ext_comm: bgp_ext_comm1
          interface: Ethernet4
          ip:
            address: ip_pfx_list1
          ipv6:
            address: ipv6_pfx_list1
          local_preference: 8000
          metric: 400
          origin: egp
          peer:
            ip: 10.20.30.40
          source_protocol: bgp
          source_vrf: Vrf1
          tag: 7284
        set:
          as_path_prepend: 200,315,7135
          comm_list_delete: bgp_comm_list2
          community:
            community_number:
              - "35:58"
              - "79:150"
              - "308:650"
            community_attributes:
              - local_as
              - no_advertise
              - no_export
              - no_peer
              - additive
          extcommunity:
            rt:
              - "30:40"
            soo:
              - "10.73.14.9:78"
          ip_next_hop:
            address: 10.48.16.18
            native: true
          ipv6_next_hop:
            global_addr: 30::30
            prefer_global: true
            native: true
          local_preference: 635
          metric:
            metric_value: 870
          origin: egp
          weight: 93471
          tag: 65
      - map_name: rm1
        action: deny
        sequence_num: 3047
        match:
          evpn:
            route_type: multicast
          origin: incomplete
          peer:
            interface: Ethernet6
          source_protocol: ospf
        set:
          metric:
            rtt_action: add
          origin: incomplete
      - map_name: rm3
        action: deny
        sequence_num: 285
        match:
          evpn:
            route_type: macip
          origin: igp
          peer:
            ipv6: 87:95:15::53
          source_protocol: connected
        set:
          community:
            community_attributes:
              - none
          metric:
            rtt_action: set
          origin: igp
        call: rm1
      - map_name: rm4
        action: permit
        sequence_num: 480
        match:
          evpn:
            route_type: prefix
          source_protocol: static
        set:
          metric:
            rtt_action: subtract
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration route-map
# !
# route-map rm1 permit 80
#  match as-path bgp_as1
#  match evpn default-route
#  match evpn vni 735
#  match ip address prefix-list ip_pfx_list1
#  match ipv6 address prefix-list ipv6_pfx_list1
#  match interface Ethernet4
#  match community bgp_comm_list1
#  match ext-community bgp_ext_comm1
#  match tag 7284
#  match local-preference 8000
#  match source-vrf Vrf1
#  match peer 10.20.30.40
#  match source-protocol bgp
#  match metric 400
#  match origin egp
#  set as-path prepend 200,315,7135
#  set community 35:58 79:150 308:650 local-AS no-advertise no-export no-peer additive
#  set extcommunity rt 30:40
#  set extcommunity soo 10.73.14.9:78
#  set comm-list bgp_comm_list2 delete
#  set metric 870
#  set ip next-hop 10.48.16.18
#  set ip next-hop native true
#  set ipv6 next-hop global 30::30
#  set ipv6 next-hop prefer-global
# set ipv6 next-hop native true
#  set local-preference 635
#  set origin egp
#  set weight 93471
#  set tag 65
# !
# route-map rm1 deny 3047
#  match evpn route-type multicast
#  match peer Ethernet6
#  match source-protocol ospf
#  match origin incomplete
#  set metric +rtt
#  set origin incomplete
# !
# route-map rm3 deny 285
#  match evpn route-type macip
#  call rm1
#  match peer 87:95:15::53
#  match source-protocol connected
#  match origin igp
#  set community none
#  set metric rtt
#  set origin igp
# !
# route-map rm4 permit 480
#  match evpn route-type prefix
#  match source-protocol static
#  set metric -rtt
# ------------


# Using "merged" state to update and add configuration
#
# Before state:
# ------------
#
# sonic# show running-configuration route-map
# !
# route-map rm1 permit 80
#  match as-path bgp_as1
#  match evpn default-route
#  match evpn vni 735
#  match ip address prefix-list ip_pfx_list1
#  match ipv6 address prefix-list ipv6_pfx_list1
#  match interface Ethernet4
#  match community bgp_comm_list1
#  match ext-community bgp_ext_comm1
#  match tag 7284
#  match local-preference 8000
#  match source-vrf Vrf1
#  match peer 10.20.30.40
#  match source-protocol bgp
#  match metric 400
#  match origin egp
#  set as-path prepend 200,315,7135
#  set community 35:58 79:150 308:650 local-AS no-advertise no-export no-peer additive
#  set extcommunity rt 30:40
#  set extcommunity soo 10.73.14.9:78
#  set comm-list bgp_comm_list2 delete
#  set metric 870
#  set ip next-hop 10.48.16.18
#  set ipv6 next-hop global 30::30
#  set ipv6 next-hop prefer-global
#  set local-preference 635
#  set origin egp
#  set weight 93471
#  set tag 65
# !
# route-map rm1 deny 3047
#  match evpn route-type multicast
#  match peer Ethernet6
#  match source-protocol ospf
#  match origin incomplete
#  set metric +rtt
#  set origin incomplete
# !
# route-map rm3 deny 285
#  match evpn route-type macip
#  call rm1
#  match peer 87:95:15::53
#  match source-protocol connected
#  match origin igp
#  set community none
#  set metric rtt
#  set origin igp
# !
# route-map rm4 permit 480
#  match evpn route-type prefix
#  match source-protocol static
#  set metric -rtt
# ------------
#
- name: Merge additional and modified route map configuration
  dellemc.enterprise_sonic.sonic_route_maps:
    config:
      - map_name: rm1
        action: permit
        sequence_num: 80
        match:
          as_path: bgp_as2
          community: bgp_comm_list3
          evpn:
            route_type: prefix
            vni: 850
          interface: Vlan7
          ip:
            address: ip_pfx_list2
            next_hop: ip_pfx_list3
          peer:
            interface: Portchannel14
        set:
          as_path_prepend: 188,257
          community:
            community_number:
              - "45:736"
          ipv6_next_hop:
            prefer_global: false
          metric:
            rtt_action: add
      - map_name: rm1
        action: deny
        sequence_num: 3047
        match:
          as_path: bgp_as3
          ext_comm: bgp_ext_comm2
          origin: igp
        set:
          metric:
            rtt_action: subtract
      - map_name: rm2
        action: permit
        sequence_num: 100
        match:
          interface: Ethernet16
        set:
          as_path_prepend: 200,300,400
          ipv6_next_hop:
            global_addr: 37::58
            prefer_global: true
          metric: 8000
      - map_name: rm3
        action: deny
        sequence_num: 285
        match:
          local_preference: 14783
          source_protocol: bgp
        set:
          community:
            community_attributes:
              - no_advertise
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration route-map
# !
# route-map rm1 permit 80
#  match as-path bgp_as2
#  match evpn default-route
#  match evpn route-type prefix
#  match evpn vni 850
#  match ip address prefix-list ip_pfx_list2
#  match ipv6 address prefix-list ipv6_pfx_list1
#  match interface Vlan7
#  match community bgp_comm_list3
#  match ext-community bgp_ext_comm1
#  match tag 7284
#  match local-preference 8000
#  match source-vrf Vrf1
#  match ip next-hop prefix-list ip_pfx_list3
#  match peer PortChannel 14
#  match source-protocol bgp
#  match metric 400
#  match origin egp
#  set as-path prepend 188,257
#  set community 35:58 79:150 308:650 45:736 local-AS no-advertise no-export no-peer additive
#  set extcommunity rt 30:40
#  set extcommunity soo 10.73.14.9:78
#  set comm-list bgp_comm_list2 delete
#  set metric +rtt
#  set ip next-hop 10.48.16.18
#  set ipv6 next-hop global 30::30
#  set local-preference 635
#  set origin egp
#  set weight 93471
#  set tag 65
# !
# route-map rm1 deny 3047
#  match as-path bgp_as3
#  match evpn route-type multicast
#  match ext-community bgp_ext_comm2
#  match peer Ethernet6
#  match source-protocol ospf
#  match origin igp
#  set metric -rtt
#  set origin incomplete
# !
# route-map rm2 permit 100
#  match interface Ethernet16
#  set as-path prepend 200,300,400
#  set ipv6 next-hop global 37::58
#  set ipv6 next-hop prefer-global
#  set metric 8000
# !
# route-map rm3 deny 285
#  match evpn route-type macip
#  match local-preference 14783
#  call rm1
#  match peer 87:95:15::53
#  match source-protocol bgp
#  match origin igp
#  set community no-advertise
#  set metric rtt
#  set origin igp
# !
# route-map rm4 permit 480
#  match evpn route-type prefix
#  match source-protocol static
#  set metric -rtt


# Using "replaced" state to replace the contents of a list
#
# Before state:
# ------------
#
# sonic(config-route-map)# do show running-configuration route-map rm1 80
# !
# route-map rm1 permit 80
#  match as-path bgp_as2
#  match evpn default-route
#  match evpn route-type prefix
#  match evpn vni 850
#  match ip address prefix-list ip_pfx_list2
#  match ipv6 address prefix-list ipv6_pfx_list1
#  match interface Vlan7
#  match community bgp_comm_list3
#  match ext-community bgp_ext_comm1
#  match tag 7284
#  match local-preference 8000
#  match source-vrf Vrf1
#  match ip next-hop prefix-list ip_pfx_list3
#  match peer PortChannel 14
#  match source-protocol bgp
#  match metric 400
#  match origin egp
#  set as-path prepend 188,257
#  set community 35:58 79:150 308:650 45:736 local-AS no-export no-peer additive
#  set extcommunity rt 30:40
#  set extcommunity soo 10.73.14.9:78
#  set comm-list bgp_comm_list2 delete
#  set metric +rtt
#  set ip next-hop 10.48.16.18
#  set ipv6 next-hop global 30::30
#  set local-preference 635
#  set origin egp
#  set weight 93471
#  set tag 65
# ------------
- name: Replace a list
  dellemc.enterprise_sonic.sonic_route_maps:
    config:
      - map_name: rm1
        action: permit
        sequence_num: 80
        set:
          community:
            community_number:
              - "15:30"
              - "26:54"
    state: replaced

# After state:
# ------------
#
# sonic#show running-configuration route-map rm1 80
# !
# route-map rm1 permit 80
#  match as-path bgp_as2
#  match evpn default-route
#  match evpn route-type prefix
#  match evpn vni 850
#  match ip address prefix-list ip_pfx_list2
#  match ipv6 address prefix-list ipv6_pfx_list1
#  match interface Vlan7
#  match community bgp_comm_list3
#  match ext-community bgp_ext_comm1
#  match tag 7284
#  match local-preference 8000
#  match source-vrf Vrf1
#  match ip next-hop prefix-list ip_pfx_list3
#  match peer PortChannel 14
#  match source-protocol bgp
#  match metric 400
#  match origin egp
#  set as-path prepend 188,257
#  set community 15:30 26:54 local-AS no-export no-peer additive
#  set extcommunity rt 30:40
#  set extcommunity soo 10.73.14.9:78
#  set comm-list bgp_comm_list2 delete
#  set metric +rtt
#  set ip next-hop 10.48.16.18
#  set ipv6 next-hop global 30::30
#  set local-preference 635
#  set origin egp
#  set weight 93471
#  set tag 65


# Using "replaced" state to replace the contents of dictionaries
#
# Before state:
# ------------
# sonic# show running-configuration route-map
# !
# route-map rm1 permit 80
#  match as-path bgp_as2
#  match evpn default-route
#  match evpn route-type prefix
#  match evpn vni 850
#  match ip address prefix-list ip_pfx_list2
#  match ipv6 address prefix-list ipv6_pfx_list1
#  match interface Vlan7
#  match community bgp_comm_list3
#  match ext-community bgp_ext_comm1
#  match tag 7284
#  match local-preference 8000
#  match source-vrf Vrf1
#  match ip next-hop prefix-list ip_pfx_list3
#  match peer PortChannel 14
#  match source-protocol bgp
#  match metric 400
#  match origin egp
#  set as-path prepend 188,257
#  set community 15:30 26:54 local-AS no-export no-peer additive
#  set extcommunity rt 30:40
#  set extcommunity soo 10.73.14.9:78
#  set comm-list bgp_comm_list2 delete
#  set metric +rtt
#  set ip next-hop 10.48.16.18
#  set ipv6 next-hop global 30::30
#  set local-preference 635
#  set origin egp
#  set weight 93471
#  set tag 65
# !
# route-map rm1 deny 3047
#  match as-path bgp_as3
#  match evpn route-type multicast
#  match ext-community bgp_ext_comm2
#  match peer Ethernet6
#  match source-protocol ospf
#  match origin igp
#  set metric -rtt
#  set origin incomplete
# !
# route-map rm2 permit 100
#  match interface Ethernet16
#  set as-path prepend 200,300,400
#  set ipv6 next-hop global 37::58
#  set ipv6 next-hop prefer-global
#  set metric 8000
# !
# route-map rm3 deny 285
#  match evpn route-type macip
#  match local-preference 14783
#  call rm1
#  match peer 87:95:15::53
#  match source-protocol bgp
#  match origin igp
#  set community no-advertise
#  set metric rtt
#  set origin igp
# !
# route-map rm4 permit 480
#  match evpn route-type prefix
#  match source-protocol static
#  set metric -rtt
# ------------
- name: Replace dictionaries
  dellemc.enterprise_sonic.sonic_route_maps:
    config:
      - map_name: rm1
        action: permit
        sequence_num: 80
        match:
          evpn:
            route_type: multicast
          ip:
            address: ip_pfx_list1
        set:
          community:
            community_attributes:
              - no_advertise
          extcommunity:
            rt:
              - "20:20"
      - map_name: rm2
        action: permit
        sequence_num: 100
        set:
          ipv6_next_hop:
            global_addr: 45::90
            native: true
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration route-map
# !
# route-map rm1 permit 80
#  match as-path bgp_as2
#  match evpn route-type multicast
#  match ip address prefix-list ip_pfx_list1
#  match ipv6 address prefix-list ipv6_pfx_list1
#  match interface Vlan7
#  match community bgp_comm_list3
#  match ext-community bgp_ext_comm1
#  match tag 7284
#  match local-preference 8000
#  match source-vrf Vrf1
#  match peer PortChannel 14
#  match source-protocol bgp
#  match metric 400
#  match origin egp
#  set as-path prepend 188,257
#  set community no-advertise
#  set extcommunity rt 20:20
#  set comm-list bgp_comm_list2 delete
#  set metric +rtt
#  set ip next-hop 10.48.16.18
#  set ipv6 next-hop global 30::30
#  set local-preference 635
#  set origin egp
#  set weight 93471
#  set tag 65
# !
# route-map rm1 deny 3047
#  match as-path bgp_as3
#  match evpn route-type multicast
#  match ext-community bgp_ext_comm2
#  match peer Ethernet6
#  match source-protocol ospf
#  match origin igp
#  set metric -rtt
#  set origin incomplete
# !
# route-map rm2 permit 100
#  match interface Ethernet16
#  set as-path prepend 200,300,400
#  set metric 8000
#  set ipv6 next-hop global 45::90
# set ipv6 next-hop native true
# !
# route-map rm3 deny 285
#  match evpn route-type macip
#  match local-preference 14783
#  call rm1
#  match peer 87:95:15::53
#  match source-protocol bgp
#  match origin igp
#  set community no-advertise
#  set metric rtt
#  set origin igp
# !
# route-map rm4 permit 480
#  match evpn route-type prefix
#  match source-protocol static
#  set metric -rtt


# Using "overridden" state to override all existing configuration with new
# configuration
#
# Before state:
# ------------
#
# sonic# show running-configuration route-map
# !
# route-map rm1 permit 80
#  match as-path bgp_as2
#  match evpn route-type multicast
#  match ip address prefix-list ip_pfx_list1
#  match ipv6 address prefix-list ipv6_pfx_list1
#  match interface Vlan7
#  match community bgp_comm_list3
#  match ext-community bgp_ext_comm1
#  match tag 7284
#  match local-preference 8000
#  match source-vrf Vrf1
#  match peer PortChannel 14
#  match source-protocol bgp
#  match metric 400
#  match origin egp
#  set as-path prepend 188,257
#  set community no-advertise
#  set extcommunity rt 30:40
#  set extcommunity rt 20:20
#  set comm-list bgp_comm_list2 delete
#  set metric +rtt
#  set ip next-hop 10.48.16.18
#  set ipv6 next-hop global 30::30
#  set local-preference 635
#  set origin egp
#  set weight 93471
#  set tag 65
# !
# route-map rm1 deny 3047
#  match as-path bgp_as3
#  match evpn route-type multicast
#  match ext-community bgp_ext_comm2
#  match peer Ethernet6
#  match source-protocol ospf
#  match origin igp
#  set metric -rtt
#  set origin incomplete
# !
# route-map rm2 permit 100
#  match interface Ethernet16
#  set as-path prepend 200,300,400
#  set metric 8000
#  set ipv6 next-hop global 45::90
# !
# route-map rm3 deny 285
#  match evpn route-type macip
#  match local-preference 14783
#  call rm1
#  match peer 87:95:15::53
#  match source-protocol bgp
#  match origin igp
#  set community no-advertise
#  set metric rtt
#  set origin igp
# !
# route-map rm4 permit 480
#  match evpn route-type prefix
#  match source-protocol static
#  set metric -rtt
# ------------
- name: Override all route map configuration with new configuration
  dellemc.enterprise_sonic.sonic_route_maps:
    config:
      - map_name: rm5
        action: permit
        sequence_num: 250
        match:
          interface: Ethernet28
        set:
          as_path_prepend: 150,275
          metric: 7249
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration route-map
# !
# route-map rm5 permit 250
#  match interface Ethernet28
#  set as-path prepend 150,275
#  set metric 7249


# Using "overridden" state to override all existing configuration with new
# configuration. (Restore previous configuration.)
#
# Before state:
# ------------
#
# sonic# show running-configuration route-map
# !
# route-map rm5 permit 250
#  match interface Ethernet28
#  set as-path prepend 150,275
#  set metric 7249
# ------------
- name: Override (restore) all route map configuration with older configuration
  dellemc.enterprise_sonic.sonic_route_maps:
    config:
      - map_name: rm1
        action: permit
        sequence_num: 80
        match:
          as_path: bgp_as2
          community: bgp_comm_list3
          evpn:
            default_route: true
            route_type: prefix
            vni: 850
          ext_comm: bgp_ext_comm1
          interface: Vlan7
          ip:
            address: ip_pfx_list2
            next_hop: ip_pfx_list3
          ipv6:
            address: ipv6_pfx_list1
          local_preference: 8000
          metric: 400
          origin: egp
          peer:
            interface: Portchannel14
          source_protocol: bgp
          source_vrf: Vrf1
          tag: 7284
        set:
          as_path_prepend: 188,257
          comm_list_delete: bgp_comm_list2
          community:
            community_number:
              - "35:58"
              - "79:150"
              - "308:650"
              - "45:736"
            community_attributes:
              - local_as
              - no_export
              - no_peer
              - additive
          extcommunity:
            rt:
              - "30:40"
            soo:
              - "10.73.14.9:78"
          ip_next_hop:
            address: 10.48.16.18
            native: false
          ipv6_next_hop:
            global_addr: 30::30
            native: false
          local_preference: 635
          metric:
            rtt_action: add
          origin: egp
          weight: 93471
          tag: 65
      - map_name: rm1
        action: deny
        sequence_num: 3047
        match:
          as_path: bgp_as3
          evpn:
            route_type: multicast
          ext_comm: bgp_ext_comm2
          origin: igp
          peer:
            interface: Ethernet6
          source_protocol: ospf
        set:
          metric:
            rtt_action: subtract
          origin: incomplete
      - map_name: rm2
        action: permit
        sequence_num: 100
        match:
          interface: Ethernet16
        set:
          as_path_prepend: 200,300,400
          ipv6_next_hop:
            global_addr: 37::58
            prefer_global: true
          metric: 8000
      - map_name: rm3
        action: deny
        sequence_num: 285
        match:
          evpn:
            route_type: macip
          origin: igp
          peer:
            ipv6: 87:95:15::53
          local_preference: 14783
          source_protocol: bgp
        set:
          community:
            community_attributes:
              - no_advertise
          metric:
            rtt_action: set
          origin: igp
        call: rm1
      - map_name: rm4
        action: permit
        sequence_num: 480
        match:
          evpn:
            route_type: prefix
          source_protocol: static
        set:
          metric:
            rtt_action: subtract
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration route-map
# !
# route-map rm1 permit 80
#  match as-path bgp_as2
#  match evpn default-route
#  match evpn route-type prefix
#  match evpn vni 850
#  match ip address prefix-list ip_pfx_list2
#  match ipv6 address prefix-list ipv6_pfx_list1
#  match interface Vlan7
#  match community bgp_comm_list3
#  match ext-community bgp_ext_comm1
#  match tag 7284
#  match local-preference 8000
#  match source-vrf Vrf1
#  match ip next-hop prefix-list ip_pfx_list3
#  match peer PortChannel 14
#  match source-protocol bgp
#  match metric 400
#  match origin egp
#  set as-path prepend 188,257
#  set community 35:58 79:150 308:650 45:736 local-AS no-export no-peer additive
#  set extcommunity rt 30:40
#  set extcommunity soo 10.73.14.9:78
#  set comm-list bgp_comm_list2 delete
#  set metric +rtt
#  set ip next-hop 10.48.16.18
#  set ip next-hop native false
#  set ipv6 next-hop global 30::30
#  set ipv6 next-hop native false
#  set local-preference 635
#  set origin egp
#  set weight 93471
#  set tag 65
# !
# route-map rm1 deny 3047
#  match as-path bgp_as3
#  match evpn route-type multicast
#  match ext-community bgp_ext_comm2
#  match peer Ethernet6
#  match source-protocol ospf
#  match origin igp
#  set metric -rtt
#  set origin incomplete
# !
# route-map rm2 permit 100
#  match interface Ethernet16
#  set as-path prepend 200,300,400
#  set ipv6 next-hop global 37::58
#  set ipv6 next-hop prefer-global
#  set metric 8000
# !
# route-map rm3 deny 285
#  match evpn route-type macip
#  match local-preference 14783
#  call rm1
#  match peer 87:95:15::53
#  match source-protocol bgp
#  match origin igp
#  set community no-advertise
#  set metric rtt
#  set origin igp
# !
# route-map rm4 permit 480
#  match evpn route-type prefix
#  match source-protocol static
#  set metric -rtt


# Using "deleted" state to remove configuration
#
# Before state:
# ------------
#
# sonic# show running-configuration route-map rm1 80
# !
# route-map rm1 permit 80
#  match as-path bgp_as2
#  match evpn default-route
#  match evpn route-type prefix
#  match evpn vni 850
#  match ip address prefix-list ip_pfx_list2
#  match ipv6 address prefix-list ipv6_pfx_list1
#  match interface Vlan7
#  match community bgp_comm_list3
#  match ext-community bgp_ext_comm1
#  match tag 7284
#  match local-preference 8000
#  match source-vrf Vrf1
#  match ip next-hop prefix-list ip_pfx_list3
#  match peer PortChannel 14
#  match source-protocol bgp
#  match metric 400
#  match origin egp
#  set as-path prepend 188,257
#  set community 35:58 79:150 308:650 45:736 local-AS no-export no-peer additive
#  set extcommunity rt 30:40
#  set extcommunity soo 10.73.14.9:78
#  set comm-list bgp_comm_list2 delete
#  set metric +rtt
#  set ip next-hop 10.48.16.18
#  set ip next-hop native true
#  set ipv6 next-hop global 30::30
#  set local-preference 635
#  set origin egp
#  set weight 93471
#  set tag 65
# ------------
- name: Delete selected route map configuration
  dellemc.enterprise_sonic.sonic_route_maps:
    config:
      - map_name: rm1
        action: permit
        sequence_num: 80
        match:
          as_path: bgp_as2
          community: bgp_comm_list3
          evpn:
            vni: 850
          ip:
            address: ip_pfx_list2
        set:
          as_path_prepend: 188,257
          ip_next_hop:
          address: 10.48.16.18
          native: true
          ipv6_next_hop:
            native: true
          community:
            community_number:
              - "35:58"
            community_attributes:
              - local_as
          extcommunity:
            rt:
              - "30:40"
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration route-map rm1 80
# !
# route-map rm1 permit 80
#  match evpn default-route
#  match evpn route-type prefix
#  match ipv6 address prefix-list ipv6_pfx_list1
#  match interface Vlan7
#  match ext-community bgp_ext_comm1
#  match tag 7284
#  match local-preference 8000
#  match source-vrf Vrf1
#  match ip next-hop prefix-list ip_pfx_list3
#  match peer PortChannel 14
#  match source-protocol bgp
#  match metric 400
#  match origin egp
#  set community 79:150 308:650 45:736 no-export no-peer additive
#  set extcommunity soo 10.73.14.9:78
#  set comm-list bgp_comm_list2 delete
#  set metric +rtt
#  set ipv6 next-hop global 30::30
#  set local-preference 635
#  set origin egp
#  set weight 93471
#  set tag 65


# Using "deleted" state to remove a route map or route map subset
#
# Before state:
# ------------
#
# sonic# show running-configuration route-map
# !
# route-map rm1 permit 80
#  match evpn default-route
#  match evpn route-type prefix
#  match ipv6 address prefix-list ipv6_pfx_list1
#  match interface Vlan7
#  match ext-community bgp_ext_comm1
#  match tag 7284
#  match local-preference 8000
#  match source-vrf Vrf1
#  match ip next-hop prefix-list ip_pfx_list3
#  match peer PortChannel 14
#  match source-protocol bgp
#  match metric 400
#  match origin egp
#  set community 79:150 308:650 45:736 no-export no-peer additive
#  set extcommunity soo 10.73.14.9:78
#  set comm-list bgp_comm_list2 delete
#  set metric +rtt
#  set ip next-hop 10.48.16.18
#  set ipv6 next-hop global 30::30
#  set local-preference 635
#  set origin egp
#  set weight 93471
#  set tag 65
# !
# route-map rm1 deny 3047
#  match as-path bgp_as3
#  match evpn route-type multicast
#  match ext-community bgp_ext_comm2
#  match peer Ethernet6
#  match source-protocol ospf
#  match origin igp
#  set metric -rtt
#  set origin incomplete
# !
# route-map rm2 permit 100
#  match interface Ethernet16
#  set as-path prepend 200,300,400
#  set metric 8000
#  set ipv6 next-hop prefer-global
#  set ipv6 next-hop global 37::58
# !
# route-map rm3 deny 285
#  match evpn route-type macip
#  match local-preference 14783
#  call rm1
#  match peer 87:95:15::53
#  match source-protocol bgp
#  match origin igp
#  set community no-advertise
#  set metric rtt
#  set origin igp
# !
# route-map rm4 permit 480
#  match evpn route-type prefix
#  match source-protocol static
#  set metric -rtt
# ------------
- name: Delete a route map subset or a route map
  dellemc.enterprise_sonic.sonic_route_maps:
    config:
      - map_name: rm1
        sequence_num: 3047
      - map_name: rm2
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration route-map
# !
# route-map rm1 permit 80
#  match evpn default-route
#  match evpn route-type prefix
#  match ipv6 address prefix-list ipv6_pfx_list1
#  match interface Vlan7
#  match ext-community bgp_ext_comm1
#  match tag 7284
#  match local-preference 8000
#  match source-vrf Vrf1
#  match ip next-hop prefix-list ip_pfx_list3
#  match peer PortChannel 14
#  match source-protocol bgp
#  match metric 400
#  match origin egp
#  set community 79:150 308:650 45:736 no-export no-peer additive
#  set extcommunity soo 10.73.14.9:78
#  set comm-list bgp_comm_list2 delete
#  set metric +rtt
#  set ip next-hop 10.48.16.18
#  set ipv6 next-hop global 30::30
#  set local-preference 635
#  set origin egp
#  set weight 93471
#  set tag 65
# !
# route-map rm3 deny 285
#  match evpn route-type macip
#  match local-preference 14783
#  call rm1
#  match peer 87:95:15::53
#  match source-protocol bgp
#  match origin igp
#  set community no-advertise
#  set metric rtt
#  set origin igp
# !
# route-map rm4 permit 480
#  match evpn route-type prefix
#  match source-protocol static
#  set metric -rtt


# Using "deleted" state to remove all route map configuration
#
# Before state:
# ------------
#
# sonic# show running-configuration route-map
# !
# route-map rm1 permit 80
#  match evpn default-route
#  match evpn route-type prefix
#  match ipv6 address prefix-list ipv6_pfx_list1
#  match interface Vlan7
#  match ext-community bgp_ext_comm1
#  match tag 7284
#  match local-preference 8000
#  match source-vrf Vrf1
#  match ip next-hop prefix-list ip_pfx_list3
#  match peer PortChannel 14
#  match source-protocol bgp
#  match metric 400
#  match origin egp
#  set community 79:150 308:650 45:736 no-export no-peer additive
#  set extcommunity soo 10.73.14.9:78
#  set comm-list bgp_comm_list2 delete
#  set metric +rtt
#  set ip next-hop 10.48.16.18
#  set ipv6 next-hop global 30::30
#  set local-preference 635
#  set origin egp
#  set weight 93471
#  set tag 65
# !
# route-map rm3 deny 285
#  match evpn route-type macip
#  match local-preference 14783
#  call rm1
#  match peer 87:95:15::53
#  match source-protocol bgp
#  match origin igp
#  set community no-advertise
#  set metric rtt
#  set origin igp
# !
# route-map rm4 permit 480
#  match evpn route-type prefix
#  match source-protocol static
#  set metric -rtt
# ------------
- name: Delete all route map configuration
  dellemc.enterprise_sonic.sonic_route_maps:
    config: []
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration route-map
# sonic#
# (no route map configuration present)
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: list
  sample: >
    The configuration returned will always be in the same format
     as the parameters above.
after:
  description: The resulting configuration module invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
     as the parameters above.
after(generated):
  description: The generated configuration module invocation.
  returned: when C(check_mode)
  type: list
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.route_maps.route_maps import Route_mapsArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.route_maps.route_maps import Route_maps


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Route_mapsArgs.argument_spec,
                           supports_check_mode=True)

    result = Route_maps(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
