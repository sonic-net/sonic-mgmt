#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for iosxr_bgp_templates
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: iosxr_bgp_templates
short_description: Manages BGP templates resource module.
description:
- This module configures and manages the attributes of BGP templates on Cisco IOS-XR platforms.
version_added: 6.0.0
author: Ashwini Mhatre (@amhatre)
notes:
- This module works with connection C(network_cli).
options:
    config:
      description: BGP template configurations.
      type: dict
      suboptions:
        as_number:
          description: Autonomous system number.
          type: str
        neighbor:
            description: A list of BGP neighbor group configurations.
            type: list
            elements: dict
            suboptions:
              name:
                description: Name of neighbor group.
                type: str
              address_family:
                description: Enable address family and enter its config mode
                type: list
                elements: dict
                suboptions:
                  afi:
                    description: address family.
                    type: str
                    choices: [ 'ipv4', 'ipv6', 'vpnv4', 'vpnv6', 'link-state', 'l2vpn']
                  safi:
                    description: Address Family modifier
                    type: str
                    choices: [ 'flowspec', 'mdt', 'multicast', 'mvpn', 'rt-filter', 'tunnel',
                    'unicast', 'labeled-unicast' , 'sr-policy', 'link-state', 'evpn', 'mspw', 'vpls-vpws']
                  signalling:
                    type: dict
                    description: Signalling protocols to disable, BGP or LDP
                    suboptions:
                      bgp_disable:
                        type: bool
                        description: Select BGP to disable
                      ldp_disable:
                        type: bool
                        description: Select LDP to disable
                  advertise:
                    type: dict
                    description: Per neighbor advertisement options
                    suboptions:
                      local_labeled_route:
                        type: dict
                        description: Advertisement of routes with local-label
                        suboptions:
                          set:
                            type: bool
                            description: set local-labeled-route
                          disable:
                            type: bool
                            description: disable local-labeled-route
                      permanent_network:
                        type: bool
                        description: Allow permanent networks for this neighbor
                  aigp:
                    description: AIGP attribute
                    type: dict
                    suboptions:
                      disable:
                        description: Ignore AIGP attribute.
                        type: bool
                      set:
                        description: Set AIGP attribute.
                        type: bool
                      send_cost_community_disable:
                        description: send AIGP attribute.
                        type: bool
                      send_med:
                        description: send med options.
                        type: dict
                        suboptions:
                          set:
                            type: bool
                            description: set Send AIGP value in MED.
                          disable:
                            description: disable Send AIGP value in MED.
                            type: bool
                  allowas_in:
                    type: dict
                    description: Allow as-path with my AS present in it.
                    suboptions:
                      value:
                        type: int
                        description: Number of occurences of AS number 1-10.
                      set:
                        type: bool
                        description: set allowas_in
                  as_override:
                    type: dict
                    description: Override matching AS-number while sending update
                    suboptions:
                      set:
                        type: bool
                        description: set as_override
                      inheritance_disable:
                        type: bool
                        description: Prevent as-override from being inherited from the parent.
                  bestpath_origin_as_allow_invalid:
                    type: bool
                    description: Change default route selection criteria.Allow BGP origin-AS knobs.
                  capability_orf_prefix:
                    type: str
                    description: Advertise address prefix ORF capability to this neighbor.
                    choices: [ 'both', 'send', 'none', 'receive' ]
                  default_originate:
                    type: dict
                    description: Originate default route to this neighbor.
                    suboptions:
                      set:
                        type: bool
                        description: set default route.
                      route_policy:
                        type: str
                        description: Route policy to specify criteria to originate default
                      inheritance_disable:
                        type: bool
                        description: Prevent default-originate from being inherited from the parent.
                  encapsulation_type_srv6:
                    type: bool
                    description: Specify encapsulation type
                  long_lived_graceful_restart:
                    type: dict
                    description: Enable long lived graceful restart support.
                    suboptions:
                      capable:
                        type: bool
                        description: Treat neighbor as LLGR capable.
                      stale_time:
                        type: dict
                        description: Maximum time to wait before purging long-lived stale routes.
                        suboptions:
                          send:
                            type: int
                            description: max send time
                          accept:
                            type: int
                            description: max accept time
                  maximum_prefix:
                    type: dict
                    description: Maximum number of prefixes to accept from this peer.
                    suboptions:
                      max_limit:
                        type: int
                        description: maximum no. of prefix limit.<1-4294967295.
                      threshold_value:
                        type: int
                        description: hreshold value (%) at which to generate a warning msg <1-100>.
                      restart:
                        type: int
                        description: Restart time interval.
                      warning_only:
                        type: bool
                        description: Only give warning message when limit is exceeded.
                      discard_extra_paths:
                        description: Discard extra paths when limit is exceeded.
                        type: bool
                  multipath:
                    type: bool
                    description: Paths from this neighbor is eligible for multipath.
                  next_hop_self:
                    type: dict
                    description: Disable the next hop calculation for this neighbor.
                    suboptions:
                      set:
                        type: bool
                        description: set next hop self.
                      inheritance_disable:
                        type: bool
                        description: Prevent next_hop_self from being inherited from the parent.
                  next_hop_unchanged:
                    type: dict
                    description: Disable the next hop calculation for this neighbor.
                    suboptions:
                      set:
                        type: bool
                        description: set next hop unchanged.
                      inheritance_disable:
                        type: bool
                        description: Prevent next_hop_unchanged from being inherited from the parent.
                      multipath:
                        type: bool
                        description: Do not overwrite nexthop before advertising multipaths.
                  optimal_route_reflection_group_name:
                    type: str
                    description: Configure optimal-route-reflection group.
                  orf_route_policy: &orf_rp
                    type: str
                    description: Specify ORF and inbound filtering criteria.'
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
                  remove_private_AS:
                    type: dict
                    description: Remove private AS number from outbound updates.
                    suboptions:
                      set:
                        type: bool
                        description: set remove private As.
                      inbound:
                        type: bool
                        description: Remove private AS number from inbound updates.
                      entire_aspath:
                        type: bool
                        description: remove only if all ASes in the path are private.
                      inheritance_disable:
                        type: bool
                        description: Prevent remove-private-AS from being inherited from the parent.
                  route_policy:
                    type: dict
                    description: Apply route policy to neighbor.
                    suboptions:
                      inbound:
                        type: str
                        description: Apply route policy to inbound routes.
                      outbound:
                        type: str
                        description: Apply route policy to outbound routes.
                  route_reflector_client:
                    type: dict
                    description: Configure a neighbor as Route Reflector client.
                    suboptions:
                      set:
                        type: bool
                        description: set route-reflector-client.
                      inheritance_disable:
                        type: bool
                        description: Prevent route-reflector-client from being inherited from the parent.
                  send_community_ebgp:
                    description: Send community attribute to this external neighbor.
                    type: dict
                    suboptions:
                      set:
                        type: bool
                        description: set send_community_ebgp.
                      inheritance_disable:
                        type: bool
                        description: Prevent send_community_ebgp from being inherited from the parent.
                  send_community_gshut_ebgp:
                    description: Allow the g-shut community to be sent to this external neighbor.
                    type: dict
                    suboptions:
                      set:
                        type: bool
                        description: set send_community_gshut_ebgp.
                      inheritance_disable:
                        type: bool
                        description: Prevent send_community_gshut_ebgp from being inherited from the parent.
                  send_extended_community_ebgp:
                    description: Send extended community attribute to this external neighbor.
                    type: dict
                    suboptions:
                      set:
                        type: bool
                        description: set send_extended_community_ebgp.
                      inheritance_disable:
                        type: bool
                        description: Prevent send_extended_community_ebgp from being inherited from the parent.
                  send_multicast_attributes:
                    description: Send multicast attributes to this neighbor .
                    type: dict
                    suboptions:
                      set:
                        type: bool
                        description: set send_multicast_attributes.
                      disable:
                        type: bool
                        description: Disable send multicast attributes.
                  soft_reconfiguration: &soft_reconfiguration
                    description: Per neighbor soft reconfiguration.
                    type: dict
                    suboptions:
                      inbound:
                        type: dict
                        description: inbound soft reconfiguration
                        suboptions:
                          set:
                            type: bool
                            description: set inbound
                          always:
                            type: bool
                            description: Allow inbound soft reconfiguration for this neighbor. Always use soft reconfig, even if route refresh is supported.
                          inheritance_disable:
                            type: bool
                            description: Prevent soft_reconfiguration from being inherited from the parent.
                  weight:
                    type: int
                    description: Set default weight for routes from this neighbor.
                  update:
                    type: dict
                    description: update
                    suboptions:
                      out_originator_loopcheck_disable:
                        type: bool
                        description: Disable originator loop check
                      out_originator_loopcheck_set:
                        type: bool
                        description: Set originator loop check
                  use:
                    description: Inherit configuration for this address-family from an af-group.
                    type: str
              advertisement_interval:
                description: Minimum interval between sending BGP routing updates.Example-<0-600>.
                type: int
              bfd:
                description: Configure BFD parameters.
                type: dict
                suboptions:
                  fast_detect:
                    description: Enable Fast detection
                    type: dict
                    suboptions:
                      set:
                        description: set fast-detect
                        type: bool
                      disable:
                        description: Prevent bfd settings from being inherited from the parent.
                        type: bool
                      strict_mode:
                        description: Hold down neighbor session until BFD session is up
                        type: bool
                  minimum_interval:
                    description: Specifies the BFD session's minimum-interval value for the neighbor.
                    type: int
                  multiplier:
                    description: Specifies the BFD session's multiplier value for the neighbor.
                    type: int
              bmp_activate:
                description: Enable BMP logging for this neighbor.
                type: dict
                suboptions:
                  server:
                    description: Enable BMP connection to particular server.Example-<1-8>.
                    type: int
              capability:
                description: Advertise capability to the peer.
                type: dict
                suboptions:
                  additional_paths:
                    description: BGP additional-paths commands.
                    type: dict
                    suboptions:
                      send:
                        type: dict
                        description: Additional paths Send capability
                        suboptions:
                          set:
                            type: bool
                            description: set send capability
                          disable:
                            type: bool
                            description: set send capability
                      receive:
                        type: dict
                        description: Additional paths receive capability
                        suboptions:
                          set:
                            type: bool
                            description: set receive capability
                          disable:
                            type: bool
                            description: set receive capability
                  suppress:
                    description: Suppress advertising capability to the peer.
                    type: dict
                    suboptions:
                      four_byte_AS:
                        description: 4-byte-as capability
                        type: dict
                        suboptions:
                          set:
                            description: set 4_byte_as.
                            type: bool

                      all:
                        description: all capability
                        type: dict
                        suboptions:
                          inheritance_disable:
                            description: Do not inherit this configuration from parent group.
                            type: bool
                          set:
                            description: set all.
                            type: bool
              cluster_id:
                description: Cluster ID of this router acting as a route reflector.
                type: str
              description:
                description: Neighbor specific description.
                type: str
              dmz_link_bandwidth:
                description: Propagate the DMZ link bandwidth.
                type: dict
                suboptions:
                  inheritance_disable:
                    description: Do not inherit this configuration from parent group.
                    type: bool
                  set:
                    description: set dmz-link-bandwidth.
                    type: bool
              dscp:
                description: Set IP DSCP (DiffServ CodePoint).Please refer vendor document for valid entries.
                type: str
              ebgp_multihop:
                description: Allow EBGP neighbors not on directly connected networks.
                type: dict
                suboptions:
                  value:
                    description: maximum hop count.Example-<1-255>.
                    type: int
                  mpls:
                    description: Disable BGP MPLS forwarding.
                    type: bool
              ebgp_recv_extcommunity_dmz:
                description: Receive extcommunity dmz link bandwidth from ebgp neighbor.
                type: dict
                suboptions:
                  inheritance_disable:
                    description: Prevent ebgp-recv-community-dmz from being inherited from parent
                    type: bool
                  set:
                    description: set ebgp-recv-community-dmz.
                    type: bool
              ebgp_send_extcommunity_dmz:
                description: Send extcommunity dmz link bandwidth from ebgp neighbor.
                type: dict
                suboptions:
                  inheritance_disable:
                    description: Prevent ebgp-send-community-dmz from being inherited from parent
                    type: bool
                  cumulatie:
                    description: Send cumulative community dmz link bandwidth of all multipaths to ebgp neighbor.
                    type: bool
                  set:
                    description: set ebgp-send-community-dmz.
                    type: bool
              egress_engineering:
                type: dict
                description: Enable egress peer engineering for this neighbor.
                suboptions:
                  inheritance_disable:
                    description: Prevent egress-engineering from being inherited from parent
                    type: bool
                  set:
                    description: set egress-engineering.
                    type: bool
              enforce_first_as:
                description: Enforce the first AS for EBGP routes
                type: dict
                suboptions:
                    disable:
                      description: disable enforce 1st as
                      type: bool
              graceful_maintenance:
                description:
                  Attributes for Graceful Maintenance. This will cause neighbors to de-prefer routes from this router and
                  choose alternates. This allows the router to be brought in or out of service gracefully.
                type: dict
                suboptions:
                  set:
                    description: set graceful maintenance.
                    type: bool
                  activate:
                    description: Routes will be announced with the graceful maintenance attributes while activated either here or under router
                      bgp configuration.
                    type: dict
                    suboptions:
                      inheritance_disable:
                        description: Prevent activate from being inherited from the parent.
                        type: bool
                      set:
                        description: activate.
                        type: bool
                  as_prepends:
                    description: Number of times to prepend the local AS number to the
                      AS path of routes. Default=0
                    type: dict
                    suboptions:
                      inheritance_disable:
                        description: Prevent as prepends from being inherited from the parent.
                        type: bool
                      value:
                        description: Range of values for as prepends.Example-<0-6> .
                        type: int
                  local_preference:
                    description: local preference with which to advertise routes to ibgp neigbors. Default=No Touch
                    type: dict
                    suboptions:
                      value:
                        description: Range of values for Local Preference.Example-<0-4294967295> .
                        type: int
                      inheritance_disable:
                        description: Prevent local preference from being inherited from the parent.
                        type: bool
              graceful_restart:
                description: Enable graceful restart support for this neighbor.
                type: dict
                suboptions:
                  restart_time:
                    description: Restart time advertised to neighbors in seconds <1-4095>.
                    type: int
                  stalepath_time:
                    description: Maximum time to wait for restart of GR capable peers in seconds <1-4095>.
                    type: int
              ignore_connected_check:
                description: Bypass the directly connected nexthop check for single-hop eBGP peering
                type: dict
                suboptions:
                  inheritance_disable:
                    description: Prevent ignore-connected-check from being inherited from the parent
                    type: bool
                  set:
                    description: set ignore-connected-check.
                    type: bool
              idle_watch_time:
                type: int
                description: Maximum time to wait for deletion of IDLE state dynamic peer.
              internal_vpn_client:
                type: bool
                description: Preserve iBGP CE neighbor path in ATTR_SET across VPN core.
              keychain:
                description: Set keychain based authentication.
                type: dict
                suboptions:
                  name:
                    description: Name of the key chain - maximum 32 characters.
                    type: str
                  inheritance_disable:
                    description: Prevent keychain from being inherited from parent.
                    type: bool
              local:
                type: dict
                description: Configure local parameter
                suboptions:
                  address:
                    description: IPv4 address
                    type: dict
                    suboptions:
                      ipv4_address:
                        description: IPv4 address <A.B.C.D>.
                        type: str
                      inheritance_disable:
                        description: Prevent local address from being inherited from parent.
                        type: bool
              local_as:
                description: Specify local AS number.
                type: dict
                suboptions:
                  value:
                    description: 2 byte, 4 byte As number
                    type: int
                  no_prepend:
                    description: Do not prepend local AS to announcements from this neighbor.
                    type: dict
                    suboptions:
                      set:
                        type: bool
                        description: Do not prepend local AS to announcements from this neighbor.
                      replace_as:
                        type: dict
                        description: Prepend only local AS to announcements to this neighbor.
                        suboptions:
                          set:
                            type: bool
                            description: Prepend only local AS to announcements to this neighbor.
                          dual_as:
                            type: bool
                            description: Dual-AS mode.
                  inheritance_disable:
                    description: Prevent local AS from being inherited from parent.
                    type: bool
              local_address_subnet:
                type: str
                description: Local address subnet of routing updates
              log:
                description: Logging update messages per neighbor.
                type: dict
                suboptions:
                  log_message:
                    description: Logging update/notification messages per neighbor.
                    type: dict
                    suboptions:
                      in:
                        description: Inbound log messages
                        type: dict
                        suboptions:
                          value:
                            description: Range for message log buffer size <1-100>.
                            type: int
                          disable:
                            description: Disable inbound message logging.
                            type: bool
                          inheritance_disable:
                            description: Prevents the msg log from being inherited from the parent.
                            type: bool
                      out:
                        description: Outbound log messages
                        type: dict
                        suboptions:
                          value:
                            description: Range for message log buffer size <1-100>.
                            type: int
                          disable:
                            description: Disable inbound message logging.
                            type: bool
                          inheritance_disable:
                            description: Prevents the msg log from being inherited from the parent.
                            type: bool
              maximum_peers:
                type: int
                description: Maximum dynamic neighbors <1-4095>.
              password:
                type: dict
                description: Set a password.
                suboptions:
                  encrypted:
                    type: str
                    description: Specifies an ENCRYPTED password will follow.
                  inheritance_disable:
                    description: Prevent password from being inherited from parent.
                    type: bool
              peer_set:
                type: int
                description: Assign this neighbor to a peer-set used for egress peer engineering <1-255>.
              precedence:
                type: str
                choices: ["critical", "flash", "flash-override", "immediate", "internet", "network", "priority","routine"]
                description: Set precedence
              receive_buffer_size:
                description: Set socket and BGP receive buffer size.Example <512-131072>.
                type: int
              remote_as:
                description: Neighbor Autonomous System.
                type: int
              remote_as_list:
                description: Remote as-list configuration
                type: str
              send_buffer_size:
                description: Set socket and BGP send buffer size.Example  <4096-131072>.
                type: int
              session_open_mode:
                description: Establish BGP session using this TCP open mode.
                type: str
                choices: [ 'active-only', 'both', 'passive-only' ]
              shutdown:
                description: Administratively shut down this neighbor.
                type: dict
                suboptions:
                  inheritance_disable:
                    description: Prevent shutdown from being inherited from parent
                    type: bool
                  set:
                    description: shutdown.
                    type: bool
              tcp:
                description: TCP session configuration commands.
                type: dict
                suboptions:
                  mss:
                    description: Maximum Segment Size.
                    type: dict
                    suboptions:
                      value:
                        description: TCP initial maximum segment size.
                        type: int
                      inheritance_disable:
                        description: Prevent mss from being inherited from parent
                        type: bool
              timers:
                description: BGP per neighbor timers.
                type: dict
                suboptions:
                  keepalive_time:
                    description: keepalive interval <0-65535>.
                    type: int
                  holdtime:
                    description: hold time <3-65535> or 0 Disable hold time.
                    type: int
                  min_holdtime:
                    description: Minimum acceptable holdtime from neighbor <3-65535>.
                    type: int
              ttl_security:
                description: Enable EBGP TTL security.
                type: dict
                suboptions:
                  inheritance_disable:
                    description: Prevent ttl-security from being inherited from parent
                    type: bool
                  set:
                    description: set ttl-security
                    type: bool
              update:
                description: BGP Update configuration.
                type: dict
                suboptions:
                  in:
                    description: Inbound update message handling.
                    type: dict
                    suboptions:
                      filtering:
                        description: Inbound update message filtering
                        type: dict
                        suboptions:
                          attribute_filter:
                            description: Attribute-filter configuration.
                            type: dict
                            suboptions:
                              group:
                                description: Name of group.
                                type: str
                          logging:
                            description: Update filtering syslog message.
                            type: dict
                            suboptions:
                              disable:
                                description: Disable update filtering syslog message.
                                type: bool
                          update_message:
                            description: Filtered update messages.
                            type: dict
                            suboptions:
                              buffers:
                                description: Number of buffers to store filtered update messages.
                                type: int
              update_source:
                description: Source of routing updates.Refer vendor document for valid values.
                type: str
              use:
                description: Use a neighbor-group and session-group template.
                type: dict
                suboptions:
                  neighbor_group:
                    description: Inherit configuration from a neighbor-group.
                    type: str
                  session_group:
                    description: Inherit address-family independent config from a session-group
                    type: str
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
# RP/0/RP0/CPU0:10#show running-config router bgp
# Thu Mar 23 10:00:12.668 UTC
# % No such configuration item(s)
#
# RP/0/RP0/CPU0:10#

- name: Merge the provided configuration with the existing running configuration
  cisco.iosxr.iosxr_bgp_templates:
    config:
      as_number: 65536
      neighbor:
        - address_family:
            - advertise:
                local_labeled_route:
                  set: true
              afi: ipv4
              safi: unicast
          advertisement_interval: 10
          bfd:
            fast_detect:
              strict_mode: true
          internal_vpn_client: true
          name: neighbor-group1
          precedence: critical
        - cluster_id: '1'
          description: neighbor-group2
          dmz_link_bandwidth:
            set: true
          ebgp_multihop:
            value: 255
          egress_engineering:
            set: true
          graceful_maintenance:
            as_prepends:
              value: 0
            set: true
          ignore_connected_check:
            set: true
          internal_vpn_client: true
          local:
            address:
              inheritance_disable: true
          local_as:
            value: 6
          name: neighbor-group2
          precedence: flash
          receive_buffer_size: 512
          send_buffer_size: 4096
          session_open_mode: both
          tcp:
            mss:
              inheritance_disable: true
          ttl_security:
            set: true
          update_source: Loopback919
    state: merged

# Task Output
# -----------
# before: {}
# commands:
# - router bgp 65536
# - neighbor-group neighbor-group1
# - advertisement-interval 10
# - bfd fast-detect strict-mode
# - internal-vpn-client
# - precedence critical
# - address-family ipv4 unicast
# - advertise local-labeled-route
# - neighbor-group neighbor-group2
# - dmz-link-bandwidth
# - description neighbor-group2
# - cluster-id 1
# - ebgp-multihop 255
# - egress-engineering
# - internal-vpn-client
# - ignore-connected-check
# - local-as 6
# - local address inheritance-disable
# - precedence flash
# - receive-buffer-size 512
# - send-buffer-size 4096
# - session-open-mode both
# - tcp mss inheritance-disable
# - update-source Loopback919
# - ttl-security
# - graceful-maintenance
# - graceful-maintenance as-prepends 0
# after:
#   as_number: '65536'
#   neighbor:
#     - address_family:
#         - advertise:
#             local_labeled_route:
#               set: true
#           afi: ipv4
#           safi: unicast
#       advertisement_interval: 10
#       bfd:
#         fast_detect:
#           strict_mode: true
#       internal_vpn_client: true
#       name: neighbor-group1
#       precedence: critical
#     - cluster_id: '1'
#       description: neighbor-group2
#       dmz_link_bandwidth:
#         set: true
#       ebgp_multihop:
#         value: 255
#       egress_engineering:
#         set: true
#       graceful_maintenance:
#         as_prepends:
#           value: 0
#         set: true
#       ignore_connected_check:
#         set: true
#       internal_vpn_client: true
#       local:
#         address:
#           inheritance_disable: true
#       local_as:
#         value: 6
#       name: neighbor-group2
#       precedence: flash
#       receive_buffer_size: 512
#       send_buffer_size: 4096
#       session_open_mode: both
#       tcp:
#         mss:
#           inheritance_disable: true
#       ttl_security:
#         set: true
#       update_source: Loopback919

# After state:
# ------------
# RP/0/RP0/CPU0:10#show running-config router bgp
# Thu Mar 23 10:14:33.116 UTC
# router bgp 65536
#  neighbor-group neighbor-group1
#   bfd fast-detect strict-mode
#   precedence critical
#   advertisement-interval 10
#   internal-vpn-client
#   address-family ipv4 unicast
#    advertise local-labeled-route
#   !
#  !
#  neighbor-group neighbor-group2
#   ebgp-multihop 255
#   egress-engineering
#   precedence flash
#   graceful-maintenance
#    as-prepends 0
#   !
#   tcp mss inheritance-disable
#   local-as 6
#   cluster-id 1
#   dmz-link-bandwidth
#   description neighbor-group2
#   ttl-security
#   local address inheritance-disable
#   update-source Loopback919
#   ignore-connected-check
#   session-open-mode both
#   send-buffer-size 4096
#   receive-buffer-size 512
#   internal-vpn-client
#  !
# !


# Using replaced
# Before state:
# ------------
# RP/0/RP0/CPU0:10#show running-config router bgp
# Thu Mar 23 10:14:33.116 UTC
# router bgp 65536
#  neighbor-group neighbor-group1
#   bfd fast-detect strict-mode
#   precedence critical
#   advertisement-interval 10
#   internal-vpn-client
#   address-family ipv4 unicast
#    advertise local-labeled-route
#   !
#  !
#  neighbor-group neighbor-group2
#   ebgp-multihop 255
#   egress-engineering
#   precedence flash
#   graceful-maintenance
#    as-prepends 0
#   !
#   tcp mss inheritance-disable
#   local-as 6
#   cluster-id 1
#   dmz-link-bandwidth
#   description neighbor-group2
#   ttl-security
#   local address inheritance-disable
#   update-source Loopback919
#   ignore-connected-check
#   session-open-mode both
#   send-buffer-size 4096
#   receive-buffer-size 512
#   internal-vpn-client
#  !
# !

- name: Replaced given bgp_templates configuration
  cisco.iosxr.iosxr_bgp_templates:
    config:
      as_number: 65536
      neighbor:
        - address_family:
            - advertise:
                local_labeled_route:
                  set: true
              afi: ipv4
              safi: unicast
          advertisement_interval: 12
          name: neighbor-group1
          precedence: flash
        - cluster_id: '2'
          description: replace neighbor-group2
          ebgp_multihop:
            value: 254
          graceful_maintenance:
            as_prepends:
              value: 2
            set: true
          update_source: Loopback917
          name: neighbor-group2
    state: replaced

# Task Output
# -----------
# before:
#   as_number: '65536'
#   neighbor:
#     - address_family:
#         - advertise:
#             local_labeled_route:
#               set: true
#           afi: ipv4
#           safi: unicast
#       advertisement_interval: 10
#       bfd:
#         fast_detect:
#           strict_mode: true
#       internal_vpn_client: true
#       name: neighbor-group1
#       precedence: critical
#     - cluster_id: '1'
#       description: neighbor-group2
#       dmz_link_bandwidth:
#         set: true
#       ebgp_multihop:
#         value: 255
#       egress_engineering:
#         set: true
#       graceful_maintenance:
#         as_prepends:
#           value: 0
#         set: true
#       ignore_connected_check:
#         set: true
#       internal_vpn_client: true
#       local:
#         address:
#           inheritance_disable: true
#       local_as:
#         value: 6
#       name: neighbor-group2
#       precedence: flash
#       receive_buffer_size: 512
#       send_buffer_size: 4096
#       session_open_mode: both
#       tcp:
#         mss:
#           inheritance_disable: true
#       ttl_security:
#         set: true
#       update_source: Loopback919
# commands:
# - router bgp 65536
# - neighbor-group neighbor-group1
# - no bfd fast-detect strict-mode
# - no internal-vpn-client
# - advertisement-interval 12
# - precedence flash
# - neighbor-group neighbor-group2
# - no dmz-link-bandwidth
# - no egress-engineering
# - no internal-vpn-client
# - no ignore-connected-check
# - no local-as 6
# - no local address inheritance-disable
# - no precedence flash
# - no receive-buffer-size 512
# - no send-buffer-size 4096
# - no session-open-mode both
# - no tcp mss inheritance-disable
# - no ttl-security
# - description replace neighbor-group2
# - cluster-id 2
# - ebgp-multihop 254
# - update-source Loopback917
# - graceful-maintenance as-prepends 2
# after:
#   as_number: '65536'
#   neighbor:
#     - address_family:
#         - advertise:
#             local_labeled_route:
#               set: true
#           afi: ipv4
#           safi: unicast
#       advertisement_interval: 12
#       name: neighbor-group1
#       precedence: flash
#     - cluster_id: '2'
#       description: replace neighbor-group2
#       ebgp_multihop:
#         value: 254
#       graceful_maintenance:
#         as_prepends:
#           value: 2
#         set: true
#       name: neighbor-group2
#       update_source: Loopback917

# After state:
# ------------
# RP/0/RP0/CPU0:10#show running-config router bgp
# Thu Mar 23 10:23:34.104 UTC
# router bgp 65536
#  neighbor-group neighbor-group1
#   precedence flash
#   advertisement-interval 12
#   address-family ipv4 unicast
#    advertise local-labeled-route
#   !
#  !
#  neighbor-group neighbor-group2
#   ebgp-multihop 254
#   graceful-maintenance
#    as-prepends 2
#   !
#   cluster-id 2
#   description replace neighbor-group2
#   update-source Loopback917
#  !
# !


# Using deleted
# Before state:
# -------------
# RP/0/RP0/CPU0:10#show running-config router bgp
# Thu Mar 23 10:23:34.104 UTC
# router bgp 65536
#  neighbor-group neighbor-group1
#   precedence flash
#   advertisement-interval 12
#   address-family ipv4 unicast
#    advertise local-labeled-route
#   !
#  !
#  neighbor-group neighbor-group2
#   ebgp-multihop 254
#   graceful-maintenance
#    as-prepends 2
#   !
#   cluster-id 2
#   description replace neighbor-group2
#   update-source Loopback917
#  !
# !

- name: Delete given bgp_nbr_address_family configuration
  cisco.iosxr.iosxr_bgp_templates: &deleted
    config:
    state: deleted

# Task Output
# -----------
# before:
#   as_number: '65536'
#   neighbor:
#     - address_family:
#         - advertise:
#             local_labeled_route:
#               set: true
#           afi: ipv4
#           safi: unicast
#       advertisement_interval: 12
#       name: neighbor-group1
#       precedence: flash
#     - cluster_id: '2'
#       description: replace neighbor-group2
#       ebgp_multihop:
#         value: 254
#       graceful_maintenance:
#         as_prepends:
#           value: 2
#         set: true
#       name: neighbor-group2
#       update_source: Loopback917
# commands:
# - router bgp 65536
# - no neighbor-group neighbor-group1
# - no neighbor-group neighbor-group2
# after: {}

# After state:
# -------------
# RP/0/RP0/CPU0:10#show running-config router bgp
# Thu Mar 23 10:00:12.668 UTC
# % No such configuration item(s)
#
# RP/0/RP0/CPU0:10#

# Using gathered
# Before state:
# -------------
# RP/0/RP0/CPU0:10#show running-config router bgp
# Thu Mar 23 10:30:38.785 UTC
# router bgp 65536
#  neighbor-group neighbor-group1
#   bfd fast-detect strict-mode
#   precedence critical
#   advertisement-interval 10
#   internal-vpn-client
#   address-family ipv4 unicast
#    advertise local-labeled-route
#   !
#  !
#  neighbor-group neighbor-group2
#   ebgp-multihop 255
#   egress-engineering
#   precedence flash
#   graceful-maintenance
#    as-prepends 0
#   !
#   tcp mss inheritance-disable
#   local-as 6
#   cluster-id 1
#   dmz-link-bandwidth
#   description neighbor-group2
#   ttl-security
#   local address inheritance-disable
#   update-source Loopback919
#   ignore-connected-check
#   session-open-mode both
#   send-buffer-size 4096
#   receive-buffer-size 512
#   internal-vpn-client
#  !
# !

- name: Gather given bgp_templates configuration
  cisco.iosxr.iosxr_bgp_templates: &id001
    config:
    state: gathered

# Task output
# -----------
# gathered:
#   as_number: '65536'
#   neighbor:
#     - address_family:
#         - advertise:
#             local_labeled_route:
#               set: true
#           afi: ipv4
#           safi: unicast
#       advertisement_interval: 10
#       bfd:
#         fast_detect:
#           strict_mode: true
#       internal_vpn_client: true
#       name: neighbor-group1
#       precedence: critical
#     - cluster_id: '1'
#       description: neighbor-group2
#       dmz_link_bandwidth:
#         set: true
#       ebgp_multihop:
#         value: 255
#       egress_engineering:
#         set: true
#       graceful_maintenance:
#         as_prepends:
#           value: 0
#         set: true
#       ignore_connected_check:
#         set: true
#       internal_vpn_client: true
#       local:
#         address:
#           inheritance_disable: true
#       local_as:
#         value: 6
#       name: neighbor-group2
#       precedence: flash
#       receive_buffer_size: 512
#       send_buffer_size: 4096
#       session_open_mode: both
#       tcp:
#         mss:
#           inheritance_disable: true
#       ttl_security:
#         set: true
#       update_source: Loopback919


# Using overridden

# Before state:
# -------------
# RP/0/RP0/CPU0:10#show running-config router bgp
# Thu Mar 23 10:30:38.785 UTC
# router bgp 65536
#  neighbor-group neighbor-group1
#   bfd fast-detect strict-mode
#   precedence critical
#   advertisement-interval 10
#   internal-vpn-client
#   address-family ipv4 unicast
#    advertise local-labeled-route
#   !
#  !
#  neighbor-group neighbor-group2
#   ebgp-multihop 255
#   egress-engineering
#   precedence flash
#   graceful-maintenance
#    as-prepends 0
#   !
#   tcp mss inheritance-disable
#   local-as 6
#   cluster-id 1
#   dmz-link-bandwidth
#   description neighbor-group2
#   ttl-security
#   local address inheritance-disable
#   update-source Loopback919
#   ignore-connected-check
#   session-open-mode both
#   send-buffer-size 4096
#   receive-buffer-size 512
#   internal-vpn-client
#  !
# !
- name: override given bgp_templates configuration
  cisco.iosxr.iosxr_bgp_templates:
    config:
      as_number: 65536
      neighbor:
        - address_family:
            - advertise:
                local_labeled_route:
                  disable: true
              afi: ipv4
              safi: unicast
          advertisement_interval: 12
          bfd:
            fast_detect:
              strict_mode: true
          name: neighbor-group1
          precedence: flash
    state: overridden

# Task Output
# -----------
# before:
#   as_number: '65536'
#   neighbor:
#     - address_family:
#         - advertise:
#             local_labeled_route:
#               set: true
#           afi: ipv4
#           safi: unicast
#       advertisement_interval: 10
#       bfd:
#         fast_detect:
#           strict_mode: true
#       internal_vpn_client: true
#       name: neighbor-group1
#       precedence: critical
#     - cluster_id: '1'
#       description: neighbor-group2
#       dmz_link_bandwidth:
#         set: true
#       ebgp_multihop:
#         value: 255
#       egress_engineering:
#         set: true
#       graceful_maintenance:
#         as_prepends:
#           value: 0
#         set: true
#       ignore_connected_check:
#         set: true
#       internal_vpn_client: true
#       local:
#         address:
#           inheritance_disable: true
#       local_as:
#         value: 6
#       name: neighbor-group2
#       precedence: flash
#       receive_buffer_size: 512
#       send_buffer_size: 4096
#       session_open_mode: both
#       tcp:
#         mss:
#           inheritance_disable: true
#       ttl_security:
#         set: true
#       update_source: Loopback919
# commands:
# - router bgp 65536
# - no neighbor-group neighbor-group2
# - neighbor-group neighbor-group1
# - no internal-vpn-client
# - advertisement-interval 12
# - precedence flash
# - address-family ipv4 unicast
# - no advertise local-labeled-route
# - advertise local-labeled-route disable
# after:
#   as_number: '65536'
#   neighbor:
#     - address_family:
#         - advertise:
#             local_labeled_route:
#               disable: true
#           afi: ipv4
#           safi: unicast
#       advertisement_interval: 12
#       bfd:
#         fast_detect:
#           strict_mode: true
#       name: neighbor-group1
#       precedence: flash


# Using rendered
- name: >-
    Render platform specific configuration lines with state rendered (without
    connecting to the device)
  cisco.iosxr.iosxr_bgp_templates:
    config:
      as_number: 65536
      neighbor:
        - address_family:
            - advertise:
                local_labeled_route:
                  set: true
              afi: ipv4
              safi: unicast
          advertisement_interval: 10
          bfd:
            fast_detect:
              strict_mode: true
          internal_vpn_client: true
          name: neighbor-group1
          precedence: critical
        - cluster_id: '1'
          description: neighbor-group2
          dmz_link_bandwidth:
            set: true
          ebgp_multihop:
            value: 255
          egress_engineering:
            set: true
          graceful_maintenance:
            as_prepends:
              value: 0
            set: true
          ignore_connected_check:
            set: true
          internal_vpn_client: true
          local:
            address:
              inheritance_disable: true
          local_as:
            value: 6
          name: neighbor-group2
          precedence: flash
          receive_buffer_size: 512
          send_buffer_size: 4096
          session_open_mode: both
          tcp:
            mss:
              inheritance_disable: true
          ttl_security:
            set: true
          update_source: Loopback919
    state: rendered

# Task Output
# -----------
# rendered:
# - router bgp 65536
# - neighbor-group neighbor-group1
# - advertisement-interval 10
# - bfd fast-detect strict-mode
# - internal-vpn-client
# - precedence critical
# - address-family ipv4 unicast
# - advertise local-labeled-route
# - neighbor-group neighbor-group2
# - dmz-link-bandwidth
# - description neighbor-group2
# - cluster-id 1
# - ebgp-multihop 255
# - egress-engineering
# - internal-vpn-client
# - ignore-connected-check
# - local-as 6
# - local address inheritance-disable
# - precedence flash
# - receive-buffer-size 512
# - send-buffer-size 4096
# - session-open-mode both
# - tcp mss inheritance-disable
# - update-source Loopback919
# - ttl-security
# - graceful-maintenance
# - graceful-maintenance as-prepends 0


# Using parsed
- name: Parse externally provided BGP configuration
  register: result
  cisco.iosxr.iosxr_bgp_templates:
    running_config: "{{ lookup('file', 'parsed.cfg') }}"
    state: parsed

# content of pared.cfg
# router bgp 65536
#  neighbor-group neighbor-group1
#   bfd fast-detect strict-mode
#   precedence critical
#   advertisement-interval 10
#   internal-vpn-client
#   address-family ipv4 unicast
#    advertise local-labeled-route
#   !
#  !
#  neighbor-group neighbor-group2
#   ebgp-multihop 255
#   egress-engineering
#   precedence flash
#   graceful-maintenance
#    as-prepends 0
#   !
#   tcp mss inheritance-disable
#   local-as 6
#   cluster-id 1
#   dmz-link-bandwidth
#   description neighbor-group2
#   ttl-security
#   local address inheritance-disable
#   update-source Loopback919
#   idle-watch-time 30
#   ignore-connected-check
#   session-open-mode both
#   send-buffer-size 4096
#   receive-buffer-size 512
#   internal-vpn-client
#  !
# !
# Task output
# -----------
# parsed:
#   as_number: '65536'
#   neighbor:
#     - address_family:
#         - advertise:
#             local_labeled_route:
#               set: true
#           afi: ipv4
#           safi: unicast
#       advertisement_interval: 10
#       bfd:
#         fast_detect:
#           strict_mode: true
#       internal_vpn_client: true
#       name: neighbor-group1
#       precedence: critical
#     - cluster_id: '1'
#       description: neighbor-group2
#       dmz_link_bandwidth:
#         set: true
#       ebgp_multihop:
#         value: 255
#       egress_engineering:
#         set: true
#       graceful_maintenance:
#         as_prepends:
#           value: 0
#         set: true
#       ignore_connected_check:
#         set: true
#       internal_vpn_client: true
#       local:
#         address:
#           inheritance_disable: true
#       local_as:
#         value: 6
#       name: neighbor-group2
#       precedence: flash
#       receive_buffer_size: 512
#       send_buffer_size: 4096
#       session_open_mode: both
#       tcp:
#         mss:
#           inheritance_disable: true
#       ttl_security:
#         set: true
#       update_source: Loopback919
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
    - neighbor-group neighbor-group1
    - advertisement-interval 10
    - bfd fast-detect strict-mode
    - internal-vpn-client
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
   - router bgp 65536
   - neighbor-group neighbor-group1
   - advertisement-interval 10
   - bfd fast-detect strict-mode
   - internal-vpn-client
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

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.bgp_templates.bgp_templates import (
    Bgp_templatesArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.config.bgp_templates.bgp_templates import (
    Bgp_templates,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=Bgp_templatesArgs.argument_spec,
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

    result = Bgp_templates(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
