#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for iosxr_bgp_global
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: iosxr_bgp_global
short_description: Resource module to configure BGP.
description:
- This module configures and manages the attributes of BGP global on Cisco IOS-XR platforms.
version_added: 2.0.0
author: Ashwini Mhatre (@amhatre)
notes:
- This module works with connection C(network_cli).
options:
    config:
      description: A list of configurations for BGP global.
      type: dict
      suboptions:
        as_number:
          description: Autonomous system number of the router.
          type: str
        bfd: &bfd
          description: Configure BFD parameters.
          type: dict
          suboptions:
            minimum_interval: &min_interval
              description: Specifies the BFD session's minimum-interval value for the neighbor.
              type: int
            multiplier: &multiplier
              description: Specifies the BFD session's multiplier value for the neighbor.
              type: int
        bgp: &bgp
          description: BGP parameters.
          type: dict
          suboptions:
            as_path_loopcheck:
              description: Enable AS-path loop checking for iBGP peers.
              type: bool
            auto_policy_soft_reset: &auto_policy_soft_reset
              description: Enable automatic soft peer reset on policy reconfiguration.
              type: dict
              suboptions:
                disable:
                  description: Disable an automatic soft reset of Border Gateway Protocol (BGP) peers.
                  type: bool
            bestpath: &bestpath
              description: Select the bestpath selection algorithim for BGP routes.
              type: dict
              suboptions:
                as_path:
                  description: Select the bestpath selection based on as-path.
                  type: dict
                  suboptions:
                    ignore:
                      description: ignore
                      type: bool
                    multipath_relax:
                      description: multipath-relax
                      type: bool
                aigp:
                  description: AIGP attribute
                  type: dict
                  suboptions:
                    ignore:
                      description: Ignore AIGP attribute.
                      type: bool
                med:
                  description: MED attribute
                  type: dict
                  suboptions:
                    always:
                      description: Allow comparing MED from different neighbors.
                      type: bool
                    confed:
                      description: Compare MED among confederation paths.
                      type: bool
                    missing_as_worst:
                      description: Treat missing MED as the least preferred one.
                      type: bool
                compare_routerid:
                  description: Compare router-id for identical EBGP paths.
                  type: bool
                cost_community:
                  description: Cost community.
                  type: dict
                  suboptions:
                    ignore:
                      description: ignore cost_community
                      type: bool
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
            cluster_id: &cluster_id
              description: Cluster ID of this router acting as a route reflector.
              type: str
            confederation: &confederation
              description: confederation.
              type: dict
              suboptions:
                identifier:
                  description: Set routing domain confederation AS.
                  type: int
                peers:
                  description: Enter peer ASs in BGP confederation mode.
                  type: list
                  elements: int
            default: &default
              description: Configure default value.
              type: dict
              suboptions:
                local_preference:
                  description:
                    - local preferance.
                    - Please refer vendor documentation for valid values
                  type: int
            enforce_first_as: &enforce_first_as
              description: Enforce the first AS for EBGP routes
              type: dict
              suboptions:
                disable:
                  description: disable enforce 1st as
                  type: bool
            fast_external_fallover: &fast_external_fallover
              description: Immediately reset session if a link to a directly connected external peer goes down.
              type: dict
              suboptions:
                disable:
                  description: disable fast external fallover.
                  type: bool
            graceful_restart:
              description: Enable graceful restart support.
              type: dict
              suboptions:
                set:
                  description: Enable graceful-restart.
                  type: bool
                graceful_reset:
                  description: Reset gracefully if configuration change forces a peer reset.
                  type: bool
                restart_time: &restart_time
                  description: Restart time advertised to neighbors in seconds <1-4095>.
                  type: int
                purge_time:
                  description: Time before stale routes are purged in seconds <1-6000>.
                  type: int
                stalepath_time: &stalepath_time
                  description: Maximum time to wait for restart of GR capable peers in seconds <1-4095>.
                  type: int
            install:
              description: Install diversion path to RIB/CEF.
              type: dict
              suboptions:
                diversion:
                  description: Install diversion path to RIB/CEF.
                  type: bool
            log: &bgp_log
              description: Log bgp info
              type: dict
              suboptions:
                log_message:
                  description: Log neighbor inbound/outbound message.
                  type: dict
                  suboptions:
                    disable:
                      description: disable inbound outbound messages.
                      type: bool
                neighbor:
                  description: Log neighbor state info.
                  type: dict
                  suboptions:
                    changes:
                      description: Log neighbor up/down and reset reason.
                      type: dict
                      suboptions:
                        detail:
                          type: bool
                          description: detail
                        disable:
                          type: bool
                          description: disable
            maximum:
              description: Maximum number of neighbors that can be configured
              type: dict
              suboptions:
                neighbor:
                  description: Maximum number of neighbors <1-15000>.
                  type: int
            multipath: &multipath
              description: Change multipath selection criteria
              type: dict
              suboptions:
                as_path:
                  description: AS path
                  type: dict
                  suboptions:
                    ignore:
                      description: Ignore as-path related check for multipath selection.
                      type: dict
                      suboptions:
                        onwards:
                          description: Ignore everything onwards as-path for multipath selection.
                          type: bool
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
                    time:
                      description: Time to wait between an RPKI update and a BGP table walk.
                      type: dict
                      suboptions:
                        time_off:
                          description: No automatic prefix validation after an RPKI update.
                          type: bool
                        time_in_second:
                          description: Prefix validation time (in seconds).
                          type: int
            redistribute_internal: &redistribute_internal
              description: Redistribute internal BGP routes.
              type: bool
            router_id: &router_id
              description: Configure Router-id. Example- A.B.C.D  IPv4 address.
              type: str
            scan_time:
              description: Configure background scanner interval for generic scanner Example- <5-3600>.
              type: int
            unsafe_ebgp_policy: &ebgp_policy
              description: Make eBGP neighbors with no policy pass all routes(cisco-support).
              type: bool
            update_delay:
              description: Set the max initial delay for sending updates Example-<0-3600> in secs.
              type: int
        default_information: &default_info
          description: Control distribution of default information.
          type: dict
          suboptions:
            originate:
              description: Distribute a default route
              type: bool
        default_metric: &default_metric
          description: Default metric. Example-<1-4294967295>.
          type: int
        graceful_maintenance:
          description: This allows the router to be brought in or out of service gracefully.
          type: dict
          suboptions:
            activate:
              description: All neighbors with graceful-maintenance config
              type: str
              choices: [ 'all-neighbors','retain-routes','all-neighbors retain-routes', '' ]
        ibgp:
          description: Set options for iBGP peers.
          type: dict
          suboptions:
            policy:
              description: Set options for route-policy.
              type: dict
              suboptions:
                out:
                  description: Set options for outbound policy.
                  type: dict
                  suboptions:
                    enforce_modifications:
                      description: Allow policy to modify all attributes.
                      type: bool
        mpls: &mpls
          description: Enable mpls parameters.
          type: dict
          suboptions:
            activate:
              description: Enter mpls interfaces in BGP mpls activate mode.
              type: dict
              suboptions:
                interface:
                  description: Name of interface to enable mpls.
                  type: str
        mvpn:
          description: Connect to PIM/PIM6.
          type: bool
        neighbors: &neighbors
          description: Specify a neighbor router.
          type: list
          elements: dict
          suboptions:
            neighbor_address:
              description:
                - Neighbor router address.
              type: str
              aliases:
                - neighbor
              required: true
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
                multiplier: *multiplier
                minimum_interval: *min_interval
            bmp_activate: &bmp_activate
              description: Enable BMP logging for this neighbor.
              type: dict
              suboptions:
                server:
                  description: Enable BMP connection to particular server.Example-<1-8>.
                  type: int
            capability: &capability
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
            cluster_id: *cluster_id
            description:
              description: Neighbor specific description.
              type: str
            dmz_link_bandwidth: &dmz_link_bw
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
            enforce_first_as: *enforce_first_as
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
                restart_time: *restart_time
                stalepath_time: *stalepath_time
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
                inheritance_disable:
                  description: Prevent local AS from being inherited from parent.
                  type: bool
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
            receive_buffer_size:
              description: Set socket and BGP receive buffer size.Example <512-131072>.
              type: int
            remote_as:
              description: Neighbor Autonomous System.
              type: int
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
            timers: &timers
              description: BGP per neighbor timers.
              type: dict
              suboptions:
                keepalive_time:
                  description: keepalive interval <0-65535>.
                  type: int
                holdtime:
                  description: hold time <3-65535> or 0 Disable hold time.
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
        nsr:
          description: Enable non-stop-routing support for all neighbors.
          type: dict
          suboptions:
            set:
              type: bool
              description: set nsr
            disable:
              type: bool
              description: disable nsr
        socket: &socket
          description: set socket parameters.
          type: dict
          suboptions:
            receive_buffer_size:
              description: socket receive buffer size.Example-<512-131072>.
              type: int
            send_buffer_size:
              description: socket send buffer size.Example- <4096-131072>.
              type: int
        timers: *timers
        update:
          description: BGP Update configuration.
          type: dict
          suboptions:
            in:
              description: Inbound update message handling
              type: dict
              suboptions:
                error_handling:
                  description: Inbound update message error handling.
                  type: dict
                  suboptions:
                    basic:
                      description: Inbound update message basic error handling
                      type: dict
                      suboptions:
                        ebgp:
                          type: dict
                          description: Inbound update message basic error handling for EBGP neighbors
                          suboptions:
                            disable:
                              description: disable
                              type: bool
                        ibgp:
                          type: dict
                          description: Inbound update message basic error handling for ibgp neighbors
                          suboptions:
                            disable:
                              description: disable
                              type: bool
                    extended:
                      description: Inbound update message extended error handling
                      type: dict
                      suboptions:
                        ebgp:
                          type: bool
                          description: Inbound update message extended error handling for EBGP neighbors

                        ibgp:
                          type: bool
                          description: Inbound update message extended error handling for ibgp neighbors
            out:
              description: BGP Update generation configuration.
              type: dict
              suboptions:
                logging:
                  description: Enable logging of update generation events.
                  type: bool
            limit:
              description: Upper bound on transient memory usage for update generation.Example-<16-2048>.
              type: int
        rpki:
          description: Configure RPKI.
          type: dict
          suboptions:
            route:
              description: Configure an RPKI route.A.B.C.D/length or X:X::X/length  Network/Minimum prefix length
              type: dict
              suboptions:
                value:
                  description: A.B.C.D/length or X:X::X/length  Network/Minimum prefix length.
                  type: str
                max:
                  description: Maximum prefix length. Example- <1-128>  .
                  type: int
                origin:
                  description: Origin Autonomous System number (in asplain format) Example-<1-4294967295>.
                  type: int
            servers:
              description: Configure RPKI cache-servers.
              type: list
              elements: dict
              suboptions:
                name:
                  description: address of rpki server.
                  type: str
                purge_time:
                  type: int
                  description: Time to wait after a cache goes down to clean up stale routes
                refresh_time:
                  type: dict
                  description: Time between sending serial-queries for the RPKI cache-server
                  suboptions:
                    value:
                      description: Purge time (in seconds) <30-360>
                      type: int
                    time_off:
                      description: Do not send serial-queries periodically
                      type: bool
                response_time:
                  type: dict
                  description: Time to wait for a response from the RPKI cache-server
                  suboptions:
                    value:
                      description: Purge time (in seconds) <15-3600>
                      type: int
                    time_off:
                      description: Wait indefinitely for a response
                      type: bool
                shutdown:
                  type: bool
                  description: Shutdown the RPKI cache-server
                transport:
                  type: dict
                  description: Specify a transport method for the RPKI cache-server
                  suboptions:
                    ssh:
                      description: Connect to the RPKI cache-server using SSH
                      type: dict
                      suboptions:
                        port:
                          description: Specify a port number for the RPKI cache-server transport
                          type: int
                    tcp:
                      description: Connect to the RPKI cache-server using TCP (unencrypted)
                      type: dict
                      suboptions:
                        port:
                          description: Specify a port number for the RPKI cache-server transport
                          type: int
        vrfs:
          description: Specify a vrf name.
          type: list
          elements: dict
          suboptions:
            vrf:
              description: VRF name.
              type: str
            bfd: *bfd
            bgp:
              description: BGP commands.
              type: dict
              suboptions:
                auto_policy_soft_reset: *auto_policy_soft_reset
                bestpath: *bestpath
                default: *default
                enforce_first_as: *enforce_first_as
                fast_external_fallover: *fast_external_fallover
                log: *bgp_log
                multipath: *multipath
                redistribute_internal: *redistribute_internal
                router_id: *router_id
                unsafe_ebgp_policy: *ebgp_policy
            default_information: *default_info
            default_metric: *default_metric
            mpls: *mpls
            neighbors: *neighbors
            rd:
              description: route distinguisher.
              type: dict
              suboptions:
                auto:
                  description: Automatic route distinguisher.
                  type: bool
            socket: *socket
            timers: *timers
    running_config:
      description:
        The state the configuration should be left in.
        - State I(purged) removes all the BGP configurations from the
        target device. Use caution with this state.
        - State I(deleted) only removes BGP attributes that this modules
        manages and does not negate the BGP process completely. Thereby, preserving
        address-family related configurations under BGP context.
        - Running states I(deleted) and I(replaced) will result in an error if there
        are address-family configuration lines present under a neighbor,
        or a vrf context that is to be removed. Please use the
        M(cisco.iosxr.iosxr_bgp_address_family) or M(cisco.iosxr.iosxr_bgp_neighbor_address_family)
        modules for prior cleanup.
        - Refer to examples for more details.
      type: str
    state:
      description:
      - The state the configuration should be left in.
      type: str
      choices: [deleted, merged, replaced, gathered, rendered, parsed, purged, overridden]
      default: merged
"""
EXAMPLES = """

# Using merged
#
# Before state
# ------------
# RP/0/0/CPU0:10#show running-config router bgp
# Thu Feb  4 09:38:36.245 UTC
# % No such configuration item(s)
# RP/0/0/CPU0:10#

- name: Merge the following BGP global configuration
  cisco.iosxr.iosxr_bgp_global:
    config:
      as_number: 65536
      default_metric: 5
      socket:
        receive_buffer_size: 514
        send_buffer_size: 4098
      bgp:
        confederation:
          identifier: 4
        bestpath:
          med:
            confed: true
        cluster_id: 5
        router_id: 192.0.2.10
      neighbors:
        - neighbor: 192.0.2.13
          remote_as: 65538
          bfd:
            fast_detect:
              strict_mode: true
            multiplier: 6
            minimum_interval: 20
      vrfs:
        - vrf: vrf1
          default_metric: 5

#
# Task Output:
# ---------------
#
# before: {}
# commands:
#   - router bgp 65536
#   - bgp cluster-id 5
#   - bgp router-id 192.0.2.10
#   - bgp bestpath med confed
#   - bgp confederation identifier 4
#   - default-metric 5
#   - socket receive-buffer-size 514
#   - socket send-buffer-size 4098
#   - neighbor 192.0.2.13
#   - bfd fast-detect strict-mode
#   - bfd minimum-interval 20
#   - bfd multiplier 6
#   - remote-as 65538
#   - vrf vrf1
#   - default-metric 5
#
# after:
#     as_number: '65536'
#     bgp:
#       bestpath:
#         med:
#           confed: true
#       cluster_id: '5'
#       confederation:
#         identifier: 4
#       router_id: 192.0.2.10
#     default_metric: 5
#     neighbors:
#     - bfd:
#         fast_detect:
#           strict_mode: true
#         minimum_interval: 20
#         multiplier: 6
#       neighbor_address: 192.0.2.13
#       remote_as: 65538
#     socket:
#       receive_buffer_size: 514
#       send_buffer_size: 4098
#     vrfs:
#     - default_metric: 5
#       vrf: vrf1
#
# After state
# -----------

# RP/0/0/CPU0:10#show running-config router bgp
# Thu Feb  4 09:44:32.480 UTC
# router bgp 65536
#  bgp confederation identifier 4
#  bgp router-id 192.0.2.10
#  bgp cluster-id 5
#  default-metric 5
#  socket send-buffer-size 4098
#  bgp bestpath med confed
#  socket receive-buffer-size 514
#  neighbor 192.0.2.13
#   remote-as 65538
#   bfd fast-detect strict-mode
#   bfd multiplier 6
#   bfd minimum-interval 20
#  !
#  vrf vrf1
#   default-metric 5
#  !
# !

# Using replaced
#
# Before state
# ------------
#
# RP/0/0/CPU0:10#show running-config router bgp
# Thu Feb  4 09:44:32.480 UTC
# router bgp 65536
#  bgp confederation identifier 4
#  bgp router-id 192.0.2.10
#  bgp cluster-id 5
#  default-metric 5
#  socket send-buffer-size 4098
#  bgp bestpath med confed
#  socket receive-buffer-size 514
#  neighbor 192.0.2.13
#   remote-as 65538
#   bfd fast-detect strict-mode
#   bfd multiplier 6
#   bfd minimum-interval 20
#  !
#  vrf vrf1
#   default-metric 5
#  !
# !

- name: Replace the following configuration
  cisco.iosxr.iosxr_bgp_global:
    state: replaced
    config:
      as_number: 65536
      default_metric: 4
      socket:
        receive_buffer_size: 514
        send_buffer_size: 4098
      bgp:
        confederation:
          identifier: 4
        bestpath:
          med:
            confed: true
        cluster_id: 5
        router_id: 192.0.2.10
      neighbors:
        - neighbor: 192.0.2.14
          remote_as: 65538
          bfd:
            fast_detect:
              strict_mode: true
            multiplier: 6
            minimum_interval: 20
      vrfs:
        - vrf: vrf1
          default_metric: 5

#
# Task Output:
# -------------
#
# before:
#     as_number: '65536'
#     bgp:
#       bestpath:
#         med:
#           confed: true
#       cluster_id: '5'
#       confederation:
#         identifier: 4
#       router_id: 192.0.2.10
#     default_metric: 5
#     neighbors:
#     - bfd:
#         fast_detect:
#           strict_mode: true
#         minimum_interval: 20
#         multiplier: 6
#       neighbor_address: 192.0.2.13
#       remote_as: 65538
#     socket:
#       receive_buffer_size: 514
#       send_buffer_size: 4098
#     vrfs:
#     - default_metric: 5
#       vrf: vrf1
#
# commands:
#   - router bgp 65536
#   - default-metric 4
#   - neighbor 192.0.2.14
#   - bfd fast-detect strict-mode
#   - bfd minimum-interval 20
#   - bfd multiplier 6
#   - remote-as 65538
#   - no neighbor 192.0.2.13
#
# after:
#     as_number: '65536'
#     bgp:
#       bestpath:
#         med:
#           confed: true
#       cluster_id: '5'
#       confederation:
#         identifier: 4
#       router_id: 192.0.2.10
#     default_metric: 4
#     neighbors:
#     - bfd:
#         fast_detect:
#           strict_mode: true
#         minimum_interval: 20
#         multiplier: 6
#       neighbor_address: 192.0.2.14
#       remote_as: 65538
#     socket:
#       receive_buffer_size: 514
#       send_buffer_size: 4098
#     vrfs:
#     - default_metric: 5
#       vrf: vrf1
#
# After state
# -----------
#
# RP/0/0/CPU0:10#show running-config router bgp
# Thu Feb  4 09:54:11.161 UTC
# router bgp 65536
#  bgp confederation identifier 4
#  bgp router-id 192.0.2.10
#  bgp cluster-id 5
#  default-metric 4
#  socket send-buffer-size 4098
#  bgp bestpath med confed
#  socket receive-buffer-size 514
#  neighbor 192.0.2.14
#   remote-as 65538
#   bfd fast-detect strict-mode
#   bfd multiplier 6
#   bfd minimum-interval 20
#  !
#  vrf vrf1
#   default-metric 5
#  !
# !

# Using overridden
#
# Before state
# ------------
#
# RP/0/0/CPU0:10#show running-config router bgp
# Thu Feb  4 09:44:32.480 UTC
# router bgp 65536
#  bgp confederation identifier 4
#  bgp router-id 192.0.2.10
#  bgp cluster-id 5
#  default-metric 5
#  socket send-buffer-size 4098
#  bgp bestpath med confed
#  socket receive-buffer-size 514
#  neighbor 192.0.2.13
#   remote-as 65538
#   bfd fast-detect strict-mode
#   bfd multiplier 6
#   bfd minimum-interval 20
#  !
#  vrf vrf1
#   default-metric 5
#  !
# !

- name: Override running config with provided configuration
  cisco.iosxr.iosxr_bgp_global:
    state: overridden
    config:
      as_number: 65536
      default_metric: 4
      socket:
        receive_buffer_size: 514
        send_buffer_size: 4098
      bgp:
        confederation:
          identifier: 4
        bestpath:
          med:
            confed: true
        cluster_id: 5
        router_id: 192.0.2.10
      neighbors:
        - neighbor: 192.0.2.14
          remote_as: 65538
          bfd:
            fast_detect:
              strict_mode: true
            multiplier: 6
            minimum_interval: 20
      vrfs:
        - vrf: vrf1
          default_metric: 5
#
# Task Output:
# -------------
#
# before:
#     as_number: '65536'
#     bgp:
#       bestpath:
#         med:
#           confed: true
#       cluster_id: '5'
#       confederation:
#         identifier: 4
#       router_id: 192.0.2.10
#     default_metric: 5
#     neighbors:
#     - bfd:
#         fast_detect:
#           strict_mode: true
#         minimum_interval: 20
#         multiplier: 6
#       neighbor_address: 192.0.2.13
#       remote_as: 65538
#     socket:
#       receive_buffer_size: 514
#       send_buffer_size: 4098
#     vrfs:
#     - default_metric: 5
#       vrf: vrf1
#
# commands:
#   - router bgp 65536
#   - default-metric 4
#   - neighbor 192.0.2.14
#   - bfd fast-detect strict-mode
#   - bfd minimum-interval 20
#   - bfd multiplier 6
#   - remote-as 65538
#   - no neighbor 192.0.2.13
#
# after:
#     as_number: '65536'
#     bgp:
#       bestpath:
#         med:
#           confed: true
#       cluster_id: '5'
#       confederation:
#         identifier: 4
#       router_id: 192.0.2.10
#     default_metric: 4
#     neighbors:
#     - bfd:
#         fast_detect:
#           strict_mode: true
#         minimum_interval: 20
#         multiplier: 6
#       neighbor_address: 192.0.2.14
#       remote_as: 65538
#     socket:
#       receive_buffer_size: 514
#       send_buffer_size: 4098
#     vrfs:
#     - default_metric: 5
#       vrf: vrf1

# After state
# -----------
#
# RP/0/0/CPU0:10#show running-config router bgp
# Thu Feb  4 09:54:11.161 UTC
# router bgp 65536
#  bgp confederation identifier 4
#  bgp router-id 192.0.2.10
#  bgp cluster-id 5
#  default-metric 4
#  socket send-buffer-size 4098
#  bgp bestpath med confed
#  socket receive-buffer-size 514
#  neighbor 192.0.2.14
#   remote-as 65538
#   bfd fast-detect strict-mode
#   bfd multiplier 6
#   bfd minimum-interval 20
#  !
#  vrf vrf1
#   default-metric 5
#  !
# !

# Using deleted
#
# Before state
# ------------
#
# RP/0/0/CPU0:10#show running-config router bgp
# Thu Feb  4 09:54:11.161 UTC
# router bgp 65536
#  bgp confederation identifier 4
#  bgp router-id 192.0.2.10
#  bgp cluster-id 5
#  default-metric 4
#  socket send-buffer-size 4098
#  bgp bestpath med confed
#  socket receive-buffer-size 514
#  neighbor 192.0.2.14
#   remote-as 65538
#   bfd fast-detect strict-mode
#   bfd multiplier 6
#   bfd minimum-interval 20
#  !
#  vrf vrf1
#   default-metric 5
#  !
# !
#

- name: Delete BGP configurations handled by this module
  cisco.iosxr.iosxr_bgp_global:
    config:
      as_number: 65536
    state: deleted

#
# Task Output:
# -------------
#
# before:
#     as_number: '65536'
#     bgp:
#       bestpath:
#         med:
#           confed: true
#       cluster_id: '5'
#       confederation:
#         identifier: 4
#       router_id: 192.0.2.10
#     default_metric: 4
#     neighbors:
#     - bfd:
#         fast_detect:
#           strict_mode: true
#         minimum_interval: 20
#         multiplier: 6
#       neighbor_address: 192.0.2.14
#       remote_as: 65538
#     socket:
#       receive_buffer_size: 514
#       send_buffer_size: 4098
#     vrfs:
#     - default_metric: 5
#       vrf: vrf1
#
# commands:
#   - router bgp 65536
#   - no bgp cluster-id 5
#   - no bgp router-id 192.0.2.10
#   - no bgp bestpath med confed
#   - no bgp confederation identifier 4
#   - no default-metric 4
#   - no socket receive-buffer-size 514
#   - no socket send-buffer-size 4098
#   - no neighbor 192.0.2.14
#   - no vrf vrf1
#
# after:
#     as_number: '65536'
#
# After state
# -----------
#
# RP/0/0/CPU0:10#show running-config router bgp
# Thu Feb  4 10:01:08.232 UTC
# router bgp 65536
# !
#

# Using purged
#
# Before state
# ------------
#
# RP/0/0/CPU0:10#show running-config router bgp
# Thu Feb  4 09:54:11.161 UTC
# router bgp 65536
#  bgp confederation identifier 4
#  bgp router-id 192.0.2.10
#  bgp cluster-id 5
#  default-metric 5
#  socket send-buffer-size 4098
#  bgp bestpath med confed
#  socket receive-buffer-size 514
#  neighbor 192.0.2.13
#   remote-as 65538
#   bfd fast-detect strict-mode
#   bfd multiplier 6
#   bfd minimum-interval 20
#  !
#  vrf vrf1
#   default-metric 5
#  !
# !
#

- name: Purge all BGP configurations from the device
  cisco.iosxr.iosxr_bgp_global:
    state: purged

#
# Task Output:
# -------------
#
# before:
#     as_number: '65536'
#     bgp:
#       bestpath:
#         med:
#           confed: true
#       cluster_id: '5'
#       confederation:
#         identifier: 4
#       router_id: 192.0.2.10
#     default_metric: 5
#     neighbors:
#     - bfd:
#         fast_detect:
#           strict_mode: true
#         minimum_interval: 20
#         multiplier: 6
#       neighbor_address: 192.0.2.13
#       remote_as: 65538
#     socket:
#       receive_buffer_size: 514
#       send_buffer_size: 4098
#     vrfs:
#     - default_metric: 5
#       vrf: vrf1
#
# commands:
#   - no router bgp 65536
#
# after: {}
#
# After state
# -----------
#
# RP/0/0/CPU0:10#show running-config router bgp
# Thu Feb  4 09:38:36.245 UTC
# % No such configuration item(s)
# RP/0/0/CPU0:10#
#

#
# Using Rendered
# -----------------
#
- name: >-
    Render platform specific configuration lines (without connecting to the
    device)
  cisco.iosxr.iosxr_bgp_global:
    state: rendered
    config:
      as_number: 1
      default_metric: 4
      vrfs:
        - vrf: vrf3
          bfd:
            minimum_interval: 20
            multiplier: 10
          bgp:
            fast_external_fallover:
              disable: true
            router_id: 1.2.3.4
            auto_policy_soft_reset:
              disable: true
          timers:
            keepalive_time: 20
            holdtime: 30
        - vrf: vrf2
          bgp:
            enforce_first_as:
              disable: true
          default_metric: 4
          neighbors:
            - neighbor: 1.1.1.3
              remote_as: 2
              graceful_maintenance:
                set: true
                activate:
                  inheritance_disable: true
                local_preference:
                  value: 1
                as_prepends:
                  value: 2

#
# Task output
# -----------------------
# rendered:
#   - router bgp 1
#   - default-metric 4
#   - vrf vrf3
#   - bfd multiplier 10
#   - bfd minimum-interval 20
#   - bgp auto-policy-soft-reset disable
#   - bgp fast-external-fallover disable
#   - bgp router-id 1.2.3.4
#   - timers bgp 20 30
#   - vrf vrf2
#   - neighbor 1.1.1.3
#   - remote-as 2
#   - graceful-maintenance
#   - graceful-maintenance activate inheritance-disable
#   - graceful-maintenance local-preference 1
#   - graceful-maintenance as-prepends 2
#   - bgp enforce-first-as disable
#   - default-metric 4

# Using parsed
#
#  parsed.cfg
#  ------------
# router bgp 65536
#  bgp confederation identifier 4
#  bgp router-id 192.0.2.10
#  bgp cluster-id 5
#  default-metric 4
#  socket send-buffer-size 4098
#  bgp bestpath med confed
#  socket receive-buffer-size 514
#  neighbor 192.0.2.11
#   remote-as 65537
#   cluster-id 3
#  !
#  neighbor 192.0.2.14
#   remote-as 65538
#   bfd fast-detect strict-mode
#   bfd multiplier 6
#   bfd minimum-interval 20
#  !
# !
#

- name: Parse externally provided BGP config
  cisco.iosxr.iosxr_bgp_global:
    running_config: "{{ lookup('file', 'parsed.cfg') }}"
    state: parsed

# Task output
# -----------------------
# parsed:
#     as_number: '65536'
#     bgp:
#       bestpath:
#         med:
#           confed: true
#       cluster_id: '5'
#       confederation:
#         identifier: 4
#       router_id: 192.0.2.10
#     default_metric: 4
#     neighbors:
#     - cluster_id: '3'
#       neighbor_address: 192.0.2.11
#       remote_as: 65537
#     - bfd:
#         fast_detect:
#           strict_mode: true
#         minimum_interval: 20
#         multiplier: 6
#       neighbor_address: 192.0.2.14
#       remote_as: 65538
#     socket:
#       receive_buffer_size: 514
#       send_buffer_size: 4098

# Using gathered
#
# Before state
# ------------
#

# RP/0/0/CPU0:10#show running-config router bgp
# Thu Feb  4 09:38:36.245 UTC
# router bgp 65536
#  bgp confederation identifier 4
#  bgp router-id 192.0.2.10
#  bgp cluster-id 5
#  default-metric 5
#  socket send-buffer-size 4098
#  bgp bestpath med confed
#  socket receive-buffer-size 514
#  neighbor 192.0.2.13
#   remote-as 65538
#   bfd fast-detect strict-mode
#   bfd multiplier 6
#   bfd minimum-interval 20
#  !
#  vrf vrf1
#   default-metric 5
#  !
# !

- name: Gather bgp global facts
  cisco.iosxr.iosxr_bgp_global:
    state: gathered

# Task Output:
# ------------
#
# gathered:
#     as_number: '65536'
#     bgp:
#       bestpath:
#         med:
#           confed: true
#       cluster_id: '5'
#       confederation:
#         identifier: 4
#       router_id: 192.0.2.10
#     default_metric: 5
#     neighbors:
#     - bfd:
#         fast_detect:
#           strict_mode: true
#         minimum_interval: 20
#         multiplier: 6
#       neighbor_address: 192.0.2.13
#       remote_as: 65538
#     socket:
#       receive_buffer_size: 514
#       send_buffer_size: 4098
#     vrfs:
#     - default_metric: 5
#       vrf: vrf1
"""
RETURN = """
before:
  description: The configuration prior to the model invocation.
  returned: always
  type: dict
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
after:
  description: The resulting configuration model invocation.
  returned: when changed
  type: dict
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample:
  - router bgp 65536
  - bgp cluster-id 5
  - bgp router-id 192.0.2.10
  - bgp bestpath med confed

rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
  - router bgp 1
  - default-metric 4
  - vrf vrf3
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

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.bgp_global.bgp_global import (
    Bgp_globalArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.config.bgp_global.bgp_global import (
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
