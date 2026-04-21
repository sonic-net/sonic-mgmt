#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_bgp_neighbors
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_bgp_neighbors
version_added: 1.0.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
short_description: Manage a BGP neighbor and its parameters
description:
  - This module provides configuration management of global BGP_NEIGHBORS parameters on devices running Enterprise SONiC.
  - bgp_as and vrf_name must be created on the device in advance.
author: Abirami N (@abirami-n)
options:
  config:
    description: Specifies the BGP neighbors related configuration.
    type: list
    elements: dict
    suboptions:
      bgp_as:
        description:
          - Specifies the BGP autonomous system (AS) number which is already configured on the device.
        type: str
        required: True
      vrf_name:
        description:
          - Specifies the VRF name which is already configured on the device.
        default: default
        type: str
      peer_group:
        description: Specifies the list of peer groups.
        type: list
        elements: dict
        suboptions:
          name:
            description: Name of the peer group.
            type: str
            required: True
          remote_as:
            description:
              - Remote AS of the BGP peer group to configure.
              - peer_as and peer_type are mutually exclusive.
            type: dict
            suboptions:
              peer_as:
                description:
                  - Specifies remote AS number.
                  - The range is from 1 to 4294967295.
                type: str
              peer_type:
                description:
                  - Specifies the type of BGP peer.
                type: str
                choices:
                  - internal
                  - external
          bfd:
            description:
              - Enables or disables BFD.
            type: dict
            suboptions:
              enabled:
                description:
                  - Enables BFD liveliness check for a BGP peer.
                type: bool
              check_failure:
                description:
                  - Link dataplane status with control plane.
                type: bool
              profile:
                description:
                  - BFD Profile name.
                type: str
          advertisement_interval:
            description:
              - Specifies the minimum interval between sending BGP routing updates.
              - The range is from 0 to 600.
            type: int
          timers:
            description:
              - Specifies BGP peer group timer related configurations.
            type: dict
            suboptions:
              keepalive:
                description:
                  - Frequency with which the device sends keepalive messages to its peer, in seconds.
                  - The range is from 0 to 65535.
                type: int
              holdtime:
                description:
                  - Interval after not receiving a keepalive message that Enterprise SONiC declares a peer dead, in seconds.
                  - The range is from 0 to 65535.
                type: int
              connect_retry:
                description:
                  - Time interval in seconds between attempts to establish a session with the peer.
                  - The range is from 1 to 65535.
                type: int
          capability:
            description:
              - Specifies capability attributes to this peer group.
            type: dict
            suboptions:
              dynamic:
                description:
                  - Enables or disables dynamic capability to this peer group.
                type: bool
              extended_nexthop:
                description:
                  - Enables or disables advertise extended next-hop capability to the peer.
                type: bool
          auth_pwd:
            description:
              - Configuration for peer group authentication password.
            type: dict
            suboptions:
              pwd:
                description:
                  - Authentication password for the peer group.
                type: str
                required: True
              encrypted:
                description:
                  - Indicates whether the password is encrypted text.
                type: bool
                default: False
          pg_description:
            description:
              - A textual description of the peer group.
            type: str
          disable_connected_check:
            description:
              - Disables EBGP conntected route check.
            type: bool
          dont_negotiate_capability:
            description:
              - Disables capability negotiation.
            type: bool
          ebgp_multihop:
            description:
              - Allow EBGP peers not on directly connected networks.
            type: dict
            suboptions:
              enabled:
                description:
                  - Enables the referenced group or peers to be indirectly connected.
                type: bool
                default: False
              multihop_ttl:
                description:
                  - Time-to-live value to use when packets are sent to the referenced group or peers and ebgp-multihop is enabled.
                type: int
          enforce_first_as:
            description:
              - Enforces the first AS for EBGP routes.
            type: bool
          enforce_multihop:
            description:
              - Enforces EBGP multihop performance for peer.
            type: bool
          extended_link_bandwidth:
            version_added: 3.1.0
            description:
              - Configure the Link Bandwidth extended community for a BGP peer.
            type: bool
          local_address:
            description:
              - Set the local IP address to use for the session when sending BGP update messages.
            type: str
          local_as:
            description:
              - Specifies local autonomous system number.
            type: dict
            suboptions:
              as:
                description:
                  - Local autonomous system number.
                type: str
                required: True
              no_prepend:
                description:
                  - Do not prepend the local-as number in AS-Path advertisements.
                type: bool
              replace_as:
                description:
                  - Replace the configured AS Number with the local-as number in AS-Path advertisements.
                type: bool
          override_capability:
            description:
              - Override capability negotiation result.
            type: bool
          passive:
            description:
              - Do not send open messages to this peer.
              - Default value while adding a new peergroup is C(False).
            type: bool
          shutdown_msg:
            description:
              - Add a shutdown message.
            type: str
          solo:
            description:
              - Indicates that routes advertised by the peer should not be reflected back to the peer.
            type: bool
          strict_capability_match:
            description:
              - Enables strict capability negotiation match.
            type: bool
          ttl_security:
            description:
              - Enforces only the peers that are specified number of hops away will be allowed to become peers.
            type: int
          address_family:
            description:
              - Holds of list of address families associated to the peergroup.
            type: dict
            suboptions:
              afis:
                description:
                  - List of address families with afi, safi, activate and allowas-in parameters.
                  - afi and safi are required together.
                type: list
                elements: dict
                suboptions:
                  afi:
                    description:
                      - Holds afi mode.
                    type: str
                    required: True
                    choices:
                      - ipv4
                      - ipv6
                      - l2vpn
                  safi:
                    description:
                      - Holds safi mode.
                    type: str
                    choices:
                      - unicast
                      - evpn
                  activate:
                    description:
                      - Enable or disable activate.
                    type: bool
                  allowas_in:
                    description:
                      - Criterion for accepting received advertisements containing the AS number
                      - of this BGP router intance in the AS PATH of received advertisements.
                      - The 'origin' option can not be set to true when a 'value' is set.
                    type: dict
                    suboptions:
                      origin:
                        description:
                          - Accept this BGP router instance's set AS as the origin.
                        type: bool
                      value:
                        description:
                          - Accept up to this number of occurrences of this BGP router's
                          - set AS in the AS-PATH of received advertisements.
                          - (Specify a number in the range 1-10.)
                        type: int
                  ip_afi:
                    description:
                      - Common configuration attributes for IPv4 and IPv6 unicast address families.
                    type: dict
                    suboptions:
                      default_policy_name:
                        description:
                          - Specifies routing policy definition.
                        type: str
                      send_default_route:
                        description:
                          - Enable or disable sending of default-route to the peer.
                        type: bool
                        default: False
                  prefix_limit:
                    description:
                      - Specifies prefix limit attributes for ipv4-unicast and ipv6-unicast.
                    type: dict
                    suboptions:
                      max_prefixes:
                        description:
                          - Maximum number of prefixes that will be accepted from the peer.
                        type: int
                      prevent_teardown:
                        description:
                          - Enable or disable teardown of BGP session when maximum prefix limit is exceeded.
                        type: bool
                        default: False
                      warning_threshold:
                        description:
                          - Threshold on number of prefixes that can be received from a peer before generation of warning messages.
                          - Expressed as a percentage of max-prefixes.
                        type: int
                      restart_timer:
                        description:
                          - Time interval in seconds after which the BGP session is re-established after being torn down.
                        type: int
                      discard_extra:
                        description:
                          - Enable or disable discard extra of BGP session when maximum prefix limit is exceeded.
                        type: bool
                        default: False
                  prefix_list_in:
                    description:
                      - Inbound route filtering policy for a peer.
                    type: str
                  prefix_list_out:
                    description:
                      - Outbound route filtering policy for a peer.
                    type: str
      neighbors:
        description: Specifies BGP neighbor-related configurations.
        type: list
        elements: dict
        suboptions:
          neighbor:
            description:
              - Neighbor router address.
            type: str
            required: True
          remote_as:
            description:
              - Remote AS of the BGP neighbor to configure.
              - peer_as and peer_type are mutually exclusive.
            type: dict
            suboptions:
              peer_as:
                description:
                  - Specifies remote AS number.
                  - The range is from 1 to 4294967295.
                type: str
              peer_type:
                description:
                  - Specifies the type of BGP peer.
                type: str
                choices:
                  - internal
                  - external
          bfd:
            description:
              - Enables or disables BFD.
            type: dict
            suboptions:
              enabled:
                description:
                  - Enables BFD liveliness check for a BGP neighbor.
                type: bool
              check_failure:
                description:
                  - Link dataplane status with control plane.
                type: bool
              profile:
                description:
                  - BFD Profile name.
                type: str
          advertisement_interval:
            description:
              - Specifies the minimum interval between sending BGP routing updates.
              - The range is from 0 to 600.
            type: int
          peer_group:
            description:
              - The name of the peer group that the neighbor is a member of.
            type: str
          timers:
            description:
              - Specifies BGP neighbor timer-related configurations.
            type: dict
            suboptions:
              keepalive:
                description:
                  - Frequency with which the device sends keepalive messages to its peer, in seconds.
                  - The range is from 0 to 65535.
                type: int
              holdtime:
                description:
                  - Interval after not receiving a keepalive message that SONiC declares a peer dead, in seconds.
                  - The range is from 0 to 65535.
                type: int
              connect_retry:
                description:
                  - Time interval in seconds between attempts to establish a session with the peer.
                  - The range is from 1 to 65535.
                type: int
          capability:
            description:
              - Specifies capability attributes to this neighbor.
            type: dict
            suboptions:
              dynamic:
                description:
                  - Enables or disables dynamic capability to this neighbor.
                type: bool
              extended_nexthop:
                description:
                  - Enables or disables advertise extended next-hop capability to the peer.
                type: bool
          auth_pwd:
            description:
              - Configuration for neighbor group authentication password.
            type: dict
            suboptions:
              pwd:
                description:
                  - Authentication password for the neighbor group.
                type: str
                required: True
              encrypted:
                description:
                  - Indicates whether the password is encrypted text.
                type: bool
                default: False
          nbr_description:
            description:
              - A textual description of the neighbor.
            type: str
          disable_connected_check:
            description:
              - Disables EBGP conntected route check.
            type: bool
          dont_negotiate_capability:
            description:
              - Disables capability negotiation.
            type: bool
          ebgp_multihop:
            description:
              - Allow EBGP neighbors not on directly connected networks.
            type: dict
            suboptions:
              enabled:
                description:
                  - Enables the referenced group or neighbors to be indirectly connected.
                type: bool
                default: False
              multihop_ttl:
                description:
                  - Time-to-live value to use when packets are sent to the referenced group or neighbors and ebgp-multihop is enabled.
                type: int
          enforce_first_as:
            description:
              - Enforces the first AS for EBGP routes.
            type: bool
          enforce_multihop:
            description:
              - Enforces EBGP multihop performance for neighbor.
            type: bool
          extended_link_bandwidth:
            version_added: 3.1.0
            description:
              - Configure the Link Bandwidth extended community for a BGP neighbor.
            type: bool
          local_address:
            description:
              - Set the local IP address to use for the session when sending BGP update messages.
            type: str
          local_as:
            description:
              - Specifies local autonomous system number.
            type: dict
            suboptions:
              as:
                description:
                  - Local autonomous system number.
                type: str
                required: True
              no_prepend:
                description:
                  - Do not prepend the local-as number in AS-Path advertisements.
                type: bool
              replace_as:
                description:
                  - Replace the configured AS Number with the local-as number in AS-Path advertisements.
                type: bool
          override_capability:
            description:
              - Override capability negotiation result.
            type: bool
          passive:
            description:
              - Do not send open messages to this neighbor.
              - Default value while adding a new neighbor is C(False).
            type: bool
          port:
            description:
              - Neighbor's BGP port.
            type: int
          shutdown_msg:
            description:
              - Add a shutdown message.
            type: str
          solo:
            description:
              - Indicates that routes advertised by the peer should not be reflected back to the peer.
            type: bool
          strict_capability_match:
            description:
              - Enables strict capability negotiation match.
            type: bool
          ttl_security:
            description:
              - Enforces only the neighbors that are specified number of hops away will be allowed to become neighbors.
            type: int
          v6only:
            description:
              - Enables BGP with v6 link-local only.
            type: bool

  state:
    description:
      - Specifies the operation to be performed on the BGP process that is configured on the device.
      - In case of merged, the input configuration is merged with the existing BGP configuration on the device.
      - In case of deleted, the existing BGP configuration is removed from the device.
      - In case of replaced, the existing BGP configuration will be replaced with the input BGP configuration on the device.
      - In case of overridden, the existing BGP configuration will be overriden with the input BGP configuration on the device.
    default: merged
    type: str
    choices:
      - merged
      - deleted
      - replaced
      - overridden
"""

EXAMPLES = """
# Using "deleted" state
#
# Before state:
# -------------
# router bgp 11 vrf VrfCheck2
#  network import-check
#  timers 60 180
# !
# router bgp 51 vrf VrfReg1
#  network import-check
#  timers 60 180
#  !
#  neighbor interface Eth1/3
# !
# router bgp 11
# network import-check
# timers 60 180
# !
# neighbor 192.168.1.4
# !
# peer-group SP1
#  timers connect 30
#  advertisement-interval 0
#  bfd
#  capability dynamic
# !
# peer-group SP2
#  timers connect 30
#  advertisement-interval 0
# !
#

- name: Deletes all BGP neighbors
  dellemc.enterprise_sonic.sonic_bgp_neighbors:
    config:
    state: deleted

#
# After state:
# -------------
# router bgp 11 vrf VrfCheck2
#  network import-check
#  timers 60 180
# !
# router bgp 51 vrf VrfReg1
#  network import-check
#  timers 60 180
# !
# router bgp 11
#  network import-check
#  timers 60 180
# !
#

# Using "merged" state
#
# Before state:
# ------------
# router bgp 11 vrf VrfCheck2
#  network import-check
#  timers 60 180
# !
# router bgp 51 vrf VrfReg1
#  network import-check
#  timers 60 180
# !
# router bgp 11
#  network import-check
#  timers 60 180
# !

- name: "Adds sonic_bgp_neighbors"
  dellemc.enterprise_sonic.sonic_bgp_neighbors:
    config:
      - bgp_as: 51
        neighbors:
          - neighbor: Eth1/2
            auth_pwd:
              pwd: 'pw123'
              encrypted: false
            dont_negotiate_capability: true
            ebgp_multihop:
              enabled: true
              multihop_ttl: 1
            enforce_first_as: true
            enforce_multihop: true
            local_address: 'Ethernet4'
            local_as:
              as: 2
              no_prepend: true
              replace_as: true
            nbr_description: "description 1"
            override_capability: true
            passive: true
            port: 3
            shutdown_msg: 'msg1'
            solo: true
          - neighbor: 1.1.1.1
            disable_connected_check: true
            ttl_security: 5
      - bgp_as: 51
        vrf_name: VrfReg1
        peer_group:
          - name: SPINE
            bfd:
              check_failure: true
              enabled: true
              profile: 'profile 1'
            capability:
              dynamic: true
              extended_nexthop: true
            auth_pwd:
              pwd: 'U2FsdGVkX1/4sRsZ624wbAJfDmagPLq2LsGDOcW/47M='
              encrypted: true
            dont_negotiate_capability: true
            ebgp_multihop:
              enabled: true
              multihop_ttl: 1
            enforce_first_as: true
            enforce_multihop: true
            extended_link_bandwidth: true
            local_address: 'Ethernet4'
            local_as:
              as: 2
              no_prepend: true
              replace_as: true
            pg_description: 'description 1'
            override_capability: true
            passive: true
            solo: true
            remote_as:
              peer_as: 4
          - name: SPINE1
            disable_connected_check: true
            shutdown_msg: "msg1"
            strict_capability_match: true
            timers:
              keepalive: 30
              holdtime: 15
              connect_retry: 25
            ttl_security: 5
            address_family:
              afis:
                - afi: ipv4
                  safi: unicast
                  activate: true
                  allowas_in:
                    origin: true
                - afi: ipv6
                  safi: unicast
                  activate: true
                  allowas_in:
                    value: 5
        neighbors:
          - neighbor: Eth1/3
            remote_as:
              peer_as: 10
            peer_group: SPINE
            advertisement_interval: 15
            extended_link_bandwidth: true
            timers:
              keepalive: 30
              holdtime: 15
              connect_retry: 25
            bfd:
              check_failure: true
              enabled: true
              profile: 'profile 1'
            capability:
              dynamic: true
              extended_nexthop: true
            auth_pwd:
              pwd: 'U2FsdGVkX199MZ7YOPkOR9O6wEZmtGSgiDfnlcN9hBg='
              encrypted: true
            nbr_description: 'description 2'
            strict_capability_match: true
            v6only: true
          - neighbor: 192.168.1.4
    state: merged

#
# After state:
# ------------
# !
# router bgp 11 vrf VrfCheck2
#  network import-check
#  timers 60 180
# !
# router bgp 51 vrf VrfReg1
#  network import-check
#  timers 60 180
# !
# peer-group SPINE1
#  timers 15 30
#  timers connect 25
#  advertisement-interval 0
#  shutdown message msg1
#  disable-connected-check
#  strict-capability-match
#  ttl-security hops 5
# !
# peer-group SPINE
#  description "description 1"
#  ebgp-multihop 1
#  remote-as 4
#  timers connect 30
#  advertisement-interval 0
#  bfd check-control-plane-failure profile "profile 1"
#  update-source interface Ethernet4
#  capability dynamic
#  capability extended-nexthop
#  dont-capability-negotiate
#  enforce-first-as
#  enforce-multihop
#  extended-link-bandwidth
#  local-as 2 no-prepend replace-as
#  override-capability
#  passive
#  password U2FsdGVkX1/4sRsZ624wbAJfDmagPLq2LsGDOcW/47M= encrypted
#  solo
#  address-family ipv4 unicast
#   activate
#   allowas-in origin
#   send-community both
# !
#  address-family ipv6 unicast
#   activate
#   allowas-in 5
#   send-community both
# !
# neighbor interface Eth1/3
#  description "description 2"
#  peer-group SPINE
#  remote-as 10
#  timers 15 30
#  timers connect 25
#  bfd check-control-plane-failure profile "profile 1"
#  advertisement-interval 15
#  capability extended-nexthop
#  capability dynamic
#  extended-link-bandwidth
#  v6only
#  password U2FsdGVkX199MZ7YOPkOR9O6wEZmtGSgiDfnlcN9hBg= encrypted
#  strict-capability-match
# !
# neighbor 192.168.1.4
# !
# router bgp 51
#  network import-check
#  timers 60 180
# !
# neighbor interface Eth1/2
#  description "description 1"
#  shutdown message msg1
#  ebgp-multihop 1
#  remote-as external
#  update-source interface Ethernet4
#  dont-capability-negotiate
#  enforce-first-as
#  enforce-multihop
#  local-as 2 no-prepend replace-as
#  override-capability
#  passive
#  password U2FsdGVkX1+bxMf9TKOhaXRNNaHmywiEVDF2lJ2c000= encrypted
#  port 3
#  solo
# neighbor 1.1.1.1
#  disable-connected-check
#  ttl-security hops 5
# router bgp 11
#  network import-check
#  timers 60 180
#

# Using "deleted" state
#
# Before state:
# ------------
# !
# router bgp 11 vrf VrfCheck2
#  network import-check
#  timers 60 180
# !
# router bgp 51 vrf VrfReg1
#  network import-check
#  timers 60 180
# !
# peer-group SPINE
#  bfd
#  remote-as 4
#  timers connect 30
#  advertisement-interval 0
# !
# neighbor interface Eth1/3
#  peer-group SPINE
#  remote-as 10
#  timers 15 30
#  advertisement-interval 15
#  bfd
#  capability extended-nexthop
#  capability dynamic
# !
# neighbor 192.168.1.4
# !
# router bgp 11
#  network import-check
#  timers 60 180
# !
# peer-group SP
#  timers connect 30
#  advertisement-interval 0
# !
# neighbor interface Eth1/3
#

- name: "Deletes sonic_bgp_neighbors and peer-groups specific to vrfname"
  dellemc.enterprise_sonic.sonic_bgp_neighbors:
    config:
      - bgp_as: 51
        vrf_name: VrfReg1
    state: deleted

# After state:
# ------------
# !
# router bgp 11 vrf VrfCheck2
#  network import-check
#  timers 60 180
# !
# router bgp 51 vrf VrfReg1
#  network import-check
#  timers 60 180
# !
# router bgp 11
#  network import-check
#  timers 60 180
# !
# peer-group SP
#  timers connect 30
#  advertisement-interval 0
# !
# neighbor interface Eth1/3
#

# Using "deleted" state
#
# Before state:
# -------------
#
# router bgp 51 vrf VrfReg1
#  network import-check
#  timers 60 180
# !
# peer-group SPINE
#  bfd
#  remote-as 4
#  timers connect 30
#  advertisement-interval 0
# !
# neighbor interface Eth1/3
#  peer-group SPINE
#  remote-as 10
#  timers 15 30
#  advertisement-interval 15
#  bfd
#  capability extended-nexthop
#  capability dynamic
#  extended-link-bandwidth
# !
# neighbor 192.168.1.4
# !

- name: "Deletes specific sonic_bgp_neighbors"
  dellemc.enterprise_sonic.sonic_bgp_neighbors:
    config:
      - bgp_as: 51
        neighbors:
          - neighbor: Eth1/2
            auth_pwd:
              pwd: 'pw123'
              encrypted: false
            dont_negotiate_capability: true
            ebgp_multihop:
              enabled: true
              multihop_ttl: 1
            enforce_first_as: true
            enforce_multihop: true
            local_address: 'Ethernet4'
            local_as:
              as: 2
              no_prepend: true
              replace_as: true
            nbr_description: 'description 1'
            override_capability: true
            passive: true
            port: 3
            shutdown_msg: 'msg1'
            solo: true
          - neighbor: 1.1.1.1
            disable_connected_check: true
            ttl_security: 5
      - bgp_as: 51
        vrf_name: VrfReg1
        peer_group:
          - name: SPINE
            bfd:
              check_failure: true
              enabled: true
              profile: 'profile 1'
            capability:
              dynamic: true
              extended_nexthop: true
            auth_pwd:
              pwd: 'U2FsdGVkX1/4sRsZ624wbAJfDmagPLq2LsGDOcW/47M='
              encrypted: true
            dont_negotiate_capability: true
            ebgp_multihop:
              enabled: true
              multihop_ttl: 1
            enforce_first_as: true
            enforce_multihop: true
            local_address: 'Ethernet4'
            local_as:
              as: 2
              no_prepend: true
              replace_as: true
            pg_description: 'description 1'
            override_capability: true
            passive: true
            solo: true
            remote_as:
              peer_as: 4
          - name: SPINE1
            disable_connected_check: true
            shutdown_msg: "msg1"
            strict_capability_match: true
            timers:
              keepalive: 30
              holdtime: 15
              connect_retry: 25
            ttl_security: 5
        neighbors:
          - neighbor: Eth1/3
            remote_as:
              peer_as: 10
            peer_group: SPINE
            advertisement_interval: 15
            timers:
              keepalive: 30
              holdtime: 15
              connect_retry: 25
            bfd:
              check_failure: true
              enabled: true
              profile: 'profile 1'
            capability:
              dynamic: true
              extended_nexthop: true
            auth_pwd:
              pwd: 'U2FsdGVkX199MZ7YOPkOR9O6wEZmtGSgiDfnlcN9hBg='
              encrypted: true
            extended_link_bandwidth: true
            nbr_description: 'description 2'
            strict_capability_match: true
            v6only: true
          - neighbor: 192.168.1.4
    state: deleted

#
# After state:
# -------------
#
# router bgp 51 vrf VrfReg1
#  network import-check
#  timers 60 180
# !
# peer-group SPINE1
#  timers connect 30
#  advertisement-interval 0
# !
# peer-group SPINE
#  timers connect 30
#  advertisement-interval 0
# !
# neighbor interface Eth1/3
# !
# neighbor interface Eth1/2
# !
# neighbor 1.1.1.1
#

# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration bgp peer-group vrf default
# (No bgp peer-group configuration present)

- name: "Configure BGP peer-group prefix-list attributes"
  dellemc.enterprise_sonic.sonic_bgp_neighbors:
    config:
      - bgp_as: 51
        peer_group:
          - name: SPINE
            address_family:
              afis:
                - afi: ipv4
                  safi: unicast
                  ip_afi:
                    default_policy_name: rmap_reg1
                    send_default_route: true
                  prefix_limit:
                    max_prefixes: 1
                    prevent_teardown: true
                    warning_threshold: 80
                  prefix_list_in: p1
                  prefix_list_out: p2
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration bgp peer-group vrf default
# !
# peer-group SPINE
#  timers connect 30
#  advertisement-interval 0
#  !
#  address-family ipv4 unicast
#   default-originate route-map rmap_reg1
#   prefix-list p1 in
#   prefix-list p2 out
#   send-community both
#   maximum-prefix 1 80 warning-only
#

# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration bgp peer-group vrf default
# (No bgp peer-group configuration present)

- name: "Configure BGP peer-group prefix-list attributes"
  dellemc.enterprise_sonic.sonic_bgp_neighbors:
    config:
      - bgp_as: 51
        peer_group:
          - name: SPINE
            address_family:
              afis:
                - afi: ipv4
                  safi: unicast
                  ip_afi:
                    default_policy_name: rmap_reg1
                    send_default_route: true
                  prefix_limit:
                    max_prefixes: 2
                    discard_extra: true
                    warning_threshold: 86
                  prefix_list_in: p1
                  prefix_list_out: p2
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration bgp peer-group vrf default
# !
# peer-group SPINE
#  timers connect 30
#  advertisement-interval 0
#  !
#  address-family ipv4 unicast
#   default-originate route-map rmap_reg1
#   prefix-list p1 in
#   prefix-list p2 out
#   send-community both
#   maximum-prefix 2 86 discard-extra
#

# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration bgp peer-group vrf default
# !
# peer-group SPINE
#  timers connect 30
#  advertisement-interval 0
#  !
#  address-family ipv6 unicast
#   default-originate route-map rmap_reg2
#   prefix-list p1 in
#   prefix-list p2 out
#   send-community both
#   maximum-prefix 5 90 restart 2

- name: "Delete BGP peer-group prefix-list attributes"
  dellemc.enterprise_sonic.sonic_bgp_neighbors:
    config:
      - bgp_as: 51
        peer_group:
          - name: SPINE
            address_family:
              afis:
                - afi: ipv6
                  safi: unicast
                  ip_afi:
                    default_policy_name: rmap_reg2
                    send_default_route: true
                  prefix_limit:
                    max_prefixes: 5
                    warning_threshold: 90
                    restart-timer: 2
                  prefix_list_in: p1
                  prefix_list_out: p2
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration bgp peer-group vrf default
# !
# peer-group SPINE
#  timers connect 30
#  advertisement-interval 0
#  !
#  address-family ipv6 unicast
#    send-community both
#  !

#
# Using "replaced" state
#
# Before state:
# ------------
# !
# router bgp 51 vrf VrfCheck2
#  network import-check
#  timers 60 180
# !
# router bgp 51 vrf VrfReg1
#  network import-check
#  timers 60 180
# !
# peer-group SPINE3
#  bfd
#  remote-as 4
#  timers connect 30
#  advertisement-interval 0
# !
# neighbor interface Eth1/3
#  remote-as 10
#  timers 15 30
#  advertisement-interval 15
#  bfd
#  capability extended-nexthop
#  capability dynamic
# !
# neighbor 192.168.1.4
# !
# router bgp 51
#  network import-check
#  timers 60 18
# !
# peer-group SP
#  timers connect 30
#  advertisement-interval 0
# !
# neighbor interface Eth1/3
#

- name: "Replaces peer-groups specific to vrfname"
  dellemc.enterprise_sonic.sonic_bgp_neighbors:
    config:
      - bgp_as: 51
        vrf_name: VrfReg1
        peer_group:
          - name: SPINE3
            remote_as:
              peer_type: internal
          - name: SPINE4
            address_family:
              afis:
                - afi: ipv4
                  safi: unicast
                  allowas_in:
                    origin: true
    state: replaced

# After state:
# ------------
# !
# router bgp 51 vrf VrfCheck2
#  network import-check
#  timers 60 180
# !
# router bgp 51 vrf VrfReg1
#  network import-check
#  timers 60 180
# !
# peer-group SPINE3
#  remote-as internal
#  timers connect 30
#  advertisement-interval 0
# !
# peer-group SPINE4
#  timers connect 30
#  advertisement-interval 0
#  !
#  address-family ipv4 unicast
#   allowas-in origin
#   send-community both
# !
#  neighbor interface Eth1/3
#   remote-as 10
#   timers 15 30
#   advertisement-interval 15
#   bfd
#   capability extended-nexthop
#   capability dynamic
#  !
#  neighbor 192.168.1.4
# !
# router bgp 51
# network import-check
# timers 60 18
# !
# peer-group SP
#  timers connect 30
#  advertisement-interval 0
# !
# neighbor interface Eth1/3
#
#

# Using "replaced" state
#
# Before state:
# ------------
# !
# router bgp 51 vrf VrfCheck2
#  network import-check
#  timers 60 180
# !
# router bgp 51 vrf VrfReg1
#  network import-check
#  timers 60 180
# !
# peer-group SPINE
#  bfd
#  remote-as 4
#  timers connect 30
#  advertisement-interval 0
#  extended-link-bandwidth
# !
# neighbor 192.168.1.1
#  peer-group SPINE
#  remote-as 10
#  timers 15 30
#  advertisement-interval 15
#  bfd
#  capability extended-nexthop
#  capability dynamic
# !
# neighbor 192.168.1.4
# !
# router bgp 51
#  network import-check
#  timers 60 18
# !
# peer-group SP
#  timers connect 30
#  advertisement-interval 0
# !
# neighbor interface Eth1/3
#

- name: "Replaces sonic_bgp_neighbors specific to vrfname"
  dellemc.enterprise_sonic.sonic_bgp_neighbors:
    config:
      - bgp_as: 51
        vrf_name: VrfReg1
        neighbors:
          - neighbor: 192.168.1.1
            bfd:
              enabled: true
            capability:
              extended_nexthop: true
              dynamic: true
    state: replaced

# After state:
# ------------
# !
# router bgp 51 vrf VrfCheck2
#  network import-check
#  timers 60 180
# !
# router bgp 51 vrf VrfReg1
#  network import-check
#  timers 60 180
# !
# peer-group SPINE
#  bfd
#  remote-as 4
#  timers connect 30
#  advertisement-interval 0
#  extended-link-bandwidth
# !
# neighbor 192.168.1.1
#  bfd
#  capability extended-nexthop
#  capability dynamic
# !
# neighbor 192.168.1.4
# !
# router bgp 51
#  network import-check
#  timers 60 18
# !
# peer-group SP
#  timers connect 30
#  advertisement-interval 0
# !
# neighbor interface Eth1/3
#

# Using "overridden" state
#
# Before state:
# ------------
# !
# router bgp 51 vrf VrfCheck2
#  network import-check
#  timers 60 180
# !
# router bgp 51 vrf VrfReg1
#  network import-check
#  timers 60 180
# !
# peer-group SPINE
#  bfd
#  remote-as 4
#  timers connect 30
#  advertisement-interval 0
# !
# neighbor interface Eth1/3
#  peer-group SPINE
#  remote-as 10
#  timers 15 30
#  advertisement-interval 15
#  bfd
#  capability extended-nexthop
#  capability dynamic
# !
# neighbor 192.168.1.4
# !
# router bgp 51
#  network import-check
#  timers 60 18
# !
# peer-group SP
#  timers connect 30
#  advertisement-interval 0
# !
# neighbor interface Eth1/3
#

- name: "Override sonic_bgp_neighbors and peer-groups specific to vrfname"
  dellemc.enterprise_sonic.sonic_bgp_neighbors:
    config:
      - bgp_as: 51
        vrf_name: VrfReg1
        peer_group:
          - name: SPINE3
            remote_as:
              peer_type: internal
          - name: SPINE4
            address_family:
              afis:
                - afi: ipv4
                  safi: unicast
                  allowas_in:
                    origin: true
    state: overridden

# After state:
# ------------
# !
# router bgp 51 vrf VrfReg1
#  network import-check
#  timers 60 180
# !
# peer-group SPINE3
#  remote-as internal
#  timers connect 30
#  advertisement-interval 0
# !
# peer-group SPINE4
#  timers connect 30
#  advertisement-interval 0
#  !
#  address-family ipv4 unicast
#   allowas-in origin
#   send-community both
# !
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
    The configuration returned is always in the same format
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.bgp_neighbors.bgp_neighbors import Bgp_neighborsArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.bgp_neighbors.bgp_neighbors import Bgp_neighbors


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Bgp_neighborsArgs.argument_spec,
                           supports_check_mode=True)

    result = Bgp_neighbors(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
