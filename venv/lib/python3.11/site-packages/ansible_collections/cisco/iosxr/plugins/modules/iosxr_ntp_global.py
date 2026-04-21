#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for iosxr_ntp_global
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: iosxr_ntp_global
short_description: Resource module to configure NTP.
description: This module configures and manages the attributes of  ntp on Cisco
  IOSXR platforms.
version_added: 2.5.0
author: Ashwini Mhatre (@amhatre)
notes:
  - Tested against IOSXR 7.0.2.
  - This module works with connection C(network_cli).
options:
  config:
    description: A dictionary of ntp options
    type: dict
    suboptions:
        access_group:
          description: Control NTP access
          type: dict
          suboptions:
            ipv4: &ipv4
              type: dict
              description: Configure IPv4 access
              suboptions:
                peer: &peer
                  type: str
                  description: Provide full access
                query_only: &query_only
                  type: str
                  description: Allow only control queries.
                serve: &serve
                  type: str
                  description: Provide server and query access.
                serve_only: &serve_only
                  type: str
                  description: Provide only server access.
            ipv6: &ipv6
              type: dict
              description: Configure IPv6 access
              suboptions:
                peer: *peer
                query_only: *query_only
                serve: *serve
                serve_only: *serve_only
            vrfs:
              type: list
              elements: dict
              description: Specify non-default VRF.
              suboptions:
                name:
                  type: str
                  description: Specify non-default VRF.
                ipv4: *ipv4
                ipv6: *ipv6
        authenticate:
          description: Authenticate time sources
          type: bool
        authentication_keys:
          description: Authentication key for trusted time sources
          type: list
          elements: dict
          suboptions:
            id:
              description: <1-65535>  Key number
              type: int
            key:
              description: Authentication key.
              type: str
            encryption:
              description: Type of key encrypted or clear-text.
              type: bool
        broadcastdelay:
          type: int
          description: Estimated round-trip delay in microseconds.
        drift:
          type: dict
          description: Drift(cisco-support)
          suboptions:
            aging_time:
              type: int
              description: Aging time in hours.
            file:
              description: File for drift values.
              type: str
        interfaces:
          type: list
          elements: dict
          description: Configure NTP on an interface.
          suboptions:
            name:
              type: str
              description: Name of the interface.
            vrf:
              type: str
              description: Name of the vrf.
            broadcast_client:
              type: bool
              description: Listen to NTP broadcasts
            broadcast_destination:
              type: str
              description: Configure broadcast destination address.
            broadcast_key:
              type: int
              description: Broadcast key number.
            broadcast_version:
              type: int
              description: <2-4>  NTP version number.
            multicast_key:
              type: int
              description: Configure multicast authentication key.
            multicast_ttl:
              type: int
              description: Configure TTL to use.
            multicast_client:
              type: str
              description: Configure multicast client
            multicast_destination:
              type: str
              description: Configure multicast destination
            multicast_version:
              type: int
              description: <2-4>  NTP version number.
        ipv4: &ip
          description: Mark the dscp/precedence bit for ipv4 packets.
          type: dict
          suboptions:
            dscp:
              description: Set IP DSCP (DiffServ CodePoint).Please refer vendor document for valid entries.
              type: str
            precedence:
              description: Set precedence Please refer vendor document for valid entries.
              type: str
              choices: [ "critical", "flash", "flash-override", "immediate", "internet", "network", "priority", "routine" ]
        ipv6: *ip
        log_internal_sync:
          type: bool
          description: Logs internal synchronization changes.
        master:
          description: Act as NTP master clock
          type: dict
          suboptions:
            stratum:
              description: Use NTP as clock source with stratum number <1-15>
              type: int
        max_associations:
          type: int
          description: <0-4294967295>  Number of associations.
        passive:
          type: bool
          description: Enable the passive associations.
        trusted_keys:
          type: list
          elements: dict
          description: list of Key numbers for trusted time sources.
          suboptions:
            key_id:
              type: int
              description: Key numbers for trusted time sources.
        update_calendar:
          type: bool
          description: Periodically update calendar with NTP time.
        source_interface:
          type: str
          description: Configure default interface.
        source_vrfs:
          type: list
          elements: dict
          description: Configure default interface.
          suboptions:
            name:
              type: str
              description: Name of source interface.
            vrf:
              type: str
              description: vrf name.
        servers:
          description: Configure NTP server.
          type: list
          elements: dict
          suboptions:
            vrf: &vrf
              description: vrf name.
              type: str
            server: &host
              description: Hostname or A.B.C.D or A:B:C:D:E:F:G:H.
              type: str
              required: True
            burst: &burst
              description: Use burst mode.
              type: bool
            iburst: &iburst
              description: Use initial burst mode.
              type: bool
            key_id: &key
              description: SConfigure peer authentication key
              type: int
            source: &source
              description: Interface for source address.
              type: str
            maxpoll: &maxpoll
              description: configure Maximum poll interval.
              type: int
            minpoll: &minpoll
              description: configure Minimum poll interval.
              type: int
            prefer: &prefer
              description: Prefer this peer when possible
              type: bool
            version: &version
              description: NTP version.
              type: int
        peers:
          description: Configure NTP peer.
          type: list
          elements: dict
          suboptions:
            vrf: *vrf
            peer: *host
            burst: *burst
            iburst: *iburst
            key_id: *key
            source: *source
            maxpoll: *maxpoll
            minpoll: *minpoll
            prefer: *prefer
            version: *version
  running_config:
    description:
      - This option is used only with state I(parsed).
      - The value of this option should be the output received from the IOSXR device by
        executing the command B(show running-config ntp).
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into Ansible structured data as per the resource module's argspec
        and the value is then returned in the I(parsed) key within the result.
    type: str
  state:
    description:
      - The state the configuration should be left in.
    type: str
    choices:
      - deleted
      - merged
      - overridden
      - replaced
      - gathered
      - rendered
      - parsed
    default: merged
"""

EXAMPLES = """
# Using state: merged
# Before state:
# -------------
# RP/0/0/CPU0:10#show running-config ntp
# --------------------- EMPTY -----------------
# Merged play:
# ------------
- name: Merge the provided configuration with the existing running configuration
  cisco.iosxr.iosxr_ntp_global:
    config:
      access_group:
        ipv4:
          peer: PeerAcl1
          query_only: QueryOnlyAcl1
          serve: ServeAcl1
          serve_only: ServeOnlyAcl1
        vrfs:
          - ipv4:
              peer: PeerAcl3
              serve: ServeAcl2
            name: siteA
      authenticate: true
      broadcastdelay: 1
      drift:
        aging_time: 0
        file: apphost
      interfaces:
        - name: GigabitEthernet0/0/0/0
          multicast_client: 224.0.0.8
          multicast_destination: 224.0.0.8
          broadcast_client: true
      ipv4:
        dscp: af11
      ipv6:
        precedence: routine
      log_internal_sync: true
      master: 1
      max_associations: 10
      passive: true
      peers:
        - iburst: true
          peer: 192.0.2.1
          vrf: siteC
      servers:
        - burst: true
          server: 192.0.2.2
          vrf: siteD
      source: GigabitEthernet0/0/0/0
      source_vrfs:
        - name: GigabitEthernet0/0/0/0
          vrf: siteE
      trusted_keys:
        - key_id: 1
      update_calendar: true
# Commands Fired:
# ------------
# "commands": [
#         "ntp peer vrf siteC 192.0.2.1 iburst ",
#         "ntp server vrf siteD 192.0.2.2 burst ",
#         "ntp trusted-key 1",
#         "ntp interface GigabitEthernet0/0/0/0 broadcast client",
#         "ntp interface GigabitEthernet0/0/0/0 multicast destination 224.0.0.8",
#         "ntp interface GigabitEthernet0/0/0/0 multicast client 224.0.0.8",
#         "ntp vrf siteE source GigabitEthernet0/0/0/0",
#         "ntp access-group vrf siteA ipv4 serve ServeAcl2",
#         "ntp access-group vrf siteA ipv4 peer PeerAcl3",
#         "ntp access-group ipv4 peer PeerAcl1",
#         "ntp access-group ipv4 serve ServeAcl1",
#         "ntp access-group ipv4 serve-only ServeOnlyAcl1",
#         "ntp access-group ipv4 query-only QueryOnlyAcl1",
#         "ntp authenticate",
#         "ntp log-internal-sync",
#         "ntp broadcastdelay 1",
#         "ntp drift aging time 0",
#         "ntp drift file apphost",
#         "ntp ipv4 dscp af11",
#         "ntp ipv6 precedence routine",
#         "ntp max-associations 10",
#         "ntp master 1",
#         "ntp passive",
#         "ntp update-calendar",
#         "ntp source GigabitEthernet0/0/0/0"
#     ],
# After state:
# ------------
# RP/0/0/CPU0:10#show running-config ntp
# ntp
#  max-associations 10
#  interface GigabitEthernet0/0/0/0
#   broadcast client
#   multicast client 224.0.0.8
#   multicast destination 224.0.0.8
#  !
#  authenticate
#  trusted-key 1
#  ipv4 dscp af11
#  ipv6 precedence routine
#  peer vrf siteC 192.0.2.1 iburst
#  server vrf siteD 192.0.2.2 burst
#  drift file apphost
#  drift aging time 0
#  master 1
#  access-group vrf siteA ipv4 peer PeerAcl3
#  access-group vrf siteA ipv4 serve ServeAcl2
#  access-group ipv4 peer PeerAcl1
#  access-group ipv4 serve ServeAcl1
#  access-group ipv4 serve-only ServeOnlyAcl1
#  access-group ipv4 query-only QueryOnlyAcl1
#  source vrf siteE GigabitEthernet0/0/0/0
#  source GigabitEthernet0/0/0/0
#  passive
#  broadcastdelay 1
#  update-calendar
#  log-internal-sync
# !
# Using state: deleted
# Before state:
# -------------
# RP/0/0/CPU0:10#show running-config ntp
# ntp
#  max-associations 10
#  interface GigabitEthernet0/0/0/0
#   broadcast client
#   multicast client 224.0.0.8
#   multicast destination 224.0.0.8
#  !
#  authenticate
#  trusted-key 1
#  ipv4 dscp af11
#  ipv6 precedence routine
#  peer vrf siteC 192.0.2.1 iburst
#  server vrf siteD 192.0.2.2 burst
#  drift file apphost
#  drift aging time 0
#  master 1
#  access-group vrf siteA ipv4 peer PeerAcl3
#  access-group vrf siteA ipv4 serve ServeAcl2
#  access-group ipv4 peer PeerAcl1
#  access-group ipv4 serve ServeAcl1
#  access-group ipv4 serve-only ServeOnlyAcl1
#  access-group ipv4 query-only QueryOnlyAcl1
#  source vrf siteE GigabitEthernet0/0/0/0
#  source GigabitEthernet0/0/0/0
#  passive
#  broadcastdelay 1
#  update-calendar
#  log-internal-sync
# !
# Deleted play:
# -------------
- name: Remove all existing configuration
  cisco.iosxr.iosxr_ntp_global:
    state: deleted
# Commands Fired:
# ---------------
# "commands": [
#         "no ntp peer vrf siteC 192.0.2.1 iburst ",
#         "no ntp server vrf siteD 192.0.2.2 burst ",
#         "no ntp trusted-key 1",
#         "no ntp interface GigabitEthernet0/0/0/0",
#         "no ntp vrf siteE source GigabitEthernet0/0/0/0",
#         "no ntp access-group vrf siteA ipv4 serve ServeAcl2",
#         "no ntp access-group vrf siteA ipv4 peer PeerAcl3",
#         "no ntp access-group ipv4 peer PeerAcl1",
#         "no ntp access-group ipv4 serve ServeAcl1",
#         "no ntp access-group ipv4 serve-only ServeOnlyAcl1",
#         "no ntp access-group ipv4 query-only QueryOnlyAcl1",
#         "no ntp authenticate",
#         "no ntp log-internal-sync",
#         "no ntp broadcastdelay 1",
#         "no ntp drift aging time 0",
#         "no ntp drift file apphost",
#         "no ntp ipv4 dscp af11",
#         "no ntp ipv6 precedence routine",
#         "no ntp max-associations 10",
#         "no ntp master 1",
#         "no ntp passive",
#         "no ntp update-calendar",
#         "no ntp source GigabitEthernet0/0/0/0"
#     ],
# After state:
# ------------
# RP/0/0/CPU0:10#show running-config ntp
# --------------------- EMPTY -----------------
# Using state: overridden
# Before state:
# -------------
# RP/0/0/CPU0:10#show running-config ntp
# ntp
#  max-associations 10
#  interface GigabitEthernet0/0/0/0
#   broadcast client
#   multicast client 224.0.0.8
#   multicast destination 224.0.0.8
#  !
#  authenticate
#  trusted-key 1
#  ipv4 dscp af11
#  ipv6 precedence routine
#  peer vrf siteC 192.0.2.1 iburst
#  server vrf siteD 192.0.2.2 burst
#  drift file apphost
#  drift aging time 0
#  master 1
#  access-group vrf siteA ipv4 peer PeerAcl3
#  access-group vrf siteA ipv4 serve ServeAcl2
#  access-group ipv4 peer PeerAcl1
#  access-group ipv4 serve ServeAcl1
#  access-group ipv4 serve-only ServeOnlyAcl1
#  access-group ipv4 query-only QueryOnlyAcl1
#  source vrf siteE GigabitEthernet0/0/0/0
#  source GigabitEthernet0/0/0/0
#  passive
#  broadcastdelay 1
#  update-calendar
#  log-internal-sync
# !
# Overridden play:
# ----------------
- name: Override BGP configuration with provided configuration
  cisco.iosxr.iosxr_ntp_global:
    state: overridden
    config:
      access_group:
        ipv4:
          peer: PeerAcl1
          query_only: QueryOnlyAcl1
          serve: ServeAcl4
          serve_only: ServeOnlyAcl1
        vrfs:
          - ipv4:
              peer: PeerAcl3
              serve: ServeAcl2
            name: siteA
      authenticate: true
      broadcastdelay: 1
      drift:
        aging_time: 0
        file: apphost
      interfaces:
        - name: GigabitEthernet0/0/0/1
          multicast_client: 224.0.0.8
          multicast_destination: 224.0.0.8
          broadcast_client: true
      ipv4:
        dscp: af12
      ipv6:
        precedence: routine
      log_internal_sync: true
      master: 1
      max_associations: 10
      passive: true
      peers:
        - iburst: true
          peer: 192.0.2.3
          vrf: siteC
      servers:
        - burst: true
          server: 192.0.2.2
          vrf: siteD
      source: GigabitEthernet0/0/0/1
      source_vrfs:
        - name: GigabitEthernet0/0/0/0
          vrf: siteE
      trusted_keys:
        - key_id: 1
      update_calendar: true
# Commands Fired:
# ---------------
# "commands": [
#         "no ntp peer vrf siteC 192.0.2.1 iburst ",
#         "no ntp interface GigabitEthernet0/0/0/0",
#         "ntp peer vrf siteC 192.0.2.3 iburst ",
#         "ntp interface GigabitEthernet0/0/0/1 broadcast client",
#         "ntp interface GigabitEthernet0/0/0/1 multicast destination 224.0.0.8",
#         "ntp interface GigabitEthernet0/0/0/1 multicast client 224.0.0.8",
#         "ntp access-group ipv4 serve ServeAcl4",
#         "ntp ipv4 dscp af12",
#         "ntp source GigabitEthernet0/0/0/1"
#     ],
# After state:
# ------------
# RP/0/RP0/CPU0:ios#show running-config ntp
# Mon Sep 13 10:38:22.690 UTC
# ntp
#  max-associations 10
#  interface GigabitEthernet0/0/0/1
#   broadcast client
#   multicast client 224.0.0.8
#   multicast destination 224.0.0.8
#  !
#  authentication-key 1 md5 encrypted testkey
#  authenticate
#  trusted-key 1
#  ipv4 dscp af12
#  ipv6 precedence routine
#  peer vrf siteC 192.0.2.3 iburst
#  server vrf siteD 192.0.2.2 burst
#  drift file apphost
#  drift aging time 0
#  master 1
#  access-group vrf siteA ipv4 peer PeerAcl3
#  access-group vrf siteA ipv4 serve ServeAcl2
#  access-group ipv4 peer PeerAcl1
#  access-group ipv4 serve ServeAcl4
#  access-group ipv4 serve-only ServeOnlyAcl1
#  access-group ipv4 query-only QueryOnlyAcl1
#  source vrf siteE GigabitEthernet0/0/0/0
#  source GigabitEthernet0/0/0/1
#  passive
#  broadcastdelay 1
#  update-calendar
#  log-internal-sync
# !
#
# Using state: replaced
# Before state:
# -------------
# RP/0/0/CPU0:10#show running-config ntp
# ntp
#  max-associations 10
#  interface GigabitEthernet0/0/0/0
#   broadcast client
#   multicast client 224.0.0.8
#   multicast destination 224.0.0.8
#  !
#  authenticate
#  trusted-key 1
#  ipv4 dscp af11
#  ipv6 precedence routine
#  peer vrf siteC 192.0.2.1 iburst
#  server vrf siteD 192.0.2.2 burst
#  drift file apphost
#  drift aging time 0
#  master 1
#  access-group vrf siteA ipv4 peer PeerAcl3
#  access-group vrf siteA ipv4 serve ServeAcl2
#  access-group ipv4 peer PeerAcl1
#  access-group ipv4 serve ServeAcl1
#  access-group ipv4 serve-only ServeOnlyAcl1
#  access-group ipv4 query-only QueryOnlyAcl1
#  source vrf siteE GigabitEthernet0/0/0/0
#  source GigabitEthernet0/0/0/0
#  passive
#  broadcastdelay 1
#  update-calendar
#  log-internal-sync
# !
# Replaced play:
# ----------------
- name: Replaced BGP configuration with provided configuration
  cisco.iosxr.iosxr_ntp_global:
    state: replaced
    config:
      access_group:
        ipv4:
          peer: PeerAcl1
          query_only: QueryOnlyAcl1
          serve: ServeAcl4
          serve_only: ServeOnlyAcl1
        vrfs:
          - ipv4:
              peer: PeerAcl3
              serve: ServeAcl2
            name: siteA
      authenticate: true
      broadcastdelay: 1
      drift:
        aging_time: 0
        file: apphost
      interfaces:
        - name: GigabitEthernet0/0/0/1
          multicast_client: 224.0.0.8
          multicast_destination: 224.0.0.8
          broadcast_client: true
      ipv4:
        dscp: af12
      ipv6:
        precedence: routine
      log_internal_sync: true
      master: 1
      max_associations: 10
      passive: true
      peers:
        - iburst: true
          peer: 192.0.2.3
          vrf: siteC
      servers:
        - burst: true
          server: 192.0.2.2
          vrf: siteD
      source: GigabitEthernet0/0/0/1
      source_vrfs:
        - name: GigabitEthernet0/0/0/0
          vrf: siteE
      trusted_keys:
        - key_id: 1
      update_calendar: true
# Commands Fired:
# ---------------
# "commands": [
#         "no ntp peer vrf siteC 192.0.2.1 iburst ",
#         "no ntp interface GigabitEthernet0/0/0/0",
#         "ntp peer vrf siteC 192.0.2.3 iburst ",
#         "ntp interface GigabitEthernet0/0/0/1 broadcast client",
#         "ntp interface GigabitEthernet0/0/0/1 multicast destination 224.0.0.8",
#         "ntp interface GigabitEthernet0/0/0/1 multicast client 224.0.0.8",
#         "ntp access-group ipv4 serve ServeAcl4",
#         "ntp ipv4 dscp af12",
#         "ntp source GigabitEthernet0/0/0/1"
#     ],
# After state:
# ------------
# RP/0/RP0/CPU0:ios#show running-config ntp
# Mon Sep 13 10:38:22.690 UTC
# ntp
#  max-associations 10
#  interface GigabitEthernet0/0/0/1
#   broadcast client
#   multicast client 224.0.0.8
#   multicast destination 224.0.0.8
#  !
#  authentication-key 1 md5 encrypted testkey
#  authenticate
#  trusted-key 1
#  ipv4 dscp af12
#  ipv6 precedence routine
#  peer vrf siteC 192.0.2.3 iburst
#  server vrf siteD 192.0.2.2 burst
#  drift file apphost
#  drift aging time 0
#  master 1
#  access-group vrf siteA ipv4 peer PeerAcl3
#  access-group vrf siteA ipv4 serve ServeAcl2
#  access-group ipv4 peer PeerAcl1
#  access-group ipv4 serve ServeAcl4
#  access-group ipv4 serve-only ServeOnlyAcl1
#  access-group ipv4 query-only QueryOnlyAcl1
#  source vrf siteE GigabitEthernet0/0/0/0
#  source GigabitEthernet0/0/0/1
#  passive
#  broadcastdelay 1
#  update-calendar
#  log-internal-sync
# !
# Using state: gathered
# Before state:
# -------------
# RP/0/0/CPU0:10#show running-config ntp
# ntp
#  max-associations 10
#  interface GigabitEthernet0/0/0/0
#   broadcast client
#   multicast client 224.0.0.8
#   multicast destination 224.0.0.8
#  !
#  authenticate
#  trusted-key 1
#  ipv4 dscp af11
#  ipv6 precedence routine
#  peer vrf siteC 192.0.2.1 iburst
#  server vrf siteD 192.0.2.2 burst
#  drift file apphost
#  drift aging time 0
#  master 1
#  access-group vrf siteA ipv4 peer PeerAcl3
#  access-group vrf siteA ipv4 serve ServeAcl2
#  access-group ipv4 peer PeerAcl1
#  access-group ipv4 serve ServeAcl1
#  access-group ipv4 serve-only ServeOnlyAcl1
#  access-group ipv4 query-only QueryOnlyAcl1
#  source vrf siteE GigabitEthernet0/0/0/0
#  source GigabitEthernet0/0/0/0
#  passive
#  broadcastdelay 1
#  update-calendar
#  log-internal-sync
# !
# Gathered play:
# --------------
- name: Gather listed ntp config
  cisco.iosxr.iosxr_ntp_global:
    state: gathered
# Module Execution Result:
# ------------------------
# "gathered":{
#         "access_group": {
#             "ipv4": {
#                 "peer": "PeerAcl1",
#                 "query_only": "QueryOnlyAcl1",
#                 "serve": "ServeAcl1",
#                 "serve_only": "ServeOnlyAcl1"
#             },
#             "vrfs": [
#                 {
#                     "ipv4": {
#                         "peer": "PeerAcl3",
#                         "serve": "ServeAcl2"
#                     },
#                     "name": "siteA"
#                 }
#             ]
#         },
#         "authenticate": true,
#         "broadcastdelay": 1,
#         "drift": {
#             "aging_time": 0,
#             "file": "apphost"
#         },
#         "interfaces": [
#             {
#                 "broadcast_client": true,
#                 "multicast_client": "224.0.0.8",
#                 "multicast_destination": "224.0.0.8",
#                 "name": "GigabitEthernet0/0/0/0"
#             }
#         ],
#         "ipv4": {
#             "dscp": "af11"
#         },
#         "ipv6": {
#             "precedence": "routine"
#         },
#         "log_internal_sync": true,
#         "master": 1,
#         "max_associations": 10,
#         "passive": true,
#         "peers": [
#             {
#                 "iburst": true,
#                 "peer": "192.0.2.1",
#                 "vrf": "siteC"
#             }
#         ],
#         "servers": [
#             {
#                 "burst": true,
#                 "server": "192.0.2.2",
#                 "vrf": "siteD"
#             }
#         ],
#         "source": "GigabitEthernet0/0/0/0",
#         "source_vrfs": [
#             {
#                 "name": "GigabitEthernet0/0/0/0",
#                 "vrf": "siteE"
#             }
#         ],
#         "trusted_keys": [
#             {
#                 "key_id": 1
#             }
#         ],
#         "update_calendar": true
#     }
# Using state: rendered
# Rendered play:
# --------------
- name: >-
    Render platform specific configuration lines with state rendered (without
    connecting to the device)
  cisco.iosxr.iosxr_ntp_global:
    state: rendered
    config:
      access_group:
        ipv4:
          peer: PeerAcl1
          query_only: QueryOnlyAcl1
          serve: ServeAcl1
          serve_only: ServeOnlyAcl1
        vrfs:
          - ipv4:
              peer: PeerAcl3
              serve: ServeAcl2
            name: siteA
      authenticate: true
      broadcastdelay: 1
      drift:
        aging_time: 0
        file: apphost
      interfaces:
        - name: GigabitEthernet0/0/0/0
          multicast_client: 224.0.0.8
          multicast_destination: 224.0.0.8
          broadcast_client: true
      ipv4:
        dscp: af11
      ipv6:
        precedence: routine
      log_internal_sync: true
      master: 1
      max_associations: 10
      passive: true
      peers:
        - iburst: true
          peer: 192.0.2.1
          vrf: siteC
      servers:
        - burst: true
          server: 192.0.2.2
          vrf: siteD
      source: GigabitEthernet0/0/0/0
      source_vrfs:
        - name: GigabitEthernet0/0/0/0
          vrf: siteE
      trusted_keys:
        - key_id: 1
      update_calendar: true
  register: result
# Module Execution Result:
# ------------------------
# "rendered": [
#         "ntp peer vrf siteC 192.0.2.1 iburst ",
#         "ntp server vrf siteD 192.0.2.2 burst ",
#         "ntp trusted-key 1",
#         "ntp interface GigabitEthernet0/0/0/0 broadcast client",
#         "ntp interface GigabitEthernet0/0/0/0 multicast destination 224.0.0.8",
#         "ntp interface GigabitEthernet0/0/0/0 multicast client 224.0.0.8",
#         "ntp vrf siteE source GigabitEthernet0/0/0/0",
#         "ntp access-group vrf siteA ipv4 serve ServeAcl2",
#         "ntp access-group vrf siteA ipv4 peer PeerAcl3",
#         "ntp access-group ipv4 peer PeerAcl1",
#         "ntp access-group ipv4 serve ServeAcl1",
#         "ntp access-group ipv4 serve-only ServeOnlyAcl1",
#         "ntp access-group ipv4 query-only QueryOnlyAcl1",
#         "ntp authenticate",
#         "ntp log-internal-sync",
#         "ntp broadcastdelay 1",
#         "ntp drift aging time 0",
#         "ntp drift file apphost",
#         "ntp ipv4 dscp af11",
#         "ntp ipv6 precedence routine",
#         "ntp max-associations 10",
#         "ntp master 1",
#         "ntp passive",
#         "ntp update-calendar",
#         "ntp source GigabitEthernet0/0/0/0"
#     ],
# Using state: parsed
# File: parsed.cfg
# ----------------
# ntp
#  max-associations 10
#  interface GigabitEthernet0/0/0/0
#   broadcast client
#   multicast client 224.0.0.8
#   multicast destination 224.0.0.8
#  !
#  authenticate
#  trusted-key 1
#  ipv4 dscp af11
#  ipv6 precedence routine
#  peer vrf siteC 192.0.2.1 iburst
#  server vrf siteD 192.0.2.2 burst
#  drift file apphost
#  drift aging time 0
#  master 1
#  access-group vrf siteA ipv4 peer PeerAcl3
#  access-group vrf siteA ipv4 serve ServeAcl2
#  access-group ipv4 peer PeerAcl1
#  access-group ipv4 serve ServeAcl1
#  access-group ipv4 serve-only ServeOnlyAcl1
#  access-group ipv4 query-only QueryOnlyAcl1
#  source vrf siteE GigabitEthernet0/0/0/0
#  source GigabitEthernet0/0/0/0
#  passive
#  broadcastdelay 1
#  update-calendar
#  log-internal-sync
# !
# Parsed play:
# ------------
- name: Parse the provided configuration with the existing running configuration
  cisco.iosxr.iosxr_ntp_global:
    running_config: "{{ lookup('file', 'parsed.cfg') }}"
    state: parsed
# Module Execution Result:
# ------------------------
# "parsed":{
#         "access_group": {
#             "ipv4": {
#                 "peer": "PeerAcl1",
#                 "query_only": "QueryOnlyAcl1",
#                 "serve": "ServeAcl1",
#                 "serve_only": "ServeOnlyAcl1"
#             },
#             "vrfs": [
#                 {
#                     "ipv4": {
#                         "peer": "PeerAcl3",
#                         "serve": "ServeAcl2"
#                     },
#                     "name": "siteA"
#                 }
#             ]
#         },
#         "authenticate": true,
#         "broadcastdelay": 1,
#         "drift": {
#             "aging_time": 0,
#             "file": "apphost"
#         },
#         "interfaces": [
#             {
#                 "broadcast_client": true,
#                 "multicast_client": "224.0.0.8",
#                 "multicast_destination": "224.0.0.8",
#                 "name": "GigabitEthernet0/0/0/0"
#             }
#         ],
#         "ipv4": {
#             "dscp": "af11"
#         },
#         "ipv6": {
#             "precedence": "routine"
#         },
#         "log_internal_sync": true,
#         "master": 1,
#         "max_associations": 10,
#         "passive": true,
#         "peers": [
#             {
#                 "iburst": true,
#                 "peer": "192.0.2.1",
#                 "vrf": "siteC"
#             }
#         ],
#         "servers": [
#             {
#                 "burst": true,
#                 "server": "192.0.2.2",
#                 "vrf": "siteD"
#             }
#         ],
#         "source": "GigabitEthernet0/0/0/0",
#         "source_vrfs": [
#             {
#                 "name": "GigabitEthernet0/0/0/0",
#                 "vrf": "siteE"
#             }
#         ],
#         "trusted_keys": [
#             {
#                 "key_id": 1
#             }
#         ],
#         "update_calendar": true
#     }
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

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.ntp_global.ntp_global import (
    Ntp_globalArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.config.ntp_global.ntp_global import (
    Ntp_global,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=Ntp_globalArgs.argument_spec,
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

    result = Ntp_global(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
