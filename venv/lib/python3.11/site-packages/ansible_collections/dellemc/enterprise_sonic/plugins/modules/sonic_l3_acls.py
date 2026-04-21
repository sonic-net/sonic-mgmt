#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_l3_acls
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_l3_acls
version_added: '2.1.0'
notes:
  - Supports C(check_mode).
short_description: Manage Layer 3 access control lists (ACL) configurations on SONiC
description:
  - This module provides configuration management of Layer 3 access control lists (ACL)
    in devices running SONiC.
author: 'Arun Saravanan Balachandran (@ArunSaravananBalachandran)'
options:
  config:
    description:
      - Specifies Layer 3 ACL configurations.
    type: list
    elements: dict
    suboptions:
      address_family:
        description:
          - Specifies the address family of the ACLs.
        type: str
        required: true
        choices:
          - ipv4
          - ipv6
      acls:
        description:
          - List of ACL configuration for the given address family.
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Specifies the ACL name.
            type: str
            required: true
          remark:
            description:
              - Specifies remark for the ACL.
            type: str
          rules:
            description:
              - List of rules with the ACL.
              - I(sequence_num), I(action), I(protocol), I(source) & I(destination) are required for adding a new rule.
              - If I(state=deleted), options other than I(sequence_num) are not considered.
            type: list
            elements: dict
            suboptions:
              sequence_num:
                description:
                  - Specifies the sequence number of the rule.
                  - The range is from 1 to 65535.
                type: int
                required: true
              action:
                description:
                  - Specifies the action taken on the matched packet.
                type: str
                choices:
                  - deny
                  - discard
                  - do-not-nat
                  - permit
                  - transit
              protocol:
                description:
                  - Specifies the protocol to match.
                  - Only one suboption can be specified for protocol in a rule.
                type: dict
                suboptions:
                  name:
                    description:
                      - Match packets with the given protocol.
                      - C(ip) - Match any IPv4 packets.
                      - C(ipv6) - Match any IPv6 packets.
                      - C(icmp) - Match ICMP packets.
                      - C(icmpv6) - Match ICMPv6 packets.
                      - C(tcp) - Match TCP packets.
                      - C(udp) - Match UDP packets.
                      - C(ip) and C(icmp) are valid only for IPv4 ACLs.
                      - C(ipv6) and C(icmpv6) are valid only for IPv6 ACLs.
                    type: str
                    choices:
                      - ip
                      - ipv6
                      - icmp
                      - icmpv6
                      - tcp
                      - udp
                  number:
                    description:
                      - Match packets with given protocol number.
                      - The range is from 0 to 255.
                    type: int
              source:
                description:
                  - Specifies the source of the packet.
                  - I(any), I(host) and I(prefix) are mutually exclusive.
                type: dict
                suboptions:
                  any:
                    description:
                      - Match any source network address.
                    type: bool
                  host:
                    description:
                      - Network address of a single source host.
                    type: str
                  prefix:
                    description:
                      - Source network prefix in the format A.B.C.D/mask (ipv4) or A::B/mask (ipv6).
                    type: str
                  port_number:
                    description:
                      - Specifies the source port (valid only for TCP or UDP)
                      - Only one suboption can be specified for port_number in a rule.
                    type: dict
                    suboptions:
                      eq:
                        description:
                          - Match packets with source port equal to the given port number.
                          - The range is from 0 to 65535.
                        type: int
                      gt:
                        description:
                          - Match packets with source port greater than the given port number.
                          - The range is from 0 to 65534.
                        type: int
                      lt:
                        description:
                          - Match packets with source port lesser than the given port number.
                          - The range is from 1 to 65535.
                        type: int
                      range:
                        description:
                          - Match packets with source port in the given range.
                          - I(begin) and I(end) are required together.
                        type: dict
                        suboptions:
                          begin:
                            description:
                              - Specifies the beginning of the port range.
                              - The range is from 0 to 65534.
                            type: int
                          end:
                            description:
                              - Specifies the end of the port range.
                              - The range is from 1 to 65535.
                            type: int
              destination:
                description:
                  - Specifies the destination of the packet.
                  - I(any), I(host) and I(prefix) are mutually exclusive.
                type: dict
                suboptions:
                  any:
                    description:
                      - Match any destination network address.
                    type: bool
                  host:
                    description:
                      - Network address of a single destination host.
                    type: str
                  prefix:
                    description:
                      - Destination network prefix in the format A.B.C.D/mask (ipv4) or A::B/mask (ipv6).
                    type: str
                  port_number:
                    description:
                      - Specifies the destination port (valid only for TCP or UDP)
                      - Only one suboption can be specified for port_number in a rule.
                    type: dict
                    suboptions:
                      eq:
                        description:
                          - Match packets with destination port equal to the given port number.
                          - The range is from 0 to 65535.
                        type: int
                      gt:
                        description:
                          - Match packets with destination port greater than the given port number.
                          - The range is from 0 to 65534.
                        type: int
                      lt:
                        description:
                          - Match packets with destination port lesser than the given port number.
                          - The range is from 1 to 65535.
                        type: int
                      range:
                        description:
                          - Match packets with destination port in the given range.
                          - I(begin) and I(end) are required together.
                        type: dict
                        suboptions:
                          begin:
                            description:
                              - Specifies the beginning of the port range.
                              - The range is from 0 to 65534.
                            type: int
                          end:
                            description:
                              - Specifies the end of the port range.
                              - The range is from 1 to 65535.
                            type: int
              protocol_options:
                description:
                  - Specifies the additional packet match options for the chosen protocol.
                  - I(icmp), I(icmpv6) and I(tcp) are mutually exclusive.
                type: dict
                suboptions:
                  icmp:
                    description:
                      - Packet match options for ICMP.
                    type: dict
                    suboptions:
                      code:
                        description:
                          - Match packets with given ICMP code.
                          - The range is from 0 to 255.
                        type: int
                      type:
                        description:
                          - Match packets with given ICMP type.
                          - The range is from 0 to 255.
                        type: int
                  icmpv6:
                    description:
                      - Packet match options for ICMPv6.
                    type: dict
                    suboptions:
                      code:
                        description:
                          - Match packets with given ICMPv6 code.
                          - The range is from 0 to 255.
                        type: int
                      type:
                        description:
                          - Match packets with given ICMPv6 type.
                          - The range is from 0 to 255.
                        type: int
                  tcp:
                    description:
                      - Packet match options for TCP.
                      - I(established) and other TCP flag options are mutually exclusive.
                    type: dict
                    suboptions:
                      established:
                        description:
                          - Match packets which are part of established TCP session.
                        type: bool
                      ack:
                        description:
                          - Match packets with ACK flag set.
                        type: bool
                      not_ack:
                        description:
                          - Match packets with ACK flag cleared.
                        type: bool
                      fin:
                        description:
                          - Match packets with FIN flag set.
                        type: bool
                      not_fin:
                        description:
                          - Match packets with FIN flag cleared.
                        type: bool
                      psh:
                        description:
                          - Match packets with PSH flag set.
                        type: bool
                      not_psh:
                        description:
                          - Match packets with PSH flag cleared.
                        type: bool
                      rst:
                        description:
                          - Match packets with RST flag set.
                        type: bool
                      not_rst:
                        description:
                          - Match packets with RST flag cleared.
                        type: bool
                      syn:
                        description:
                          - Match packets with SYN flag set.
                        type: bool
                      not_syn:
                        description:
                          - Match packets with SYN flag cleared.
                        type: bool
                      urg:
                        description:
                          - Match packets with URG flag set.
                        type: bool
                      not_urg:
                        description:
                          - Match packets with URG flag cleared.
                        type: bool
              vlan_id:
                description:
                  - Match packets with the given VLAN ID value.
                type: int
              dscp:
                description:
                  - Match packets using DSCP value.
                  - Only one suboption can be specified for dscp in a rule.
                type: dict
                suboptions:
                  value:
                    description:
                      - Match packets with given DSCP value.
                      - The range is from 0 to 63.
                    type: int
                  af11:
                    description:
                      - Match packets with AF11 DSCP (001010 - Decimal value 10).
                    type: bool
                  af12:
                    description:
                      - Match packets with AF12 DSCP (001100 - Decimal value 12).
                    type: bool
                  af13:
                    description:
                      - Match packets with AF13 DSCP (001110 - Decimal value 14).
                    type: bool
                  af21:
                    description:
                      - Match packets with AF21 DSCP (010010 - Decimal value 18).
                    type: bool
                  af22:
                    description:
                      - Match packets with AF22 DSCP (010100 - Decimal value 20).
                    type: bool
                  af23:
                    description:
                      - Match packets with AF23 DSCP (010110 - Decimal value 22).
                    type: bool
                  af31:
                    description:
                      - Match packets with AF31 DSCP (011010 - Decimal value 26).
                    type: bool
                  af32:
                    description:
                      - Match packets with AF32 DSCP (011100 - Decimal value 28).
                    type: bool
                  af33:
                    description:
                      - Match packets with AF33 DSCP (011110 - Decimal value 30).
                    type: bool
                  af41:
                    description:
                      - Match packets with AF41 DSCP (100010 - Decimal value 34).
                    type: bool
                  af42:
                    description:
                      - Match packets with AF42 DSCP (100100 - Decimal value 36).
                    type: bool
                  af43:
                    description:
                      - Match packets with AF43 DSCP (100110 - Decimal value 38).
                    type: bool
                  cs1:
                    description:
                      - Match packets with CS1 DSCP (001000 - Decimal value 8).
                    type: bool
                  cs2:
                    description:
                      - Match packets with CS2 DSCP (010000 - Decimal value 16).
                    type: bool
                  cs3:
                    description:
                      - Match packets with CS3 DSCP (011000 - Decimal value 24).
                    type: bool
                  cs4:
                    description:
                      - Match packets with CS4 DSCP (100000 - Decimal value 32).
                    type: bool
                  cs5:
                    description:
                      - Match packets with CS5 DSCP (101000 - Decimal value 40).
                    type: bool
                  cs6:
                    description:
                      - Match packets with CS6 DSCP (110000 - Decimal value 48).
                    type: bool
                  cs7:
                    description:
                      - Match packets with CS7 DSCP (111000 - Decimal value 56).
                    type: bool
                  default:
                    description:
                      - Match packets with CS0 DSCP (000000 - Decimal value 0).
                    type: bool
                  ef:
                    description:
                      - Match packets with EF DSCP (101110 - Decimal value 46).
                    type: bool
                  voice_admit:
                    description:
                      - Match packets with VOICE-ADMIT DSCP (101100 - Decimal value 44).
                    type: bool
              remark:
                description:
                  - Specifies remark for the ACL rule.
                type: str
  state:
    description:
      - The state of the configuration after module completion.
      - C(merged) - Merges provided L3 ACL configuration with on-device configuration.
      - C(replaced) - Replaces on-device configuration of the specified L3 ACLs with provided configuration.
      - C(overridden) - Overrides all on-device L3 ACL configurations with the provided configuration.
      - C(deleted) - Deletes on-device L3 ACL configuration.
    type: str
    choices:
      - merged
      - replaced
      - overridden
      - deleted
    default: merged
"""

EXAMPLES = """
# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration ip access-list
# !
# ip access-list test
#  seq 1 permit ip host 192.168.1.2 any
# sonic#
# sonic# show running-configuration ipv6 access-list
# !
# ipv6 access-list testv6
#  seq 1 permit ipv6 host 192:168:1::2 any
# sonic#

- name: Merge provided Layer 3 ACL configurations
  dellemc.enterprise_sonic.sonic_l3_acls:
    config:
      - address_family: 'ipv4'
        acls:
          - name: 'test'
            rules:
              - sequence_num: 2
                action: 'permit'
                protocol:
                  name: 'icmp'
                source:
                  any: true
                destination:
                  host: '192.168.1.2'
                protocol_options:
                  icmp:
                    type: 8
              - sequence_num: 3
                action: 'deny'
                protocol:
                  number: 2
                source:
                  any: true
                destination:
                  any: true
              - sequence_num: 4
                action: 'deny'
                protocol:
                  name: 'ip'
                source:
                  any: true
                destination:
                  any: true
                vlan_id: 10
                remark: 'Vlan10'
          - name: 'test1'
            remark: 'test_ip_acl'
            rules:
              - sequence_num: 1
                action: 'permit'
                protocol:
                  name: 'tcp'
                source:
                  prefix: '10.0.0.0/8'
                destination:
                  any: true
              - sequence_num: 2
                action: 'deny'
                protocol:
                  name: 'udp'
                source:
                  any: true
                destination:
                  prefix: '20.1.0.0/16'
                  port_number:
                    gt: 1024
              - sequence_num: 3
                action: 'deny'
                protocol:
                  name: 'ip'
                source:
                  any: true
                destination:
                  any: true
                dscp:
                  value: 63
      - address_family: 'ipv6'
        acls:
          - name: 'testv6'
            rules:
              - sequence_num: 2
                action: 'deny'
                protocol:
                  name: 'icmpv6'
                source:
                  any: true
                destination:
                  any: true
          - name: 'testv6-1'
            remark: 'test_ipv6_acl'
            rules:
              - sequence_num: 1
                action: 'permit'
                protocol:
                  name: 'ipv6'
                source:
                  prefix: '1000::/16'
                destination:
                  any: true
                dscp:
                  af22: true
              - sequence_num: 2
                action: 'deny'
                protocol:
                  name: 'tcp'
                source:
                  any: true
                destination:
                  prefix: '2000::1000:0/112'
                  port_number:
                    range:
                      begin: 100
                      end: 1000
              - sequence_num: 3
                action: 'permit'
                protocol:
                  name: 'tcp'
                source:
                  any: true
                destination:
                  any: true
                protocol_options:
                  tcp:
                    established: true
              - sequence_num: 4
                action: 'deny'
                protocol:
                  name: 'udp'
                source:
                  any: true
                  port_number:
                    eq: 3000
                destination:
                  any: true
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration ip access-list
# !
# ip access-list test
#  seq 1 permit ip host 192.168.1.2 any
#  seq 2 permit icmp any host 192.168.1.2 type 8
#  seq 3 deny 2 any any
#  seq 4 deny ip any any vlan 10 remark Vlan10
# !
# ip access-list test1
#  remark test_ip_acl
#  seq 1 permit tcp 10.0.0.0/8 any
#  seq 2 deny udp any 20.1.0.0/16 gt 1024
#  seq 3 deny ip any any dscp 63
# sonic#
# sonic# show running-configuration ipv6 access-list
# !
# ipv6 access-list testv6
#  seq 1 permit ipv6 host 192:168:1::2 any
#  seq 2 deny icmpv6 any any
# !
# ipv6 access-list testv6-1
#  remark test_ipv6_acl
#  seq 1 permit ipv6 1000::/16 any dscp af22
#  seq 2 deny tcp any 2000::1000:0/112 range 100 1000
#  seq 3 permit tcp any any established
#  seq 4 deny udp any eq 3000 any
# sonic#


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration ip access-list
# !
# ip access-list test
#  seq 1 permit ip host 192.168.1.2 any
#  seq 2 permit icmp any host 192.168.1.2 type 8
#  seq 3 deny 2 any any
#  seq 4 deny ip any any vlan 10 remark Vlan10
# !
# ip access-list test1
#  remark test_ip_acl
#  seq 1 permit tcp 10.0.0.0/8 any
#  seq 2 deny udp any 20.1.0.0/16 gt 1024
#  seq 3 deny ip any any dscp 63
# sonic#
# sonic# show running-configuration ipv6 access-list
# !
# ipv6 access-list testv6
#  seq 1 permit tcp host 3000::1 any established
#  seq 2 permit udp any any
#  seq 3 deny icmpv6 any any
# !
# ipv6 access-list testv6-1
#  remark test_ipv6_acl
#  seq 1 permit ipv6 1000::/16 any dscp af22
#  seq 2 deny tcp any 2000::1000:0/112 range 100 1000
#  seq 3 permit tcp any any established
#  seq 4 deny udp any eq 3000 any
# sonic#

- name: Replace device configuration of specified Layer 3 ACLs with provided configuration
  dellemc.enterprise_sonic.sonic_l3_acls:
    config:
      - address_family: 'ipv4'
        acls:
          - name: 'test2'
            rules:
              - sequence_num: 1
                action: 'permit'
                protocol:
                  name: 'tcp'
                source:
                  prefix: '192.168.1.0/24'
                destination:
                  any: true
      - address_family: 'ipv6'
        acls:
          - name: 'testv6'
            rules:
              - sequence_num: 1
                action: 'permit'
                protocol:
                  name: 'tcp'
                source:
                  host: '3000::1'
                destination:
                  any: true
                protocol_options:
                  tcp:
                    ack: true
                    syn: true
                    fin: true
              - sequence_num: 2
                action: 'deny'
                protocol:
                  name: 'ipv6'
                source:
                  any: true
                destination:
                  any: true
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration ip access-list
# !
# ip access-list test
#  seq 1 permit ip host 192.168.1.2 any
#  seq 2 permit icmp any host 192.168.1.3 type 8
#  seq 3 deny 2 any any
#  seq 4 deny ip any any vlan 10 remark Vlan10
# !
# ip access-list test1
#  remark test_ip_acl
#  seq 1 permit tcp 10.0.0.0/8 any
#  seq 2 deny udp any 20.1.0.0/16 gt 1024
#  seq 3 deny ip any any dscp 63
# !
# ip access-list test2
#  seq 1 permit tcp 192.168.1.0/24 any
# sonic#
# sonic# show running-configuration ipv6 access-list
# !
# ipv6 access-list testv6
#  seq 1 permit tcp host 3000::1 any fin syn ack
#  seq 2 deny ipv6 any any
# !
# ipv6 access-list testv6-1
#  remark test_ipv6_acl
#  seq 1 permit ipv6 1000::/16 any dscp af22
#  seq 2 deny tcp any 2000::1000:0/112 range 100 1000
#  seq 3 permit tcp any any established
#  seq 4 deny udp any eq 3000 any
# sonic#


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show running-configuration ip access-list
# !
# ip access-list test
#  seq 1 permit ip host 192.168.1.2 any
#  seq 2 permit icmp any host 192.168.1.3 type 8
#  seq 3 deny 2 any any
#  seq 4 deny ip any any vlan 10 remark Vlan10
# !
# ip access-list test1
#  remark test_ip_acl
#  seq 1 permit tcp 10.0.0.0/8 any
#  seq 2 deny udp any 20.1.0.0/16 gt 1024
#  seq 3 deny ip any any dscp 63
# !
# ip access-list test2
#  seq 1 permit tcp 192.168.1.0/24 any
# sonic#
# sonic# show running-configuration ipv6 access-list
# !
# ipv6 access-list testv6
#  seq 1 permit tcp 3000::/16 any
#  seq 2 deny ipv6 any any
# !
# ipv6 access-list testv6-1
#  remark test_ipv6_acl
#  seq 1 permit ipv6 1000::/16 any dscp af22
#  seq 2 deny tcp any 2000::1000:0/112 range 100 1000
#  seq 3 permit tcp any any established
#  seq 4 deny udp any eq 3000 any
# sonic#

- name: Override device configuration of all Layer 3 ACLs with provided configuration
  dellemc.enterprise_sonic.sonic_l3_acls:
    config:
      - address_family: 'ipv4'
        acls:
          - name: 'test_acl'
            rules:
              - sequence_num: 1
                action: 'permit'
                protocol:
                  name: 'ip'
                source:
                  prefix: '100.1.1.0/24'
                destination:
                  prefix: '100.1.2.0/24'
              - sequence_num: 2
                action: 'deny'
                protocol:
                  name: 'udp'
                source:
                  any: true
                destination:
                  any: true
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration ip access-list
# !
# ip access-list test_acl
#  seq 1 permit ip 100.1.1.0/24 100.1.2.0/24
#  seq 2 deny udp any any
# sonic#
# sonic# show running-configuration ipv6 access-list
# sonic#


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration ip access-list
# !
# ip access-list test
#  seq 1 permit ip host 192.168.1.2 any
#  seq 2 permit icmp any host 192.168.1.3 type 8
#  seq 3 deny 2 any any
#  seq 4 deny ip any any vlan 10 remark Vlan10
# !
# ip access-list test1
#  remark test_ip_acl
#  seq 1 permit tcp 10.0.0.0/8 any
#  seq 2 deny udp any 20.1.0.0/16 gt 1024
#  seq 3 deny ip any any dscp 63
# !
# ip access-list test2
#  seq 1 permit tcp 192.168.1.0/24 any
# sonic#
# sonic# show running-configuration ipv6 access-list
# !
# ipv6 access-list testv6
#  seq 1 permit tcp 3000::/16 any
#  seq 2 deny ipv6 any any
# !
# ipv6 access-list testv6-1
#  remark test_ipv6_acl
#  seq 1 permit ipv6 1000::/16 any dscp af22
#  seq 2 deny tcp any 2000::1000:0/112 range 100 1000
#  seq 3 permit tcp any any established
#  seq 4 deny udp any eq 3000 any
# sonic#

- name: Delete specified Layer 3 ACLs, ACL remark and ACL rule entries
  dellemc.enterprise_sonic.sonic_l3_acls:
    config:
      - address_family: 'ipv4'
        acls:
          - name: 'test'
            rules:
              - sequence_num: 2
          - name: 'test2'
      - address_family: 'ipv6'
        acls:
          - name: 'testv6-1'
            remark: 'test_ipv6_acl'
            rules:
              - sequence_num: 3
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration ip access-list
# !
# ip access-list test
#  seq 1 permit ip host 192.168.1.2 any
#  seq 3 deny 2 any any
#  seq 4 deny ip any any vlan 10 remark Vlan10
# !
# ip access-list test1
#  remark test_ip_acl
#  seq 1 permit tcp 10.0.0.0/8 any
#  seq 2 deny udp any 20.1.0.0/16 gt 1024
#  seq 3 deny ip any any dscp 63
# sonic#
# sonic# show running-configuration ipv6 access-list
# !
# ipv6 access-list testv6
#  seq 1 permit tcp 3000::/16 any
#  seq 2 deny ipv6 any any
# !
# ipv6 access-list testv6-1
#  seq 1 permit ipv6 1000::/16 any dscp af22
#  seq 2 deny tcp any 2000::1000:0/112 range 100 1000
#  seq 4 deny udp any eq 3000 any
# sonic#


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration ip access-list
# !
# ip access-list test
#  seq 1 permit ip host 192.168.1.2 any
#  seq 2 permit icmp any host 192.168.1.3 type 8
#  seq 3 deny 2 any any
#  seq 4 deny ip any any vlan 10 remark Vlan10
# !
# ip access-list test1
#  remark test_ip_acl
#  seq 1 permit tcp 10.0.0.0/8 any
#  seq 2 deny udp any 20.1.0.0/16 gt 1024
#  seq 3 deny ip any any dscp 63
# !
# ip access-list test2
#  seq 1 permit tcp 192.168.1.0/24 any
# sonic#
# sonic# show running-configuration ipv6 access-list
# !
# ipv6 access-list testv6
#  seq 1 permit tcp 3000::/16 any
#  seq 2 deny ipv6 any any
# !
# ipv6 access-list testv6-1
#  remark test_ipv6_acl
#  seq 1 permit ipv6 1000::/16 any dscp af22
#  seq 2 deny tcp any 2000::1000:0/112 range 100 1000
#  seq 3 permit tcp any any established
#  seq 4 deny udp any eq 3000 any
# sonic#

- name: Delete all Layer 3 ACLs for an address-family
  dellemc.enterprise_sonic.sonic_l3_acls:
    config:
      - address_family: 'ipv4'
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration ip access-list
# sonic#
# sonic# show running-configuration ipv6 access-list
# !
# ipv6 access-list testv6
#  seq 1 permit tcp 3000::/16 any
#  seq 2 deny ipv6 any any
# !
# ipv6 access-list testv6-1
#  remark test_ipv6_acl
#  seq 1 permit ipv6 1000::/16 any dscp af22
#  seq 2 deny tcp any 2000::1000:0/112 range 100 1000
#  seq 3 permit tcp any any established
#  seq 4 deny udp any eq 3000 any
# sonic#


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration ip access-list
# !
# ip access-list test
#  seq 1 permit ip host 192.168.1.2 any
#  seq 2 permit icmp any host 192.168.1.3 type 8
#  seq 3 deny 2 any any
#  seq 4 deny ip any any vlan 10 remark Vlan10
# !
# ip access-list test1
#  remark test_ip_acl
#  seq 1 permit tcp 10.0.0.0/8 any
#  seq 2 deny udp any 20.1.0.0/16 gt 1024
#  seq 3 deny ip any any dscp 63
# !
# ip access-list test2
#  seq 1 permit tcp 192.168.1.0/24 any
# sonic#
# sonic# show running-configuration ipv6 access-list
# !
# ipv6 access-list testv6
#  seq 1 permit tcp 3000::/16 any
#  seq 2 deny ipv6 any any
# !
# ipv6 access-list testv6-1
#  remark test_ipv6_acl
#  seq 1 permit ipv6 1000::/16 any dscp af22
#  seq 2 deny tcp any 2000::1000:0/112 range 100 1000
#  seq 3 permit tcp any any established
#  seq 4 deny udp any eq 3000 any
# sonic#

- name: Delete all Layer 3 ACL configurations
  dellemc.enterprise_sonic.sonic_l3_acls:
    config:
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration ip access-list
# sonic#
# sonic# show running-configuration ipv6 access-list
# sonic#
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.l3_acls.l3_acls import L3_aclsArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.l3_acls.l3_acls import L3_acls


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=L3_aclsArgs.argument_spec,
                           supports_check_mode=True)

    result = L3_acls(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
