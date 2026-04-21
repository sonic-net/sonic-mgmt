#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for nxos_prefix_lists
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: nxos_prefix_lists
short_description: Prefix-Lists resource module.
description:
- This module manages prefix-lists configuration on devices running Cisco NX-OS.
version_added: 2.4.0
notes:
- Tested against NX-OS 9.3.6.
- Unsupported for Cisco MDS
- This module works with connection C(network_cli) and C(httpapi).
author: Nilashish Chakraborty (@NilashishC)
options:
  running_config:
    description:
    - This option is used only with state I(parsed).
    - The value of this option should be the output received from the NX-OS device
      by executing the command B(show running-config | section '^ip(.*) prefix-list').
    - The state I(parsed) reads the configuration from C(running_config) option and
      transforms it into Ansible structured data as per the resource module's argspec
      and the value is then returned in the I(parsed) key within the result.
    type: str
  config:
    description: A list of prefix-list configuration.
    type: list
    elements: dict
    suboptions:
      afi:
        description:
        - The Address Family Identifier (AFI) for the prefix-lists.
        type: str
        choices: ["ipv4", "ipv6"]
      prefix_lists:
        description: List of prefix-list configurations.
        type: list
        elements: dict
        suboptions:
          name:
            description: Name of the prefix-list.
            type: str
          description:
            description: Description of the prefix list
            type: str
          entries:
            description: List of configurations for the specified prefix-list
            type: list
            elements: dict
            suboptions:
              sequence:
                description: Sequence Number.
                type: int
              action:
                description: Prefix-List permit or deny.
                type: str
                choices: ["permit", "deny"]
              prefix:
                description: IP or IPv6 prefix in A.B.C.D/LEN or A:B::C:D/LEN format.
                type: str
              eq:
                description: Exact prefix length to be matched.
                type: int
              ge:
                description: Minimum prefix length to be matched.
                type: int
              le:
                description: Maximum prefix length to be matched.
                type: int
              mask:
                description: Explicit match mask.
                type: str
  state:
    description:
    - The state the configuration should be left in.
    - Refer to examples for more details.
    - With state I(replaced), for the listed prefix-lists,
      sequences that are in running-config but not in the task are negated.
    - With state I(overridden), all prefix-lists that are in running-config but
      not in the task are negated.
    - Please refer to examples for more details.
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
# nxos-9k-rdo# show running-config | section 'ip(.*) prefix-list'
# nxos-9k-rdo#

- name: Merge the provided configuration with the existing running configuration
  cisco.nxos.nxos_prefix_lists:
    config:
      - afi: ipv4
        prefix_lists:
          - name: AllowPrefix
            description: allows engineering IPv4 networks
            entries:
              - sequence: 10
                action: permit
                prefix: 192.0.2.0/23
                eq: 24
              - sequence: 20
                action: permit
                prefix: 198.51.100.128/26
          - name: DenyPrefix
            description: denies lab IPv4 networks
            entries:
              - sequence: 20
                action: deny
                prefix: 203.0.113.0/24
                le: 25

      - afi: ipv6
        prefix_lists:
          - name: AllowIPv6Prefix
            description: allows engineering IPv6 networks
            entries:
              - sequence: 8
                action: permit
                prefix: "2001:db8:400::/38"
              - sequence: 20
                action: permit
                prefix: "2001:db8:8000::/35"
                le: 37

# Task output
# -------------
# before: []
#
# commands:
#   - "ipv6 prefix-list AllowIPv6Prefix description allows engineering IPv6 networks"
#   - "ipv6 prefix-list AllowIPv6Prefix seq 8 permit 2001:db8:400::/38"
#   - "ipv6 prefix-list AllowIPv6Prefix seq 20 permit 2001:db8:8000::/35 le 37"
#   - "ip prefix-list AllowPrefix description allows engineering IPv4 networks"
#   - "ip prefix-list AllowPrefix seq 10 permit 192.0.2.0/23 eq 24"
#   - "ip prefix-list AllowPrefix seq 20 permit 198.51.100.128/26"
#   - "ip prefix-list DenyPrefix description denies lab IPv4 networks"
#   - "ip prefix-list DenyPrefix seq 20 deny 203.0.113.0/24 le 25"
#
# after:
#   - afi: ipv4
#     prefix_lists:
#       - description: allows engineering IPv4 networks
#         entries:
#           - sequence: 10
#             action: permit
#             prefix: 192.0.2.0/23
#             eq: 24
#           - sequence: 20
#             action: permit
#             prefix: 198.51.100.128/26
#         name: AllowPrefix
#       - description: denies lab IPv4 networks
#         entries:
#           - sequence: 20
#             action: deny
#             prefix: 203.0.113.0/24
#             le: 25
#         name: DenyPrefix
#
#   - afi: ipv6
#     prefix_lists:
#       - description: allows engineering IPv6 networks
#         entries:
#           - sequence: 8
#             action: permit
#             prefix: "2001:db8:400::/38"
#           - sequence: 20
#             action: permit
#             prefix: "2001:db8:8000::/35"
#             le: 37
#         name: AllowIPv6Prefix

# After state:
# ------------
# nxos-9k-rdo# show running-config | section 'ip(.*) prefix-list'
# ip prefix-list AllowPrefix description allows engineering IPv4 networks
# ip prefix-list AllowPrefix seq 10 permit 192.0.2.0/23 eq 24
# ip prefix-list AllowPrefix seq 20 permit 198.51.100.128/26
# ip prefix-list DenyPrefix description denies lab IPv4 networks
# ip prefix-list DenyPrefix seq 20 deny 203.0.113.0/24 le 25
# ipv6 prefix-list AllowIPv6Prefix description allows engineering IPv6 networks
# ipv6 prefix-list AllowIPv6Prefix seq 8 permit 2001:db8:400::/38
# ipv6 prefix-list AllowIPv6Prefix seq 20 permit 2001:db8:8000::/35 le 37

# Using replaced

# Before state:
# ------------
# nxos-9k-rdo# show running-config | section 'ip(.*) prefix-list'
# ip prefix-list AllowPrefix description allows engineering IPv4 networks
# ip prefix-list AllowPrefix seq 10 permit 192.0.2.0/23 eq 24
# ip prefix-list AllowPrefix seq 20 permit 198.51.100.128/26
# ip prefix-list DenyPrefix description denies lab IPv4 networks
# ip prefix-list DenyPrefix seq 20 deny 203.0.113.0/24 le 25
# ipv6 prefix-list AllowIPv6Prefix description allows engineering IPv6 networks
# ipv6 prefix-list AllowIPv6Prefix seq 8 permit 2001:db8:400::/38
# ipv6 prefix-list AllowIPv6Prefix seq 20 permit 2001:db8:8000::/35 le 37

- name: Replace prefix-lists configurations of listed prefix-lists with provided configurations
  cisco.nxos.nxos_prefix_lists:
    config:
      - afi: ipv4
        prefix_lists:
          - name: AllowPrefix
            description: allows engineering IPv4 networks
            entries:
              - sequence: 10
                action: permit
                prefix: 203.0.113.64/27

              - sequence: 30
                action: permit
                prefix: 203.0.113.96/27
          - name: AllowPrefix2Stub
            description: allow other engineering IPv4 network
    state: replaced

# Task output
# -------------
# before:
#   - afi: ipv4
#     prefix_lists:
#       - description: allows engineering IPv4 networks
#         entries:
#           - sequence: 10
#             action: permit
#             prefix: 192.0.2.0/23
#             eq: 24
#           - sequence: 20
#             action: permit
#             prefix: 198.51.100.128/26
#         name: AllowPrefix
#       - description: denies lab IPv4 networks
#         entries:
#           - sequence: 20
#             action: deny
#             prefix: 203.0.113.0/24
#             le: 25
#         name: DenyPrefix
#
#   - afi: ipv6
#     prefix_lists:
#       - description: allows engineering IPv6 networks
#         entries:
#           - sequence: 8
#             action: permit
#             prefix: "2001:db8:400::/38"
#           - sequence: 20
#             action: permit
#             prefix: "2001:db8:8000::/35"
#             le: 37
#         name: AllowIPv6Prefix
#
# commands:
#   - "no ip prefix-list AllowPrefix seq 10 permit 192.0.2.0/23 eq 24"
#   - "ip prefix-list AllowPrefix seq 10 permit 203.0.113.64/27"
#   - "ip prefix-list AllowPrefix seq 30 permit 203.0.113.96/27"
#   - "no ip prefix-list AllowPrefix seq 20 permit 198.51.100.128/26"
#   - "ip prefix-list AllowPrefix2Stub description allow other engineering IPv4 network"
#
# after:
#   - afi: ipv4
#     prefix_lists:
#       - description: allows engineering IPv4 networks
#         entries:
#           - sequence: 10
#             action: permit
#             prefix: 203.0.113.64/27
#           - sequence: 30
#             action: permit
#             prefix: 203.0.113.96/27
#          name: AllowPrefix
#       - description: allow other engineering IPv4 network
#         name: AllowPrefix2Stub
#       - description: denies lab IPv4 networks
#         entries:
#           - sequence: 20
#             action: deny
#             prefix: 203.0.113.0/24
#             le: 25
#         name: DenyPrefix
#
#   - afi: ipv6
#     prefix_lists:
#       - description: allows engineering IPv6 networks
#         entries:
#           - sequence: 8
#             action: permit
#             prefix: "2001:db8:400::/38"
#           - sequence: 20
#             action: permit
#             prefix: "2001:db8:8000::/35"
#             le: 37
#         name: AllowIPv6Prefix
#
# After state:
# ------------
# nxos-9k-rdo# show running-config | section 'ip(.*) prefix-list'
# ip prefix-list AllowPrefix description allows engineering IPv4 networks
# ip prefix-list AllowPrefix seq 10 permit 203.0.113.64/27
# ip prefix-list AllowPrefix seq 30 permit 203.0.113.96/27
# ip prefix-list AllowPrefix2Stub description allow other engineering IPv4 network
# ip prefix-list DenyPrefix description denies lab IPv4 networks
# ip prefix-list DenyPrefix seq 20 deny 203.0.113.0/24 le 25
# ipv6 prefix-list AllowIPv6Prefix description allows engineering IPv6 networks
# ipv6 prefix-list AllowIPv6Prefix seq 8 permit 2001:db8:400::/38
# ipv6 prefix-list AllowIPv6Prefix seq 20 permit 2001:db8:8000::/35 le 37

# Using overridden

# Before state:
# ------------
# nxos-9k-rdo# show running-config | section 'ip(.*) prefix-list'
# ip prefix-list AllowPrefix description allows engineering IPv4 networks
# ip prefix-list AllowPrefix seq 10 permit 192.0.2.0/23 eq 24
# ip prefix-list AllowPrefix seq 20 permit 198.51.100.128/26
# ip prefix-list DenyPrefix description denies lab IPv4 networks
# ip prefix-list DenyPrefix seq 20 deny 203.0.113.0/24 le 25
# ipv6 prefix-list AllowIPv6Prefix description allows engineering IPv6 networks
# ipv6 prefix-list AllowIPv6Prefix seq 8 permit 2001:db8:400::/38
# ipv6 prefix-list AllowIPv6Prefix seq 20 permit 2001:db8:8000::/35 le 37

- name: Override all prefix-lists configuration with provided configuration
  cisco.nxos.nxos_prefix_lists: &id003
    config:
      - afi: ipv4
        prefix_lists:
          - name: AllowPrefix
            description: allows engineering IPv4 networks
            entries:
              - sequence: 10
                action: permit
                prefix: 203.0.113.64/27

              - sequence: 30
                action: permit
                prefix: 203.0.113.96/27
          - name: AllowPrefix2Stub
            description: allow other engineering IPv4 network
    state: overridden

# Task output
# -------------
# before:
#   - afi: ipv4
#     prefix_lists:
#       - description: allows engineering IPv4 networks
#         entries:
#           - sequence: 10
#             action: permit
#             prefix: 192.0.2.0/23
#             eq: 24
#           - sequence: 20
#             action: permit
#             prefix: 198.51.100.128/26
#         name: AllowPrefix
#       - description: denies lab IPv4 networks
#         entries:
#           - sequence: 20
#             action: deny
#             prefix: 203.0.113.0/24
#             le: 25
#         name: DenyPrefix
#
#   - afi: ipv6
#     prefix_lists:
#       - description: allows engineering IPv6 networks
#         entries:
#           - sequence: 8
#             action: permit
#             prefix: "2001:db8:400::/38"
#           - sequence: 20
#             action: permit
#             prefix: "2001:db8:8000::/35"
#             le: 37
#         name: AllowIPv6Prefix
#
# commands:
#   - "no ip prefix-list AllowPrefix seq 10 permit 192.0.2.0/23 eq 24"
#   - "ip prefix-list AllowPrefix seq 10 permit 203.0.113.64/27"
#   - "ip prefix-list AllowPrefix seq 30 permit 203.0.113.96/27"
#   - "no ip prefix-list AllowPrefix seq 20 permit 198.51.100.128/26"
#   - "ip prefix-list AllowPrefix2Stub description allow other engineering IPv4 network"
#   - "no ip prefix-list DenyPrefix"
#   - "no ipv6 prefix-list AllowIPv6Prefix"
#
# after:
#   - afi: ipv4
#     prefix_lists:
#       - name: AllowPrefix
#         description: allows engineering IPv4 networks
#         entries:
#           - sequence: 10
#             action: permit
#             prefix: 203.0.113.64/27
#
#           - sequence: 30
#             action: permit
#             prefix: 203.0.113.96/27
#       - name: AllowPrefix2Stub
#         description: allow other engineering IPv4 network
#
# After state:
# ------------
# nxos-9k-rdo# show running-config | section 'ip(.*) prefix-list'
# ip prefix-list AllowPrefix description allows engineering IPv4 networks
# ip prefix-list AllowPrefix seq 10 permit 203.0.113.64/27
# ip prefix-list AllowPrefix seq 30 permit 203.0.113.96/27
# ip prefix-list AllowPrefix2Stub description allow other engineering IPv4 network

# Using deleted to delete a all prefix lists for an AFI

# Before state:
# ------------
# nxos-9k-rdo# show running-config | section 'ip(.*) prefix-list'
# ip prefix-list AllowPrefix description allows engineering IPv4 networks
# ip prefix-list AllowPrefix seq 10 permit 192.0.2.0/23 eq 24
# ip prefix-list AllowPrefix seq 20 permit 198.51.100.128/26
# ip prefix-list DenyPrefix description denies lab IPv4 networks
# ip prefix-list DenyPrefix seq 20 deny 203.0.113.0/24 le 25
# ipv6 prefix-list AllowIPv6Prefix description allows engineering IPv6 networks
# ipv6 prefix-list AllowIPv6Prefix seq 8 permit 2001:db8:400::/38
# ipv6 prefix-list AllowIPv6Prefix seq 20 permit 2001:db8:8000::/35 le 37

- name: Delete all prefix-lists for an AFI
  cisco.nxos.nxos_prefix_lists:
    config:
      - afi: ipv4
    state: deleted
  register: result

# Task output
# -------------
# before:
#   - afi: ipv4
#     prefix_lists:
#       - description: allows engineering IPv4 networks
#         entries:
#           - sequence: 10
#             action: permit
#             prefix: 192.0.2.0/23
#             eq: 24
#           - sequence: 20
#             action: permit
#             prefix: 198.51.100.128/26
#         name: AllowPrefix
#       - description: denies lab IPv4 networks
#         entries:
#           - sequence: 20
#             action: deny
#             prefix: 203.0.113.0/24
#             le: 25
#         name: DenyPrefix
#
#   - afi: ipv6
#     prefix_lists:
#       - description: allows engineering IPv6 networks
#         entries:
#           - sequence: 8
#             action: permit
#             prefix: "2001:db8:400::/38"
#           - sequence: 20
#             action: permit
#             prefix: "2001:db8:8000::/35"
#             le: 37
#         name: AllowIPv6Prefix
#
# commands:
#   - "no ip prefix-list AllowPrefix"
#   - "no ip prefix-list DenyPrefix"
#
# after:
#   - afi: ipv6
#     prefix_lists:
#       - description: allows engineering IPv6 networks
#         entries:
#           - sequence: 8
#             action: permit
#             prefix: "2001:db8:400::/38"
#           - sequence: 20
#             action: permit
#             prefix: "2001:db8:8000::/35"
#             le: 37
#         name: AllowIPv6Prefix
#
# After state:
# ------------
# nxos-9k-rdo# show running-config | section 'ip(.*) prefix-list'
# ipv6 prefix-list AllowIPv6Prefix description allows engineering IPv6 networks
# ipv6 prefix-list AllowIPv6Prefix seq 8 permit 2001:db8:400::/38
# ipv6 prefix-list AllowIPv6Prefix seq 20 permit 2001:db8:8000::/35 le 37

# Using deleted to delete a single prefix-list

# Before state:
# ------------
# nxos-9k-rdo# show running-config | section 'ip(.*) prefix-list'
# ip prefix-list AllowPrefix description allows engineering IPv4 networks
# ip prefix-list AllowPrefix seq 10 permit 192.0.2.0/23 eq 24
# ip prefix-list AllowPrefix seq 20 permit 198.51.100.128/26
# ip prefix-list DenyPrefix description denies lab IPv4 networks
# ip prefix-list DenyPrefix seq 20 deny 203.0.113.0/24 le 25
# ipv6 prefix-list AllowIPv6Prefix description allows engineering IPv6 networks
# ipv6 prefix-list AllowIPv6Prefix seq 8 permit 2001:db8:400::/38
# ipv6 prefix-list AllowIPv6Prefix seq 20 permit 2001:db8:8000::/35 le 37

- name: Delete a single prefix-list
  cisco.nxos.nxos_prefix_lists:
    config:
      - afi: ipv4
        prefix_lists:
          - name: AllowPrefix
    state: deleted

# Task output
# -------------
# before:
#   - afi: ipv4
#     prefix_lists:
#       - description: allows engineering IPv4 networks
#         entries:
#           - sequence: 10
#             action: permit
#             prefix: 192.0.2.0/23
#             eq: 24
#           - sequence: 20
#             action: permit
#             prefix: 198.51.100.128/26
#         name: AllowPrefix
#       - description: denies lab IPv4 networks
#         entries:
#           - sequence: 20
#             action: deny
#             prefix: 203.0.113.0/24
#             le: 25
#         name: DenyPrefix
#
#   - afi: ipv6
#     prefix_lists:
#       - description: allows engineering IPv6 networks
#         entries:
#           - sequence: 8
#             action: permit
#             prefix: "2001:db8:400::/38"
#           - sequence: 20
#             action: permit
#             prefix: "2001:db8:8000::/35"
#             le: 37
#         name: AllowIPv6Prefix
#
# commands:
#   - "no ip prefix-list AllowPrefix"
#
# after:
#   - afi: ipv4
#     prefix_lists:
#       - description: denies lab IPv4 networks
#         entries:
#           - sequence: 20
#             action: deny
#             prefix: 203.0.113.0/24
#             le: 25
#         name: DenyPrefix
#
#   - afi: ipv6
#     prefix_lists:
#       - description: allows engineering IPv6 networks
#         entries:
#           - sequence: 8
#             action: permit
#             prefix: "2001:db8:400::/38"
#           - sequence: 20
#             action: permit
#             prefix: "2001:db8:8000::/35"
#             le: 37
#         name: AllowIPv6Prefix
#
# After state:
# ------------
# nxos-9k-rdo# show running-config | section 'ip(.*) prefix-list'
# ip prefix-list DenyPrefix description denies lab IPv4 networks
# ip prefix-list DenyPrefix seq 20 deny 203.0.113.0/24 le 25
# ipv6 prefix-list AllowIPv6Prefix description allows engineering IPv6 networks
# ipv6 prefix-list AllowIPv6Prefix seq 8 permit 2001:db8:400::/38
# ipv6 prefix-list AllowIPv6Prefix seq 20 permit 2001:db8:8000::/35 le 37

# Using deleted to delete all prefix-lists from the device

# Before state:
# ------------
# nxos-9k-rdo# show running-config | section 'ip(.*) prefix-list'
# ip prefix-list AllowPrefix description allows engineering IPv4 networks
# ip prefix-list AllowPrefix seq 10 permit 192.0.2.0/23 eq 24
# ip prefix-list AllowPrefix seq 20 permit 198.51.100.128/26
# ip prefix-list DenyPrefix description denies lab IPv4 networks
# ip prefix-list DenyPrefix seq 20 deny 203.0.113.0/24 le 25
# ipv6 prefix-list AllowIPv6Prefix description allows engineering IPv6 networks
# ipv6 prefix-list AllowIPv6Prefix seq 8 permit 2001:db8:400::/38
# ipv6 prefix-list AllowIPv6Prefix seq 20 permit 2001:db8:8000::/35 le 37

- name: Delete all prefix-lists
  cisco.nxos.nxos_prefix_lists:
    state: deleted

# Task output
# -------------
# before:
#   - afi: ipv4
#     prefix_lists:
#       - description: allows engineering IPv4 networks
#         entries:
#           - sequence: 10
#             action: permit
#             prefix: 192.0.2.0/23
#             eq: 24
#           - sequence: 20
#             action: permit
#             prefix: 198.51.100.128/26
#         name: AllowPrefix
#       - description: denies lab IPv4 networks
#         entries:
#           - sequence: 20
#             action: deny
#             prefix: 203.0.113.0/24
#             le: 25
#         name: DenyPrefix
#
#   - afi: ipv6
#     prefix_lists:
#       - description: allows engineering IPv6 networks
#         entries:
#           - sequence: 8
#             action: permit
#             prefix: "2001:db8:400::/38"
#           - sequence: 20
#             action: permit
#             prefix: "2001:db8:8000::/35"
#             le: 37
#         name: AllowIPv6Prefix
#
# commands:
#   - "no ip prefix-list AllowPrefix"
#   - "no ip prefix-list DenyPrefix"
#   - "no ipv6 prefix-list AllowIPv6Prefix"
#
# after: []
#
# After state:
# ------------
# nxos-9k-rdo# show running-config | section 'ip(.*) prefix-list'
# nxos-9k-rdo#

# Using rendered

- name: Render platform specific configuration lines with state rendered (without connecting to the device)
  cisco.nxos.nxos_prefix_lists: &id001
    config:
      - afi: ipv4
        prefix_lists:
          - name: AllowPrefix
            description: allows engineering IPv4 networks
            entries:
              - sequence: 10
                action: permit
                prefix: 192.0.2.0/23
                eq: 24
              - sequence: 20
                action: permit
                prefix: 198.51.100.128/26
          - name: DenyPrefix
            description: denies lab IPv4 networks
            entries:
              - sequence: 20
                action: deny
                prefix: 203.0.113.0/24
                le: 25

      - afi: ipv6
        prefix_lists:
          - name: AllowIPv6Prefix
            description: allows engineering IPv6 networks
            entries:
              - sequence: 8
                action: permit
                prefix: "2001:db8:400::/38"
              - sequence: 20
                action: permit
                prefix: "2001:db8:8000::/35"
                le: 37
    state: rendered

# Task Output (redacted)
# -----------------------
# rendered:
#   - afi: ipv4
#     prefix_lists:
#       - description: allows engineering IPv4 networks
#         entries:
#           - sequence: 10
#             action: permit
#             prefix: 192.0.2.0/23
#             eq: 24
#           - sequence: 20
#             action: permit
#             prefix: 198.51.100.128/26
#         name: AllowPrefix
#       - description: denies lab IPv4 networks
#         entries:
#           - sequence: 20
#             action: deny
#             prefix: 203.0.113.0/24
#             le: 25
#         name: DenyPrefix
#
#   - afi: ipv6
#     prefix_lists:
#       - description: allows engineering IPv6 networks
#         entries:
#           - sequence: 8
#             action: permit
#             prefix: "2001:db8:400::/38"
#           - sequence: 20
#             action: permit
#             prefix: "2001:db8:8000::/35"
#             le: 37
#         name: AllowIPv6Prefix

# Using parsed

# parsed.cfg
# ------------
# ip prefix-list AllowPrefix description allows engineering IPv4 networks
# ip prefix-list AllowPrefix seq 10 permit 192.0.2.0/23 eq 24
# ip prefix-list AllowPrefix seq 20 permit 198.51.100.128/26
# ip prefix-list DenyPrefix description denies lab IPv4 networks
# ip prefix-list DenyPrefix seq 20 deny 203.0.113.0/24 le 25
# ipv6 prefix-list AllowIPv6Prefix description allows engineering IPv6 networks
# ipv6 prefix-list AllowIPv6Prefix seq 8 permit 2001:db8:400::/38
# ipv6 prefix-list AllowIPv6Prefix seq 20 permit 2001:db8:8000::/35 le 37

- name: Parse externally provided prefix-lists configuration
  register: result
  cisco.nxos.nxos_prefix_lists:
    running_config: "{{ lookup('file', './parsed.cfg') }}"
    state: parsed

# Task output (redacted)
# -----------------------
# parsed:
#   - afi: ipv4
#     prefix_lists:
#       - description: allows engineering IPv4 networks
#         entries:
#           - sequence: 10
#             action: permit
#             prefix: 192.0.2.0/23
#             eq: 24
#           - sequence: 20
#             action: permit
#             prefix: 198.51.100.128/26
#         name: AllowPrefix
#       - description: denies lab IPv4 networks
#         entries:
#           - sequence: 20
#             action: deny
#             prefix: 203.0.113.0/24
#             le: 25
#         name: DenyPrefix
#
#   - afi: ipv6
#     prefix_lists:
#       - description: allows engineering IPv6 networks
#         entries:
#           - sequence: 8
#             action: permit
#             prefix: "2001:db8:400::/38"
#           - sequence: 20
#             action: permit
#             prefix: "2001:db8:8000::/35"
#             le: 37
#         name: AllowIPv6Prefix
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.prefix_lists.prefix_lists import (
    Prefix_listsArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.config.prefix_lists.prefix_lists import (
    Prefix_lists,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=Prefix_listsArgs.argument_spec,
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

    result = Prefix_lists(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
