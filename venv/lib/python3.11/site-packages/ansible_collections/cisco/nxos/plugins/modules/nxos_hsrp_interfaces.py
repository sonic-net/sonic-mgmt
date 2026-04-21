#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for nxos_hsrp_interfaces
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: nxos_hsrp_interfaces
short_description: HSRP interfaces resource module
description: Resource module to configure HSRP on interfaces.
version_added: 10.1.0
author:
  - Chris Van Heuveln (@chrisvanheuveln)
  - Sagar Paul (@KB-perByte)
notes:
  - Tested against NX-OS 10.4(2) Nexus 9000v.
  - Feature bfd and hsrp, should be enabled for this module.
  - Unsupported for Cisco MDS
options:
  running_config:
    description:
      - This option is used only with state I(parsed).
      - The value of this option should be the output received from the NX-OS device
        by executing the command B(show running-config | section '^interface').
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into Ansible structured data as per the resource module's argspec
        and the value is then returned in the I(parsed) key within the result.
    type: str
  config:
    description: A dictionary of HSRP configuration options to add to interface
    type: list
    elements: dict
    suboptions:
      name:
        type: str
        description: The name of the interface.
      bfd:
        type: str
        description:
          - Enable/Disable HSRP Bidirectional Forwarding Detection (BFD) on the interface.
          - B(Deprecated), Use standby.bfd instead, the facts would always render bfd information
            as a part of standby configuration
          - This option has been deprecated and will be removed in a release after 2028-06-01.
        choices:
          - enable
          - disable
      standby_options:
        description: Group number and group options for standby (HSRP)
        type: list
        elements: dict
        suboptions:
          group_no:
            description: Group number
            type: int
          authentication:
            description: Authentication configuration
            type: dict
            suboptions:
              key_chain:
                description: Set key chain
                type: str
              key_string:
                description: Set key string
                type: str
              password_text:
                description: Password text valid for plain text and and key-string
                type: str
          follow:
            description: Groups to be followed
            type: str
          mac_address:
            description: Virtual MAC address
            type: str
          ip:
            description: Enable HSRP IPv4 and set the virtual IP address
            type: list
            elements: dict
            suboptions:
              virtual_ip:
                description: Virtual IP address
                type: str
              secondary:
                description: Make this IP address a secondary virtual IP address
                type: bool
          group_name:
            description: Redundancy name string
            type: str
          preempt:
            description: Overthrow lower priority Active routers
            type: dict
            suboptions:
              minimum:
                description: Delay at least this long
                type: int
              reload:
                description: Delay after reload
                type: int
              sync:
                description: Wait for IP redundancy clients
                type: int
          priority:
            description: Priority level
            type: dict
            suboptions:
              level:
                description: Priority level value
                type: int
              upper:
                description: Set upper threshold value (forwarding-threshold)
                type: int
              lower:
                description: Set lower threshold value (forwarding-threshold)
                type: int
          timer:
            description: Overthrow lower priority Active routers
            type: dict
            suboptions:
              hello_interval:
                description: Hello interval in seconds
                type: int
              hold_time:
                description: Hold time in seconds
                type: int
              msec:
                description: Specify hello interval in milliseconds
                type: bool
          track:
            description: Priority tracking
            type: list
            elements: dict
            suboptions:
              object_no:
                description: Track object number
                type: int
              decrement:
                description: Priority decrement
                type: int
      standby:
        description:
          - Standby options generic, not idempotent when version 1 (HSRP)
        type: dict
        suboptions:
          bfd:
            description: Enable HSRP BFD
            type: bool
          delay:
            description: HSRP initialization delay
            type: dict
            suboptions:
              minimum:
                description: Delay at least this long
                type: int
              reload:
                description: Delay after reload
                type: int
          mac_refresh:
            description: Refresh MAC cache on switch by periodically sending packet from virtual mac address
            type: int
          use_bia:
            description: HSRP uses interface's burned in address (does not work with mac address)
            type: dict
            suboptions:
              set:
                description: Set use-bia only
                type: bool
              scope:
                description: Scope interface option (hsrp use-bia scope interface)
                type: bool
          version:
            description: HSRP version
            type: int
  state:
    choices:
      - merged
      - replaced
      - overridden
      - deleted
      - rendered
      - gathered
      - parsed
    default: merged
    description:
      - The state the configuration should be left in
      - The states I(rendered), I(gathered) and I(parsed) does not perform any change
        on the device.
      - The state I(rendered) will transform the configuration in C(config) option to
        platform specific CLI commands which will be returned in the I(rendered) key
        within the result. For state I(rendered) active connection to remote host is
        not required.
      - The state I(gathered) will fetch the running configuration from device and transform
        it into structured data in the format as per the resource module argspec and
        the value is returned in the I(gathered) key within the result.
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into JSON format as per the resource module parameters and the
        value is returned in the I(parsed) key within the result. The value of C(running_config)
        option should be the same format as the output of command
        I(show running-config | section ^interface) executed on device. For state I(parsed) active
        connection to remote host is not required.
    type: str
"""

EXAMPLES = """
# Using merged

# Before state:
# -------------
#
# switch# show running-config | section interface
# interface Vlan1
# interface Vlan10
# interface Vlan14
#   bandwidth 99999
# interface Vlan1000
# interface Ethernet1/1
# interface Ethernet1/2
# interface Ethernet1/3
# interface Ethernet1/4
# interface Ethernet1/5
# interface Ethernet1/6
# interface Ethernet1/7

- name: Merge provided configuration with device configuration
  cisco.nxos.nxos_hsrp_interfaces:
    config:
      - name: Ethernet1/1
        standby:
          bfd: true
          mac_refresh: 400
          version: 2
        standby_options:
          - authentication:
              key_string: SECUREKEY10
            group_name: VLAN10-GROUP
            group_no: 10
            ip:
              - secondary: true
                virtual_ip: 10.10.10.2
            mac_address: 00CC.10DD.10EE
    state: merged

# Task Output
# -----------
#
# before:
# - name: Vlan1
# - name: Vlan10
# - name: Vlan14
# - name: Vlan1000
# - name: Ethernet1/1
#   standby:
#     bfd: true
# - name: Ethernet1/2
# - name: Ethernet1/3
# - name: Ethernet1/4
# - name: Ethernet1/5
# - name: Ethernet1/6
# - name: Ethernet1/7
#  commands:
# - interface Ethernet1/1
# - hsrp version 2
# - hsrp mac-refresh 400
# - hsrp 10
# - mac-address 00CC.10DD.10EE
# - name VLAN10-GROUP
# - authentication md5 key-string SECUREKEY10
# - ip 10.10.10.2 secondary
# - interface Ethernet1/2
# - hsrp bfd
# - hsrp version 2
# - hsrp mac-refresh 400
# - hsrp 20
# - mac-address 00CC.10DD.10EF
# - name VLAN20-GROUP
# - authentication md5 key-chain SECUREKEY20
# - ip 10.10.10.3 secondary
#  after:
# - name: Vlan1
# - name: Vlan10
# - name: Vlan14
# - name: Vlan1000
# - name: Ethernet1/1
#   standby:
#     bfd: true
#     mac_refresh: 400
#     version: 2
#   standby_options:
#     - authentication:
#         key_string: SECUREKEY10
#       group_name: VLAN10-GROUP
#       group_no: 10
#       ip:
#         - secondary: true
#           virtual_ip: 10.10.10.2
#       mac_address: 00CC.10DD.10EE
# - name: Ethernet1/2
#   standby:
#     bfd: true
#     mac_refresh: 400
#     version: 2
#   standby_options:
#     - authentication:
#         key_chain: SECUREKEY20
#       group_name: VLAN20-GROUP
#       group_no: 20
#       ip:
#         - secondary: true
#           virtual_ip: 10.10.10.3
#       mac_address: 00CC.10DD.10EF
# - name: Ethernet1/3
# - name: Ethernet1/4
# - name: Ethernet1/5
# - name: Ethernet1/6
# - name: Ethernet1/7

# After state:
# ------------
#
# switch# show running-config | section interface
# interface Vlan1
# interface Vlan10
# interface Vlan14
#   bandwidth 99999
# interface Vlan1000
# interface Ethernet1/1
#   no switchport
#   hsrp bfd
#   hsrp version 2
#   hsrp mac-refresh 400
#   hsrp 10
#     authentication md5 key-string SECUREKEY10
#     name VLAN10-GROUP
#     mac-address 00CC.10DD.10EE
#     ip 10.10.10.2 secondary
# interface Ethernet1/2
#   no switchport
#   hsrp bfd
#   hsrp version 2
#   hsrp mac-refresh 400
#   hsrp 20
#     authentication md5 key-chain SECUREKEY20
#     name VLAN20-GROUP
#     mac-address 00CC.10DD.10EF
#     ip 10.10.10.3 secondary
# interface Ethernet1/3
# interface Ethernet1/4
# interface Ethernet1/5
# interface Ethernet1/6
# interface Ethernet1/7

# Using replaced

# Before state:
# -------------
#
# switch# show running-config | section interface
# interface Vlan1
# interface Vlan10
# interface Vlan14
#   bandwidth 99999
# interface Vlan1000
# interface Ethernet1/1
#   no switchport
#   hsrp bfd
#   hsrp version 2
#   hsrp mac-refresh 400
#   hsrp 10
#     authentication md5 key-string SECUREKEY10
#     name VLAN10-GROUP
#     mac-address 00CC.10DD.10EE
#     ip 10.10.10.2 secondary
# interface Ethernet1/2
#   no switchport
#   hsrp bfd
#   hsrp version 2
#   hsrp mac-refresh 400
#   hsrp 20
#     authentication md5 key-chain SECUREKEY20
#     name VLAN20-GROUP
#     mac-address 00CC.10DD.10EF
#     ip 10.10.10.3 secondary
# interface Ethernet1/3
# interface Ethernet1/4
# interface Ethernet1/5
# interface Ethernet1/6
# interface Ethernet1/7

- name: Replaces device configuration of listed interfaces with provided configuration
  cisco.nxos.nxos_hsrp_interfaces:
    config:
      - name: Ethernet1/1
        standby:
          bfd: true
          mac_refresh: 400
          version: 2
        standby_options:
          - authentication:
              key_string: SECUREKEY10
            group_name: VLAN11-GROUP
            group_no: 11
            mac_address: 00CC.10DD.10EE
      - name: Ethernet1/2
        standby:
          bfd: true
          mac_refresh: 400
          version: 2
        standby_options:
          - authentication:
              key_chain: SECUREKEY20
            group_name: VLAN20-GROUP
            group_no: 20
            mac_address: 00CC.10DD.10EF
    state: replaced

# Task Output
# -----------
#
#  before:
# - name: Vlan1
# - name: Vlan10
# - name: Vlan14
# - name: Vlan1000
# - name: Ethernet1/1
#   standby:
#     bfd: true
#     mac_refresh: 400
#     version: 2
#   standby_options:
#     - authentication:
#         key_string: SECUREKEY10
#       group_name: VLAN10-GROUP
#       group_no: 10
#       ip:
#         - secondary: true
#           virtual_ip: 10.10.10.2
#       mac_address: 00CC.10DD.10EE
# - name: Ethernet1/2
#   standby:
#     bfd: true
#     mac_refresh: 400
#     version: 2
#   standby_options:
#     - authentication:
#         key_chain: SECUREKEY20
#       group_name: VLAN20-GROUP
#       group_no: 20
#       ip:
#         - secondary: true
#           virtual_ip: 10.10.10.3
#       mac_address: 00CC.10DD.10EF
# - name: Ethernet1/3
# - name: Ethernet1/4
# - name: Ethernet1/5
# - name: Ethernet1/6
# - name: Ethernet1/7
#  commands:
# - interface Ethernet1/1
# - hsrp 11
# - mac-address 00CC.10DD.10EE
# - name VLAN11-GROUP
# - authentication md5 key-string SECUREKEY10
# - no hsrp 10
# - interface Ethernet1/2
# - hsrp 20
# - no ip 10.10.10.3 secondary
#  after:
# - name: Vlan1
# - name: Vlan10
# - name: Vlan14
# - name: Vlan1000
# - name: Ethernet1/1
#   standby:
#     bfd: true
#     mac_refresh: 400
#     version: 2
#   standby_options:
#     - authentication:
#         key_string: SECUREKEY10
#       group_name: VLAN11-GROUP
#       group_no: 11
#       mac_address: 00CC.10DD.10EE
# - name: Ethernet1/2
#   standby:
#     bfd: true
#     mac_refresh: 400
#     version: 2
#   standby_options:
#     - authentication:
#         key_chain: SECUREKEY20
#       group_name: VLAN20-GROUP
#       group_no: 20
#       mac_address: 00CC.10DD.10EF
# - name: Ethernet1/3
# - name: Ethernet1/4
# - name: Ethernet1/5
# - name: Ethernet1/6
# - name: Ethernet1/7


# After state:
# ------------
#
# switch# show running-config | section interface
# interface Vlan1
# interface Vlan10
# interface Vlan14
#   bandwidth 99999
# interface Vlan1000
# interface Ethernet1/1
#   no switchport
#   hsrp bfd
#   hsrp version 2
#   hsrp mac-refresh 400
#   hsrp 11
#     authentication md5 key-string SECUREKEY10
#     name VLAN11-GROUP
#     mac-address 00CC.10DD.10EE
# interface Ethernet1/2
#   no switchport
#   hsrp bfd
#   hsrp version 2
#   hsrp mac-refresh 400
#   hsrp 20
#     authentication md5 key-chain SECUREKEY20
#     name VLAN20-GROUP
#     mac-address 00CC.10DD.10EF
# interface Ethernet1/3
# interface Ethernet1/4
# interface Ethernet1/5
# interface Ethernet1/6
# interface Ethernet1/7

# Using overridden

# Before state:
# -------------
#
# switch# show running-config | section interface
# interface Vlan1
# interface Vlan10
# interface Vlan14
#   bandwidth 99999
# interface Vlan1000
# interface Ethernet1/1
#   no switchport
#   hsrp bfd
#   hsrp version 2
#   hsrp mac-refresh 400
#   hsrp 10
#     authentication md5 key-string SECUREKEY10
#     name VLAN10-GROUP
#     mac-address 00CC.10DD.10EE
#     ip 10.10.10.2 secondary
# interface Ethernet1/2
#   no switchport
#   hsrp bfd
#   hsrp version 2
#   hsrp mac-refresh 400
#   hsrp 20
#     authentication md5 key-chain SECUREKEY20
#     name VLAN20-GROUP
#     mac-address 00CC.10DD.10EF
#     ip 10.10.10.3 secondary

- name: Override device configuration of all interfaces with provided configuration
  cisco.nxos.nxos_hsrp_interfaces:
    config:
      - name: Ethernet1/1
        standby:
          bfd: true
          mac_refresh: 400
          version: 2
        standby_options:
          - authentication:
              key_string: SECUREKEY10
            group_name: VLAN11-GROUP
            group_no: 11
            mac_address: 00CC.10DD.10EE
      - name: Ethernet1/2
        standby:
          bfd: true
          mac_refresh: 400
          version: 2
        standby_options:
          - authentication:
              key_chain: SECUREKEY20
            group_name: VLAN20-GROUP
            group_no: 20
            mac_address: 00CC.10DD.10EF
    state: overridden

# Task Output
# -----------
#
#  before:
# - name: Vlan1
# - name: Vlan10
# - name: Vlan14
# - name: Vlan1000
# - name: Ethernet1/1
#   standby:
#     bfd: true
#     mac_refresh: 400
#     version: 2
#   standby_options:
#     - authentication:
#         key_string: SECUREKEY10
#       group_name: VLAN10-GROUP
#       group_no: 10
#       ip:
#         - secondary: true
#           virtual_ip: 10.10.10.2
#       mac_address: 00CC.10DD.10EE
# - name: Ethernet1/2
#   standby:
#     bfd: true
#     mac_refresh: 400
#     version: 2
#   standby_options:
#     - authentication:
#         key_chain: SECUREKEY20
#       group_name: VLAN20-GROUP
#       group_no: 20
#       ip:
#         - secondary: true
#           virtual_ip: 10.10.10.3
#       mac_address: 00CC.10DD.10EF
# - name: Ethernet1/3
# - name: Ethernet1/4
# - name: Ethernet1/5
# - name: Ethernet1/6
# - name: Ethernet1/7
#  commands:
# - interface Ethernet1/1
# - hsrp 11
# - mac-address 00CC.10DD.10EE
# - name VLAN11-GROUP
# - authentication md5 key-string SECUREKEY10
# - no hsrp 10
# - interface Ethernet1/2
# - hsrp 20
# - no ip 10.10.10.3 secondary
#  after:
# - name: Vlan1
# - name: Vlan10
# - name: Vlan14
# - name: Vlan1000
# - name: Ethernet1/1
#   standby:
#     bfd: true
#     mac_refresh: 400
#     version: 2
#   standby_options:
#     - authentication:
#         key_string: SECUREKEY10
#       group_name: VLAN11-GROUP
#       group_no: 11
#       mac_address: 00CC.10DD.10EE
# - name: Ethernet1/2
#   standby:
#     bfd: true
#     mac_refresh: 400
#     version: 2
#   standby_options:
#     - authentication:
#         key_chain: SECUREKEY20
#       group_name: VLAN20-GROUP
#       group_no: 20
#       mac_address: 00CC.10DD.10EF
# - name: Ethernet1/3
# - name: Ethernet1/4
# - name: Ethernet1/5
# - name: Ethernet1/6
# - name: Ethernet1/7

# After state:
# ------------
#
# switch# show running-config | section interface
# interface Vlan1
# interface Vlan10
# interface Vlan14
#   bandwidth 99999
# interface Vlan1000
# interface Ethernet1/1
#   no switchport
#   hsrp bfd
#   hsrp version 2
#   hsrp mac-refresh 400
#   hsrp 11
#     authentication md5 key-string SECUREKEY10
#     name VLAN11-GROUP
#     mac-address 00CC.10DD.10EE
# interface Ethernet1/2
#   no switchport
#   hsrp bfd
#   hsrp version 2
#   hsrp mac-refresh 400
#   hsrp 20
#     authentication md5 key-chain SECUREKEY20
#     name VLAN20-GROUP
#     mac-address 00CC.10DD.10EF
# interface Ethernet1/3
# interface Ethernet1/4
# interface Ethernet1/5
# interface Ethernet1/6
# interface Ethernet1/7


# Using deleted

# Before state:
# -------------
#
# switch# show running-config | section interface
# interface Vlan1
# interface Vlan10
# interface Vlan14
#   bandwidth 99999
# interface Vlan1000
# interface Ethernet1/1
#   no switchport
#   hsrp bfd
#   hsrp version 2
#   hsrp mac-refresh 400
#   hsrp 10
#     authentication md5 key-string SECUREKEY10
#     name VLAN10-GROUP
#     mac-address 00CC.10DD.10EE
#     ip 10.10.10.2 secondary
# interface Ethernet1/2
#   no switchport
#   hsrp bfd
#   hsrp version 2
#   hsrp mac-refresh 400
#   hsrp 20
#     authentication md5 key-chain SECUREKEY20
#     name VLAN20-GROUP
#     mac-address 00CC.10DD.10EF
#     ip 10.10.10.3 secondary
# interface Ethernet1/3
# interface Ethernet1/4
# interface Ethernet1/5
# interface Ethernet1/6
# interface Ethernet1/7

- name: Delete or return interface parameters to default settings
  cisco.nxos.nxos_hsrp_interfaces:
    config:
      - name: Ethernet1/1
        standby:
          bfd: true
          mac_refresh: 400
          version: 2
        standby_options:
          - authentication:
              key_string: SECUREKEY10
            group_name: VLAN11-GROUP
            group_no: 11
            mac_address: 00CC.10DD.10EE
      - name: Ethernet1/2
        standby:
          bfd: true
          mac_refresh: 400
          version: 2
        standby_options:
          - authentication:
              key_chain: SECUREKEY20
            group_name: VLAN20-GROUP
            group_no: 20
            mac_address: 00CC.10DD.10EF
    state: deleted

# Task Output
# -----------
#
# before:
# - name: Vlan1
# - name: Vlan10
# - name: Vlan14
# - name: Vlan1000
# - name: Ethernet1/1
#   standby:
#     bfd: true
#     mac_refresh: 400
#     version: 2
#   standby_options:
#     - authentication:
#         key_string: SECUREKEY10
#       group_name: VLAN10-GROUP
#       group_no: 10
#       ip:
#         - secondary: true
#           virtual_ip: 10.10.10.2
#       mac_address: 00CC.10DD.10EE
# - name: Ethernet1/2
#   standby:
#     bfd: true
#     mac_refresh: 400
#     version: 2
#   standby_options:
#     - authentication:
#         key_chain: SECUREKEY20
#       group_name: VLAN20-GROUP
#       group_no: 20
#       ip:
#         - secondary: true
#           virtual_ip: 10.10.10.3
#       mac_address: 00CC.10DD.10EF
# - name: Ethernet1/3
# - name: Ethernet1/4
# - name: Ethernet1/5
# - name: Ethernet1/6
# - name: Ethernet1/7
# commands:
# - interface Ethernet1/1
# - no hsrp bfd
# - no hsrp version 2
# - no hsrp mac-refresh 400
# - no hsrp 10
# - interface Ethernet1/2
# - no hsrp bfd
# - no hsrp version 2
# - no hsrp mac-refresh 400
# - no hsrp 20
# after:
# - name: Vlan1
# - name: Vlan10
# - name: Vlan14
# - name: Vlan1000
# - name: Ethernet1/1
# - name: Ethernet1/2
# - name: Ethernet1/3
# - name: Ethernet1/4
# - name: Ethernet1/5
# - name: Ethernet1/6

# After state:
# ------------
#
# switch# show running-config | section interface
# interface Vlan1
# interface Vlan10
# interface Vlan14
#   bandwidth 99999
# interface Vlan1000
# interface Ethernet1/1
#   no switchport
# interface Ethernet1/2
#   no switchport
# interface Ethernet1/3
# interface Ethernet1/4
# interface Ethernet1/5
# interface Ethernet1/6
# interface Ethernet1/7

# Using rendered

- name: Use rendered state to convert task input to device specific commands
  cisco.nxos.nxos_hsrp_interfaces:
    config:
      - name: Ethernet1/1
        description: outbound-intf
        mode: layer3
        speed: 100
      - name: Ethernet1/2
        mode: layer2
        enabled: true
        duplex: full
    state: rendered

# Task Output
# -----------
#
# rendered:
#  - interface Vlan1
#  - hsrp version 2
#  - hsrp 10
#  - timers msec 250 255
#  - authentication md5 key-chain test
#  - interface Vlan10
#  - hsrp bfd
#  - hsrp version 2
#  - hsrp mac-refresh 400
#  - hsrp 10
#  - mac-address 00CC.10DD.10EE
#  - name VLAN10-GROUP
#  - preempt delay minimum 15 reload 120 sync 10
#  - authentication md5 key-string SECUREKEY10
#  - ip 10.10.10.2 secondary
#  - interface Vlan14
#  - hsrp bfd
#  - hsrp version 2
#  - hsrp delay 22 123
#  - hsrp mac-refresh 300
#  - hsrp 14
#  - follow VLAN14-GROUP
#  - mac-address 00AA.14BB.14CC
#  - ip 192.168.14.1 secondary
#  - ip 192.168.14.2 secondary
#  - hsrp 15
#  - mac-address 00BB.14CC.15DD
#  - preempt delay minimum 10 reload 100 sync 5
#  - priority 22 forwarding-threshold lower 12 upper 22
#  - timers msec 456 33
#  - authentication md5 key-string SECUREKEY14
#  - interface Vlan1000
#  - hsrp 10
#  - mac-address 0423.4567.89AB
#  - name testhsr
#  - preempt delay minimum 33 reload 23 sync 22
#  - priority 22 forwarding-threshold lower 12 upper 22
#  - timers msec 456 33
#  - authentication md5 key-string testmesecurte
#  - ip 10.15.8.1 secondary


# Using parsed

# parsed.cfg
# ------------
#
# interface Vlan1
#   hsrp version 2
#   hsrp 10
#     authentication md5 key-chain test
#     timers msec 250  255
# interface Vlan10
#   hsrp bfd
#   hsrp version 2
#   hsrp mac-refresh 400
#   hsrp 10
#     authentication md5 key-string SECUREKEY10
#     name VLAN10-GROUP
#     mac-address 00CC.10DD.10EE
#     preempt delay minimum 15 reload 120 sync 10
#     ip 10.10.10.2 secondary
# interface Vlan14
#   bandwidth 99999
#   hsrp bfd
#   hsrp version 2
#   hsrp delay minimum 22 reload 123
#   hsrp mac-refresh 300
#   hsrp 14
#     follow VLAN14-GROUP
#     mac-address 00AA.14BB.14CC
#     ip 192.168.14.1 secondary
#     ip 192.168.14.2 secondary
#   hsrp 15
#     authentication md5 key-string SECUREKEY14
#     mac-address 00BB.14CC.15DD
#     preempt delay minimum 10 reload 100 sync 5
#     priority 22 forwarding-threshold lower 12 upper 22
#     timers msec 456  33
# interface Vlan1000
#   hsrp 10
#     authentication md5 key-string testmesecurte
#     name testhsr
#     mac-address 0423.4567.89AB
#     preempt delay minimum 33 reload 23 sync 22
#     priority 22 forwarding-threshold lower 12 upper 22
#     timers msec 456  33
#     ip 10.15.8.1 secondary

- name: Use parsed state to convert externally supplied config to structured format
  cisco.nxos.nxos_hsrp_interfaces:
    running_config: "{{ lookup('file', 'parsed.cfg') }}"
    state: parsed

# Task output
# -----------
#
# {"parsed": [
#        {
#            "name": "Vlan1",
#            "standby": {
#                "version": 2
#            },
#            "standby_options": [
#                {
#                    "authentication": {
#                        "key_chain": "test"
#                    },
#                    "group_no": 10,
#                    "timer": {
#                        "hello_interval": 250,
#                        "hold_time": 255,
#                        "msec": true
#                    }
#                }
#            ]
#        },
#        {
#            "name": "Vlan10",
#            "standby": {
#                "bfd": true,
#                "mac_refresh": 400,
#                "version": 2
#            },
#            "standby_options": [
#                {
#                    "authentication": {
#                        "key_string": "SECUREKEY10"
#                    },
#                    "group_name": "VLAN10-GROUP",
#                    "group_no": 10,
#                    "ip": [
#                        {
#                            "secondary": true,
#                            "virtual_ip": "10.10.10.2"
#                        }
#                    ],
#                    "mac_address": "00CC.10DD.10EE",
#                    "preempt": {
#                        "minimum": 15,
#                        "reload": 120,
#                        "sync": 10
#                    }
#                }
#            ]
#        },
#        {
#            "name": "Vlan14",
#            "standby": {
#                "bfd": true,
#                "delay": {
#                    "minimum": 22,
#                    "reload": 123
#                },
#                "mac_refresh": 300,
#                "version": 2
#            },
#            "standby_options": [
#                {
#                    "follow": "VLAN14-GROUP",
#                    "group_no": 14,
#                    "ip": [
#                        {
#                            "secondary": true,
#                            "virtual_ip": "192.168.14.1"
#                        },
#                        {
#                            "secondary": true,
#                            "virtual_ip": "192.168.14.2"
#                        }
#                    ],
#                    "mac_address": "00AA.14BB.14CC"
#                },
#                {
#                    "authentication": {
#                        "key_string": "SECUREKEY14"
#                    },
#                    "group_no": 15,
#                    "mac_address": "00BB.14CC.15DD",
#                    "preempt": {
#                        "minimum": 10,
#                        "reload": 100,
#                        "sync": 5
#                    },
#                    "priority": {
#                        "level": 22,
#                        "lower": 12,
#                        "upper": 22
#                    },
#                    "timer": {
#                        "hello_interval": 456,
#                        "hold_time": 33,
#                        "msec": true
#                    }
#                }
#            ]
#        },
#        {
#            "name": "Vlan1000",
#            "standby_options": [
#                {
#                    "authentication": {
#                        "key_string": "testmesecurte"
#                    },
#                    "group_name": "testhsr",
#                    "group_no": 10,
#                    "ip": [
#                        {
#                            "secondary": true,
#                            "virtual_ip": "10.15.8.1"
#                        }
#                    ],
#                    "mac_address": "0423.4567.89AB",
#                    "preempt": {
#                        "minimum": 33,
#                        "reload": 23,
#                        "sync": 22
#                    },
#                    "priority": {
#                        "level": 22,
#                        "lower": 12,
#                        "upper": 22
#                    },
#                    "timer": {
#                        "hello_interval": 456,
#                        "hold_time": 33,
#                        "msec": true
#                    }
#                }
#            ]}
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
    - hsrp 14
    - follow VLAN14-GROUP
    - mac-address 00AA.14BB.14CC
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - hsrp 14
    - follow VLAN14-GROUP
    - mac-address 00AA.14BB.14CC
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

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.hsrp_interfaces.hsrp_interfaces import (
    Hsrp_interfacesArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.config.hsrp_interfaces.hsrp_interfaces import (
    Hsrp_interfaces,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=Hsrp_interfacesArgs.argument_spec,
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

    result = Hsrp_interfaces(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
