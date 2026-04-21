#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_ospf_area
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_ospf_area
description: This module provides configuration for the area settings of OSPF running on SONiC switches
version_added: "2.5.0"
short_description: configure OSPF area settings on SONiC
author: "Xiao Han (@Xiao_Han2)"
options:
  config:
    description:
      - Specifies configuration for OSPFv2 areas
    type: list
    elements: dict
    suboptions:
      area_id:
        type: str
        required: true
        description:
          - Area ID of the network (A.B.C.D or 0 to 4294967295).
      vrf_name:
        type: str
        default: 'default'
        description: name of the vrf this area belongs to
      authentication_type:
        type: str
        choices:
          - message_digest
          - text
        description: authentication type for area
      default_cost:
        description:
          - Configure NSSA or stub area summary default cost
          - range is 0 to 16777215 inclusive
        type: int
      filter_list_in:
        type: str
        description:
          - inter area prefix filter list.
          - Filter incoming prefixes into the area.
          - expects name of a prefix list.
      filter_list_out:
        type: str
        description:
          - inter area prefix filter list.
          - Filter outgoing prefixes from the area.
          - expects name of a prefix list.
      networks:
        type: list
        elements: str
        description:
        - Configure networks in an area
        - is a masked ip address
      ranges:
        type: list
        elements: dict
        description: Configure address range summarization on border routers
        suboptions:
          prefix:
            type: str
            required: true
            description:
              - address range prefix
              - is a masked ip address
          advertise:
            type: bool
            description:
              - enable address range advertising
              - default of true
          cost:
            type: int
            description:
              - configure cost of address range
              - range is 0 to 16777215 inclusive
          substitute:
            type: str
            description:
              - Configure substitute prefix for the address range
              - is a masked ip address
      shortcut:
        type: str
        choices:
          - default
          - disable
          - enable
        description: Configure area's shortcut mode
      stub:
        type: dict
        description: configuration for stub type area
        suboptions:
          enabled:
            type: bool
            description: configure area as stub type area
          no_summary:
            type: bool
            description: disable inter-area route injection into the stub
      virtual_links:
        type: list
        elements: dict
        description: configuration for virtual links
        suboptions:
          enabled:
            type: bool
            description:
              - enable virtual link
              - virtual link must be enabled for creation
          router_id:
            type: str
            required: true
            description:
             - router id of the remote ABR
             - ip address format
          dead_interval:
            type: int
            description:
              - configure adjacency dead interval
              - value is in seconds
              - range is 1 to 65535 inclusive
          hello_interval:
            type: int
            description:
              - configure neighbor hello interval
              - value is in seconds
              - range is 1 to 65535 inclusive
          retransmit_interval:
            type: int
            description:
              - configure LSA retransmit interval
              - value is in seconds
              - range is 1 to 65535 inclusive
          transmit_delay:
            type: int
            description:
              - configure LSA transmit delay
              - value is in seconds
              - range is 1 to 65535 inclusive
          authentication:
            type: dict
            description: configure authentication settings for virtual link
            suboptions:
              auth_type:
                type: str
                choices:
                  - message_digest
                  - text
                  - none
                description: authentication type for virtual link
              key:
                type: str
                description: text authentication password for virtual link
              key_encrypted:
                type: bool
                description: password is in encrypted format
          message_digest_list:
            type: list
            elements: dict
            description:
              - configure message-digest authentication keys
              - For deletion, only the key_id is used.
            suboptions:
              key_id:
                type: int
                required: true
                description:
                  - message-digest authentication key id
                  - range is 1 to 255 inclusive
              key:
                type: str
                description: authentication password (ignored for deletion)
              key_encrypted:
                type: bool
                description: password is in encrypted format (ignored for deletion)
  state:
    description:
      - Specifies the type of configuration update to be performed on the device.
    type: str
    choices:
      - merged
      - replaced
      - overridden
      - deleted
    default: merged
"""

EXAMPLES = """
# NOTE: Configuration of an OSPF network instance (VRF) is required before an OSPF "area" can
# be configured in association with that network instance (VRF).

# ============ MERGED ==================

# Scenario: Using "merged" state to add or change ospf_area settings
# merging all settings for an area

# Before state:

# sonic# show running-configuration ospf
# router ospf vrf Vrf1
# !
# router ospf vrf Vrf2
# !

# example:
- name: merge examples of all settings
  sonic_ospf_area:
    state: merged
    config:
      - area_id: 2
        vrf_name: Vrf1
        authentication_type: message_digest
        default_cost: 3
        stub:
          enabled: true
          no_summary: true
        shortcut: default
      - area_id: 3
        vrf_name: Vrf1
        filter_list_in: pf1
        filter_list_out: pf2
        ranges:
          - prefix: 1.1.1.1/24
          - prefix: 1.1.1.2/24
            advertise: true
            cost: 4
          - prefix: 1.1.1.3/24
            advertise: false
          - prefix: 1.1.1.4/24
            advertise: true
            cost: 10
            substitute: 3.3.3.3/24
      - area_id: 4
        vrf_name: Vrf1
        networks:
          - 1.1.1.1/24
          - 3.5.1.5/23
          - 23.235.75.1/23
      - area_id: 5
        vrf_name: Vrf1
        virtual_links:
          - router_id: 34.7.35.1
            enabled: true
          - router_id: 34.7.35.2
            enabled: true
            dead_interval: 30
            hello_interval: 10
            retransmit_interval: 40
            transmit_delay: 50
            authentication:
              auth_type: text
              key: "U2FsdGVkX197YJtZ/3Ac6n5kRIG/ZqeU1/wC0cVFyfU="
              key_encrypted: true
            message_digest_list:
              - key_id: 1
                key: "U2FsdGVkX1/wbqjMB7Lr+Mm3wY8+lCdaqUmG2rr9Adw="
                key_encrypted: true
              - key_id: 2
                key: "U2FsdGVkX18Czj9r8skDrg/wtpwTKKCQ8FXUehpCmHc="
                key_encrypted: true

# After state

# sonic# show running-configuration ospf
# router ospf vrf Vrf1
#  area 0.0.0.2 authentication message-digest
#  area 0.0.0.2 stub no-summary
#  area 0.0.0.2 default-cost 3
#  area 0.0.0.2 shortcut default
#  area 0.0.0.3 filter-list prefix pf1 in
#  area 0.0.0.3 filter-list prefix pf2 out
#  area 0.0.0.4
#  area 0.0.0.5
#  area 0.0.0.5 virtual-link 34.7.35.1
#  area 0.0.0.5 virtual-link 34.7.35.2
#  area 0.0.0.5 virtual-link 34.7.35.2 authentication
#  area 0.0.0.5 virtual-link 34.7.35.2 authentication-key U2FsdGVkX197YJtZ/3Ac6n5kRIG/ZqeU1/wC0cVFyfU= encrypted
#  area 0.0.0.5 virtual-link 34.7.35.2 dead-interval 30
#  area 0.0.0.5 virtual-link 34.7.35.2 hello-interval 10
#  area 0.0.0.5 virtual-link 34.7.35.2 retransmit-interval 40
#  area 0.0.0.5 virtual-link 34.7.35.2 transmit-delay 50
#  area 0.0.0.5 virtual-link 34.7.35.2 message-digest-key 1 md5 U2FsdGVkX1/wbqjMB7Lr+Mm3wY8+lCdaqUmG2rr9Adw= encrypted
#  area 0.0.0.5 virtual-link 34.7.35.2 message-digest-key 2 md5 U2FsdGVkX18Czj9r8skDrg/wtpwTKKCQ8FXUehpCmHc= encrypted
#  area 0.0.0.3 range 1.1.1.1/24
#  area 0.0.0.3 range 1.1.1.2/24 advertise cost 4
#  area 0.0.0.3 range 1.1.1.3/24 not-advertise
#  area 0.0.0.3 range 1.1.1.4/24 advertise cost 10
#  area 0.0.0.3 range 1.1.1.4/24 substitute 3.3.3.3/24
#  network 1.1.1.1/24 area 0.0.0.4
#  network 23.235.75.1/23 area 0.0.0.4
#  network 3.5.1.5/23 area 0.0.0.4
# !
# router ospf vrf Vrf2
# !
# -----

# Scenario: minimum data for config subsections

# Before state:

# sonic# show running-configuration ospf
# router ospf vrf Vrf1
# !
# router ospf vrf Vrf2
# !

# example:
- name: merge smallest group of settings
  sonic_ospf_area:
    state: merged
    config:
      - area_id: 0.0.0.2
        vrf_name: Vrf1
        networks:
          - 1.1.1.1/24
      - area_id: 0.0.0.3
        vrf_name: Vrf1
        ranges:
          - prefix: 1.1.1.1/24
      - area_id: 0.0.0.4
        vrf_name: Vrf1
        virtual_links:
          - router_id: 34.7.35.1
            enabled: true
      - area_id: 0.0.0.5
        vrf_name: Vrf1
        virtual_links:
          - router_id: 34.7.35.1
            enabled: true
            message_digest_list:
              - key_id: 1
                key: grighr
# NOTE: The existence of an 'area' is only displayed by this Ansible module if configuration options are
# currently configured for that area. (An "area" that currently has no configured sub-options is not displayed.)

# After state

# sonic# show running-configuration ospf
# router ospf vrf Vrf1
#  area 0.0.0.2
#  area 0.0.0.3
#  area 0.0.0.4
#  area 0.0.0.5
#  area 0.0.0.4 virtual-link 34.7.35.1
#  area 0.0.0.5 virtual-link 34.7.35.1
#  area 0.0.0.5 virtual-link 34.7.35.1 message-digest-key 1 md5 U2FsdGVkX19oCaX2HsxLR2nWtyK15AfE7ajHVjzgoaY= encrypted
#  area 0.0.0.3 range 1.1.1.1/24
#  network 1.1.1.1/24 area 0.0.0.2
# !
# router ospf vrf Vrf2
# !
# -----

# Scenario: merging and making changes to attributes

# Before state:

# sonic# show running-configuration ospf
# router ospf vrf Vrf1
#  area 0.0.0.1 authentication message-digest
#  area 0.0.0.1 stub no-summary
#  area 0.0.0.1 default-cost 6
#  area 0.0.0.1 filter-list prefix pf1 in
#  area 0.0.0.1 filter-list prefix pf2 out
#  area 0.0.0.1 shortcut disable
#  area 0.0.0.1 virtual-link 1.1.1.1
#  area 0.0.0.1 virtual-link 1.1.1.1 authentication
#  area 0.0.0.1 virtual-link 1.1.1.1 authentication-key U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ= encrypted
#  area 0.0.0.1 virtual-link 1.1.1.1 dead-interval 20
#  area 0.0.0.1 virtual-link 1.1.1.1 hello-interval 10
#  area 0.0.0.1 virtual-link 1.1.1.1 retransmit-interval 10
#  area 0.0.0.1 virtual-link 1.1.1.1 transmit-delay 10
#  area 0.0.0.1 virtual-link 1.1.1.2
#  area 0.0.0.1 virtual-link 1.1.1.2 dead-interval 34
#  area 0.0.0.1 virtual-link 1.1.1.1 message-digest-key 1 md5 U2FsdGVkX1//fyBCsQYQI4q743L8Rf1Q1qUOEc75lNM= encrypted
#  area 0.0.0.1 virtual-link 1.1.1.1 message-digest-key 2 md5 U2FsdGVkX18tvS+HyOt1zIbx9P8I9NMguQ17NZGd9ZY= encrypted
#  area 0.0.0.1 range 1.1.1.1/24 not-advertise
#  area 0.0.0.1 range 1.1.1.2/24 advertise
#  network 1.1.1.1/24 area 0.0.0.1
#  network 1.1.1.2/24 area 0.0.0.1
# !
# router ospf vrf Vrf2
# !

# example:
- name: "test merge all settings"
  sonic_ospf_area:
    state: merged
    config:
      - area_id: 0.0.0.1
        vrf_name: Vrf1
        authentication_type: text
        default_cost: 5
        filter_list_in: pf2
        filter_list_out: pf1
        networks:
          - 1.1.1.5/24
        ranges:
          - prefix: 1.1.1.1/24
            advertise: true
            cost: 12
            substitute: 11.11.1.1/24
          - prefix: 1.1.1.2/24
            advertise: false
        shortcut: enable
        stub:
          enabled: true
          no_summary: false
        virtual_links:
          - router_id: 1.1.1.1
            enabled: true
            dead_interval: 45
            hello_interval: 21
            retransmit_interval: 15
            transmit_delay: 23
            authentication:
              auth_type: text
              key: "U2FsdGVkX1/lz7KE/onDUAhQU2nftsm/nddLb2ZvYSQ="
              key_encrypted: true
            message_digest_list:
              - key_id: 1
                key: "somepass"
          - router_id: 1.1.1.2
            enabled: true
            dead_interval: 16

# After state

# sonic# show running-configuration ospf
# router ospf vrf Vrf1
#  area 0.0.0.1 authentication
#  area 0.0.0.1 stub
#  area 0.0.0.1 default-cost 5
#  area 0.0.0.1 filter-list prefix pf2 in
#  area 0.0.0.1 filter-list prefix pf1 out
#  area 0.0.0.1 shortcut enable
#  area 0.0.0.1 virtual-link 1.1.1.1
#  area 0.0.0.1 virtual-link 1.1.1.1 authentication
#  area 0.0.0.1 virtual-link 1.1.1.1 authentication-key U2FsdGVkX1/lz7KE/onDUAhQU2nftsm/nddLb2ZvYSQ= encrypted
#  area 0.0.0.1 virtual-link 1.1.1.1 dead-interval 45
#  area 0.0.0.1 virtual-link 1.1.1.1 hello-interval 21
#  area 0.0.0.1 virtual-link 1.1.1.1 retransmit-interval 15
#  area 0.0.0.1 virtual-link 1.1.1.1 transmit-delay 23
#  area 0.0.0.1 virtual-link 1.1.1.2
#  area 0.0.0.1 virtual-link 1.1.1.2 dead-interval 16
#  area 0.0.0.1 virtual-link 1.1.1.1 message-digest-key 1 md5 U2FsdGVkX18D0swlrl3pVzMGxRZYzY58X06jPq2CrNU= encrypted
#  area 0.0.0.1 virtual-link 1.1.1.1 message-digest-key 2 md5 U2FsdGVkX18tvS+HyOt1zIbx9P8I9NMguQ17NZGd9ZY= encrypted
#  area 0.0.0.1 range 1.1.1.1/24 advertise cost 12
#  area 0.0.0.1 range 1.1.1.1/24 substitute 11.11.1.1/24
#  area 0.0.0.1 range 1.1.1.2/24 not-advertise
#  network 1.1.1.1/24 area 0.0.0.1
#  network 1.1.1.2/24 area 0.0.0.1
#  network 1.1.1.5/24 area 0.0.0.1
# !
# router ospf vrf Vrf2
# !
# -----

# Scenario: merging different keys

# Before state:

# sonic# show running-configuration ospf
# router ospf vrf Vrf1
# !
# router ospf vrf Vrf2
# !

# example:
- name: "test merge different keys"
  sonic_ospf_area:
    state: merged
    config:
      - area_id: 0.0.0.1
        vrf_name: Vrf1
        virtual_links:
          - router_id: 1.1.1.1
            enabled: true
            authentication:
              key: qwerty
              key_encrypted: false
          - router_id: 1.1.1.3
            enabled: true
            authentication:
              key: "U2FsdGVkX1/lz7KE/onDUAhQU2nftsm/nddLb2ZvYSQ="
              key_encrypted: true
          - router_id: 1.1.1.4
            enabled: true
            authentication:
              key: somepass

# After state

# sonic# show running-configuration ospf
# router ospf vrf Vrf1
#  area 0.0.0.1
#  area 0.0.0.1 virtual-link 1.1.1.1
#  area 0.0.0.1 virtual-link 1.1.1.1 authentication-key U2FsdGVkX180JKbs3Rf5IyLot8UW0/srcXdGaQXEHiw= encrypted
#  area 0.0.0.1 virtual-link 1.1.1.3
#  area 0.0.0.1 virtual-link 1.1.1.3 authentication-key U2FsdGVkX1/lz7KE/onDUAhQU2nftsm/nddLb2ZvYSQ= encrypted
#  area 0.0.0.1 virtual-link 1.1.1.4
#  area 0.0.0.1 virtual-link 1.1.1.4 authentication-key U2FsdGVkX1+2i/anKXKpEfwZIAkb1Hzkx1nH2IBnlMA= encrypted
# !
# router ospf vrf Vrf2
# !
# Note: the device automatically converts keys to encrypted format
# ----------

# ============ DELETED ==================

# using deleted to remove ospf settings
# Scenario: deleting all settings for areas

# Before state:

# sonic# show running-configuration ospf
# router ospf vrf Vrf1
#  area 0.0.0.1 authentication message-digest
#  area 0.0.0.1 stub no-summary
#  area 0.0.0.1 default-cost 6
#  area 0.0.0.1 filter-list prefix pf1 in
#  area 0.0.0.1 filter-list prefix pf2 out
#  area 0.0.0.1 shortcut disable
#  area 0.0.0.2 stub no-summary
#  area 0.0.0.2 shortcut disable
#  area 0.0.0.3 shortcut default
#  area 0.0.0.1 virtual-link 1.1.1.1
#  area 0.0.0.1 virtual-link 1.1.1.1 authentication
#  area 0.0.0.1 virtual-link 1.1.1.1 authentication-key U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ= encrypted
#  area 0.0.0.1 virtual-link 1.1.1.1 dead-interval 20
#  area 0.0.0.1 virtual-link 1.1.1.1 hello-interval 10
#  area 0.0.0.1 virtual-link 1.1.1.1 retransmit-interval 10
#  area 0.0.0.1 virtual-link 1.1.1.1 transmit-delay 10
#  area 0.0.0.1 virtual-link 1.1.1.2
#  area 0.0.0.1 virtual-link 1.1.1.2 dead-interval 34
#  area 0.0.0.1 virtual-link 1.1.1.1 message-digest-key 1 md5 U2FsdGVkX1//fyBCsQYQI4q743L8Rf1Q1qUOEc75lNM= encrypted
#  area 0.0.0.1 virtual-link 1.1.1.1 message-digest-key 2 md5 U2FsdGVkX18tvS+HyOt1zIbx9P8I9NMguQ17NZGd9ZY= encrypted
#  area 0.0.0.1 range 1.1.1.1/24 not-advertise
#  area 0.0.0.1 range 1.1.1.2/24 advertise
#  area 0.0.0.2 range 1.1.1.1/24 advertise
#  area 0.0.0.3 range 1.1.4.6/24 cost 14
#  network 1.1.1.1/24 area 0.0.0.1
#  network 1.1.1.2/24 area 0.0.0.1
# !
# router ospf vrf Vrf2
# !

# example:
- name: "test delete all settings for areas"
  sonic_ospf_area:
    state: deleted
    config:
      - area_id: 0.0.0.1
        vrf_name: Vrf1
      - area_id: 0.0.0.2
        vrf_name: Vrf1
        ranges:
          - prefix: 1.1.1.1/24
        shortcut: disable
        stub:
          enabled: true
          no_summary: true

# After state

# sonic# show running-configuration ospf
# router ospf vrf Vrf1
#  area 0.0.0.3 shortcut default
#  area 0.0.0.3 range 1.1.4.6/24 cost 14
# !
# router ospf vrf Vrf2
# !
# -----


# Scenario: clearing subsections of config

# Before state:

# sonic# show running-configuration ospf
# router ospf vrf Vrf1
#  area 0.0.0.1 shortcut default
#  area 0.0.0.2 authentication message-digest
#  area 0.0.0.3 filter-list prefix pf1 in
#  area 0.0.0.4
#  area 0.0.0.3 virtual-link 34.7.35.1
#  area 0.0.0.3 virtual-link 34.7.35.1 hello-interval 30
#  area 0.0.0.3 virtual-link 34.7.35.1 transmit-delay 50
#  area 0.0.0.3 virtual-link 34.7.35.2
#  area 0.0.0.3 virtual-link 34.7.35.2 dead-interval 10
#  area 0.0.0.3 virtual-link 34.7.35.2 retransmit-interval 40
#  area 0.0.0.4 virtual-link 34.7.35.1
#  area 0.0.0.4 virtual-link 34.7.35.1 authentication
#  area 0.0.0.4 virtual-link 34.7.35.1 authentication-key U2FsdGVkX1/lz7KE/onDUAhQU2nftsm/nddLb2ZvYSQ= encrypted
#  area 0.0.0.4 virtual-link 34.7.35.1 dead-interval 10
#  area 0.0.0.4 virtual-link 34.7.35.2
#  area 0.0.0.4 virtual-link 34.7.35.2 dead-interval 10
#  area 0.0.0.4 virtual-link 34.7.35.2 message-digest-key 1 md5 U2FsdGVkX18mUZjlJL/Q/7vYtx2UyDc+NcLKc/BOJUA= encrypted
#  area 0.0.0.4 virtual-link 34.7.35.2 message-digest-key 3 md5 U2FsdGVkX19SlRpqsnpeRmjq7WmtctYtveHlYF0Faqo= encrypted
#  area 0.0.0.1 range 1.1.1.2/24 advertise cost 4
#  area 0.0.0.1 range 1.1.1.3/24 not-advertise
#  network 1.1.1.1/24 area 0.0.0.2
#  network 23.235.75.1/23 area 0.0.0.2
#  network 3.5.1.5/23 area 0.0.0.2
# !
# router ospf vrf Vrf2
# !

# example:
- name: "test clear subsections"
  sonic_ospf_area:
    state: deleted
    config:
      - area_id: 0.0.0.1
        vrf_name: Vrf1
        ranges: []
      - area_id: 0.0.0.2
        vrf_name: Vrf1
        networks: []
      - area_id: 0.0.0.3
        vrf_name: Vrf1
        virtual_links: []
      - area_id: 4
        vrf_name: Vrf1
        virtual_links:
          - router_id: 34.7.35.1
            authentication: {}
          - router_id: 34.7.35.2
            message_digest_list: []

# After state

# sonic# show running-configuration ospf
# router ospf vrf Vrf1
#  area 0.0.0.1 shortcut default
#  area 0.0.0.2 authentication message-digest
#  area 0.0.0.3 filter-list prefix pf1 in
#  area 0.0.0.4
#  area 0.0.0.4 virtual-link 34.7.35.1
#  area 0.0.0.4 virtual-link 34.7.35.1 dead-interval 10
#  area 0.0.0.4 virtual-link 34.7.35.2
#  area 0.0.0.4 virtual-link 34.7.35.2 dead-interval 10
# !
# router ospf vrf Vrf2
# !
# -----

# Scenario: deleting individual attributes

# Before state:

# sonic# show running-configuration ospf
# router ospf vrf Vrf1
#  area 0.0.0.1 filter-list prefix pf1 in
#  area 0.0.0.1 filter-list prefix pf2 out
#  area 0.0.0.2 authentication message-digest
#  area 0.0.0.3
#  area 0.0.0.4 stub no-summary
#  area 0.0.0.4 default-cost 3
#  area 0.0.0.4 shortcut default
#  area 0.0.0.5 stub
#  area 0.0.0.5 default-cost 5
#  area 0.0.0.3 virtual-link 34.7.35.1
#  area 0.0.0.3 virtual-link 34.7.35.1 authentication
#  area 0.0.0.3 virtual-link 34.7.35.1 authentication-key U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ= encrypted
#  area 0.0.0.3 virtual-link 34.7.35.1 hello-interval 30
#  area 0.0.0.3 virtual-link 34.7.35.1 transmit-delay 50
#  area 0.0.0.3 virtual-link 34.7.35.2
#  area 0.0.0.3 virtual-link 34.7.35.2 authentication message-digest
#  area 0.0.0.3 virtual-link 34.7.35.2 authentication-key U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ= encrypted
#  area 0.0.0.3 virtual-link 34.7.35.2 dead-interval 10
#  area 0.0.0.3 virtual-link 34.7.35.2 retransmit-interval 40
#  area 0.0.0.3 virtual-link 34.7.35.2 transmit-delay 50
#  area 0.0.0.3 virtual-link 34.7.35.2 message-digest-key 1 md5 U2FsdGVkX18mUZjlJL/Q/7vYtx2UyDc+NcLKc/BOJUA= encrypted
#  area 0.0.0.3 virtual-link 34.7.35.2 message-digest-key 3 md5 U2FsdGVkX19SlRpqsnpeRmjq7WmtctYtveHlYF0Faqo= encrypted
#  area 0.0.0.1 range 1.1.1.1/24 advertise cost 13
#  area 0.0.0.1 range 1.1.1.1/24 substitute 11.2.5.1/24
#  area 0.0.0.1 range 1.1.1.2/24 advertise cost 4
#  area 0.0.0.1 range 1.1.1.3/24 advertise
#  area 0.0.0.1 range 1.1.1.3/24 substitute 2.2.2.2/24
#  area 0.0.0.1 range 1.1.1.4/24 advertise cost 34
#  area 0.0.0.1 range 1.1.1.4/24 substitute 3.3.3.3/24
#  network 1.1.1.1/24 area 0.0.0.2
#  network 23.235.75.1/23 area 0.0.0.2
#  network 3.5.1.5/23 area 0.0.0.2
# !
# router ospf vrf Vrf2
# !

# example:
- name: "delete individual attributes"
  sonic_ospf_area:
    state: deleted
    config:
      - area_id: 0.0.0.1
        vrf_name: Vrf1
        filter_list_in: pf1
        filter_list_out: pf2
        ranges:
          - prefix: 1.1.1.1/24
          - prefix: 1.1.1.2/24
            cost: 4
          - prefix: 1.1.1.3/24
            substitute: 2.2.2.2/24
      - area_id: 0.0.0.2
        vrf_name: Vrf1
        authentication_type: message_digest
        networks:
          - 1.1.1.1/24
          - 3.5.1.5/23
      - area_id: 3
        vrf_name: Vrf1
        virtual_links:
          - router_id: 34.7.35.1
            transmit_delay: 50
            hello_interval: 30
            authentication:
              auth_type: text
          - router_id: 34.7.35.2
            enabled: true
            dead_interval: 10
            retransmit_interval: 40
            message_digest_list:
              - key_id: 1
            authentication:
              key: "U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ="
              key_encrypted: true
      - area_id: 4
        vrf_name: Vrf1
        shortcut: default
        stub:
          enabled: true
          no_summary: true
      - area_id: 5
        vrf_name: Vrf1
        default_cost: 5
        stub:
          enabled: true

# After state

# sonic# show running-configuration ospf
# router ospf vrf Vrf1
#  area 0.0.0.1
#  area 0.0.0.2
#  area 0.0.0.3
#  area 0.0.0.4 default-cost 3
#  area 0.0.0.5
#  area 0.0.0.3 virtual-link 34.7.35.1
#  area 0.0.0.3 virtual-link 34.7.35.1 authentication-key U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ= encrypted
#  area 0.0.0.3 virtual-link 34.7.35.2
#  area 0.0.0.3 virtual-link 34.7.35.2 authentication message-digest
#  area 0.0.0.3 virtual-link 34.7.35.2 transmit-delay 50
#  area 0.0.0.3 virtual-link 34.7.35.2 message-digest-key 3 md5 U2FsdGVkX19SlRpqsnpeRmjq7WmtctYtveHlYF0Faqo= encrypted
#  area 0.0.0.1 range 1.1.1.2/24 advertise
#  area 0.0.0.1 range 1.1.1.3/24 advertise
#  area 0.0.0.1 range 1.1.1.4/24 advertise cost 34
#  area 0.0.0.1 range 1.1.1.4/24 substitute 3.3.3.3/24
#  network 23.235.75.1/23 area 0.0.0.2
# !
# router ospf vrf Vrf2
# !
# -----
# ----------


# ============ REPLACED ==================

# Scenario: Replace listed areas

# Before state:

# sonic# show running-configuration ospf
# router ospf vrf Vrf1
#  area 0.0.0.1 filter-list prefix pf1 in
#  area 0.0.0.1 filter-list prefix pf2 out
#  area 0.0.0.2 authentication message-digest
#  area 0.0.0.3
#  area 0.0.0.4 stub no-summary
#  area 0.0.0.4 default-cost 3
#  area 0.0.0.4 shortcut default
#  area 0.0.0.5 stub
#  area 0.0.0.5 default-cost 5
#  area 0.0.0.3 virtual-link 34.7.35.1
#  area 0.0.0.3 virtual-link 34.7.35.1 authentication
#  area 0.0.0.3 virtual-link 34.7.35.1 authentication-key U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ= encrypted
#  area 0.0.0.3 virtual-link 34.7.35.1 hello-interval 30
#  area 0.0.0.3 virtual-link 34.7.35.1 transmit-delay 50
#  area 0.0.0.3 virtual-link 34.7.35.2
#  area 0.0.0.3 virtual-link 34.7.35.2 authentication message-digest
#  area 0.0.0.3 virtual-link 34.7.35.2 authentication-key U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ= encrypted
#  area 0.0.0.3 virtual-link 34.7.35.2 dead-interval 10
#  area 0.0.0.3 virtual-link 34.7.35.2 retransmit-interval 40
#  area 0.0.0.3 virtual-link 34.7.35.2 transmit-delay 50
#  area 0.0.0.3 virtual-link 34.7.35.2 message-digest-key 1 md5 U2FsdGVkX18mUZjlJL/Q/7vYtx2UyDc+NcLKc/BOJUA= encrypted
#  area 0.0.0.3 virtual-link 34.7.35.2 message-digest-key 3 md5 U2FsdGVkX19SlRpqsnpeRmjq7WmtctYtveHlYF0Faqo= encrypted
#  area 0.0.0.1 range 1.1.1.1/24 advertise cost 13
#  area 0.0.0.1 range 1.1.1.1/24 substitute 11.2.5.1/24
#  area 0.0.0.1 range 1.1.1.2/24 advertise cost 4
#  area 0.0.0.1 range 1.1.1.3/24 advertise
#  area 0.0.0.1 range 1.1.1.3/24 substitute 2.2.2.2/24
#  area 0.0.0.1 range 1.1.1.4/24 advertise cost 34
#  area 0.0.0.1 range 1.1.1.4/24 substitute 3.3.3.3/24
#  network 1.1.1.1/24 area 0.0.0.2
#  network 23.235.75.1/23 area 0.0.0.2
#  network 3.5.1.5/23 area 0.0.0.2
# !
# router ospf vrf Vrf2
# !

# example:
- name: "replace areas"
  sonic_ospf_area:
    state: replaced
    config:
      - area_id: 0.0.0.1
        vrf_name: Vrf1
        authentication_type: message_digest
        networks:
          - 1.1.1.1/24
          - 3.5.1.5/23
          - 23.235.75.1/23
        default_cost: 5
        stub:
          enabled: true
          no_summary: false
      - area_id: 0.0.0.2
        vrf_name: Vrf1
        filter_list_in: pf1
        filter_list_out: pf2
        shortcut: default
        default_cost: 3
        stub:
          enabled: true
          no_summary: true
        authentication_type: message_digest
        networks:
          - 1.1.1.1/24
          - 3.5.1.5/23
          - 23.235.75.1/23
      - area_id: 3
        vrf_name: Vrf1
        virtual_links:
          - router_id: 34.7.35.1
            enabled: true
            transmit_delay: 50
            hello_interval: 30
            authentication:
              auth_type: text
              key: "U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ="
              key_encrypted: true
        ranges:
          - prefix: 1.1.1.1/24
            advertise: true
            substitute: 11.2.5.1/24
          - prefix: 1.1.1.2/24
            advertise: true
            cost: 4
          - prefix: 1.1.1.3/24
            advertise: true
            substitute: 2.5.3.78/24
      - area_id: 4
        vrf_name: Vrf1
        shortcut: default
        virtual_links:
          - router_id: 34.7.35.1
            enabled: true
            transmit_delay: 50
            hello_interval: 30
            authentication:
              auth_type: text
              key: "U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ="
              key_encrypted: true
          - router_id: 34.7.35.2
            transmit_delay: 50
            enabled: true
            dead_interval: 10
            retransmit_interval: 40
            message_digest_list:
              - key_id: 1
                key: "U2FsdGVkX18mUZjlJL/Q/7vYtx2AUyDc+NcLKc/BOJUA="
                key_encrypted: true
              - key_id: 3
                key: "U2FsdGVkX19SlRpqsnpeRmjq7WmtctYtveHlYF0Faqo="
                key_encrypted: true
            authentication:
              auth_type: message_digest
              key: "U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ="
              key_encrypted: true

# After state

# sonic# show running-configuration ospf
# router ospf vrf Vrf1
#  area 0.0.0.1 authentication message-digest
#  area 0.0.0.1 stub
#  area 0.0.0.1 default-cost 5
#  area 0.0.0.2 authentication message-digest
#  area 0.0.0.2 stub no-summary
#  area 0.0.0.2 default-cost 3
#  area 0.0.0.2 filter-list prefix pf1 in
#  area 0.0.0.2 filter-list prefix pf2 out
#  area 0.0.0.2 shortcut default
#  area 0.0.0.3
#  area 0.0.0.4 shortcut default
#  area 0.0.0.5 stub
#  area 0.0.0.5 default-cost 5
#  area 0.0.0.3 virtual-link 34.7.35.1
#  area 0.0.0.3 virtual-link 34.7.35.1 authentication
#  area 0.0.0.3 virtual-link 34.7.35.1 authentication-key U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ= encrypted
#  area 0.0.0.3 virtual-link 34.7.35.1 hello-interval 30
#  area 0.0.0.3 virtual-link 34.7.35.1 transmit-delay 50
#  area 0.0.0.4 virtual-link 34.7.35.1
#  area 0.0.0.4 virtual-link 34.7.35.1 authentication
#  area 0.0.0.4 virtual-link 34.7.35.1 authentication-key U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ= encrypted
#  area 0.0.0.4 virtual-link 34.7.35.1 hello-interval 30
#  area 0.0.0.4 virtual-link 34.7.35.1 transmit-delay 50
#  area 0.0.0.4 virtual-link 34.7.35.2
#  area 0.0.0.4 virtual-link 34.7.35.2 authentication message-digest
#  area 0.0.0.4 virtual-link 34.7.35.2 authentication-key U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ= encrypted
#  area 0.0.0.4 virtual-link 34.7.35.2 dead-interval 10
#  area 0.0.0.4 virtual-link 34.7.35.2 retransmit-interval 40
#  area 0.0.0.4 virtual-link 34.7.35.2 transmit-delay 50
#  area 0.0.0.4 virtual-link 34.7.35.2 message-digest-key 1 md5 U2FsdGVkX18mUZjlJL/Q/7vYtx2UyDc+NcLKc/BOJUA= encrypted
#  area 0.0.0.4 virtual-link 34.7.35.2 message-digest-key 3 md5 U2FsdGVkX19SlRpqsnpeRmjq7WmtctYtveHlYF0Faqo= encrypted
#  area 0.0.0.3 range 1.1.1.1/24 advertise
#  area 0.0.0.3 range 1.1.1.1/24 substitute 11.2.5.1/24
#  area 0.0.0.3 range 1.1.1.2/24 advertise cost 4
#  area 0.0.0.3 range 1.1.1.3/24 advertise
#  area 0.0.0.3 range 1.1.1.3/24 substitute 2.5.3.78/24
#  network 1.1.1.1/24 area 0.0.0.1
#  network 23.235.75.1/23 area 0.0.0.1
#  network 3.5.1.5/23 area 0.0.0.1
#  network 1.1.1.1/24 area 0.0.0.2
#  network 23.235.75.1/23 area 0.0.0.2
#  network 3.5.1.5/23 area 0.0.0.2
# !
# router ospf vrf Vrf2
# !
# ----------

# ============ OVERRIDDEN ==================

# Scenario: override listed areas

# Before state:

# sonic# show running-configuration ospf
# router ospf vrf Vrf1
#  area 0.0.0.1 filter-list prefix pf1 in
#  area 0.0.0.1 filter-list prefix pf2 out
#  area 0.0.0.2 authentication message-digest
#  area 0.0.0.3
#  area 0.0.0.4 stub no-summary
#  area 0.0.0.4 default-cost 3
#  area 0.0.0.4 shortcut default
#  area 0.0.0.5 stub
#  area 0.0.0.5 default-cost 5
#  area 0.0.0.3 virtual-link 34.7.35.1
#  area 0.0.0.3 virtual-link 34.7.35.1 authentication
#  area 0.0.0.3 virtual-link 34.7.35.1 authentication-key U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ= encrypted
#  area 0.0.0.3 virtual-link 34.7.35.1 hello-interval 30
#  area 0.0.0.3 virtual-link 34.7.35.1 transmit-delay 50
#  area 0.0.0.3 virtual-link 34.7.35.2
#  area 0.0.0.3 virtual-link 34.7.35.2 authentication message-digest
#  area 0.0.0.3 virtual-link 34.7.35.2 authentication-key U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ= encrypted
#  area 0.0.0.3 virtual-link 34.7.35.2 dead-interval 10
#  area 0.0.0.3 virtual-link 34.7.35.2 retransmit-interval 40
#  area 0.0.0.3 virtual-link 34.7.35.2 transmit-delay 50
#  area 0.0.0.3 virtual-link 34.7.35.2 message-digest-key 1 md5 U2FsdGVkX18mUZjlJL/Q/7vYtx2UyDc+NcLKc/BOJUA= encrypted
#  area 0.0.0.3 virtual-link 34.7.35.2 message-digest-key 3 md5 U2FsdGVkX19SlRpqsnpeRmjq7WmtctYtveHlYF0Faqo= encrypted
#  area 0.0.0.1 range 1.1.1.1/24 advertise cost 13
#  area 0.0.0.1 range 1.1.1.1/24 substitute 11.2.5.1/24
#  area 0.0.0.1 range 1.1.1.2/24 advertise cost 4
#  area 0.0.0.1 range 1.1.1.3/24 advertise
#  area 0.0.0.1 range 1.1.1.3/24 substitute 2.2.2.2/24
#  area 0.0.0.1 range 1.1.1.4/24 advertise cost 34
#  area 0.0.0.1 range 1.1.1.4/24 substitute 3.3.3.3/24
#  network 1.1.1.1/24 area 0.0.0.2
#  network 23.235.75.1/23 area 0.0.0.2
#  network 3.5.1.5/23 area 0.0.0.2
# !
# router ospf vrf Vrf2
# !

# example:
- name: "override areas"
  sonic_ospf_area:
    state: overridden
    config:
      - area_id: 0.0.0.1
        vrf_name: Vrf1
        authentication_type: message_digest
        networks:
          - 1.1.1.1/24
          - 3.5.1.5/23
          - 23.235.75.1/23
        default_cost: 5
        stub:
          enabled: true
          no_summary: false
      - area_id: 0.0.0.2
        vrf_name: Vrf1
        filter_list_in: pf1
        filter_list_out: pf2
        shortcut: default
        default_cost: 3
        stub:
          enabled: true
          no_summary: true
        authentication_type: message_digest
        networks:
          - 1.1.1.1/24
          - 3.5.1.5/23
          - 23.235.75.1/23
      - area_id: 3
        vrf_name: Vrf1
        virtual_links:
          - router_id: 34.7.35.1
            enabled: true
            transmit_delay: 50
            hello_interval: 30
            authentication:
              auth_type: text
              key: "U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ="
              key_encrypted: true
        ranges:
          - prefix: 1.1.1.1/24
            advertise: true
            substitute: 11.2.5.1/24
          - prefix: 1.1.1.2/24
            advertise: true
            cost: 4
          - prefix: 1.1.1.3/24
            advertise: true
            substitute: 2.5.3.78/24
      - area_id: 4
        vrf_name: Vrf1
        shortcut: default
        virtual_links:
          - router_id: 34.7.35.1
            enabled: true
            transmit_delay: 50
            hello_interval: 30
            authentication:
              auth_type: text
              key: "U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ="
              key_encrypted: true
          - router_id: 34.7.35.2
            transmit_delay: 50
            enabled: true
            dead_interval: 10
            retransmit_interval: 40
            message_digest_list:
              - key_id: 1
                key: "U2FsdGVkX18mUZjlJL/Q/7vYtx2UyDc+NcLKc/BOJUA="
                key_encrypted: true
              - key_id: 3
                key: "U2FsdGVkX19SlRpqsnpeRmjq7WmtctYtveHlYF0Faqo="
                key_encrypted: true
            authentication:
              auth_type: message_digest
              key: "U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ="
              key_encrypted: true

# After state

# sonic# show running-configuration ospf
# router ospf vrf Vrf1
#  area 0.0.0.1 authentication message-digest
#  area 0.0.0.1 stub
#  area 0.0.0.1 default-cost 5
#  area 0.0.0.2 authentication message-digest
#  area 0.0.0.2 stub no-summary
#  area 0.0.0.2 default-cost 3
#  area 0.0.0.2 filter-list prefix pf1 in
#  area 0.0.0.2 filter-list prefix pf2 out
#  area 0.0.0.2 shortcut default
#  area 0.0.0.3
#  area 0.0.0.4 shortcut default
#  area 0.0.0.3 virtual-link 34.7.35.1
#  area 0.0.0.3 virtual-link 34.7.35.1 authentication
#  area 0.0.0.3 virtual-link 34.7.35.1 authentication-key U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ= encrypted
#  area 0.0.0.3 virtual-link 34.7.35.1 hello-interval 30
#  area 0.0.0.3 virtual-link 34.7.35.1 transmit-delay 50
#  area 0.0.0.4 virtual-link 34.7.35.1
#  area 0.0.0.4 virtual-link 34.7.35.1 authentication
#  area 0.0.0.4 virtual-link 34.7.35.1 authentication-key U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ= encrypted
#  area 0.0.0.4 virtual-link 34.7.35.1 hello-interval 30
#  area 0.0.0.4 virtual-link 34.7.35.1 transmit-delay 50
#  area 0.0.0.4 virtual-link 34.7.35.2
#  area 0.0.0.4 virtual-link 34.7.35.2 authentication message-digest
#  area 0.0.0.4 virtual-link 34.7.35.2 authentication-key U2FsdGVkX18zN46d3pzk+t7TofEHAZGY+5RvgXMwDiQ= encrypted
#  area 0.0.0.4 virtual-link 34.7.35.2 dead-interval 10
#  area 0.0.0.4 virtual-link 34.7.35.2 retransmit-interval 40
#  area 0.0.0.4 virtual-link 34.7.35.2 transmit-delay 50
#  area 0.0.0.4 virtual-link 34.7.35.2 message-digest-key 1 md5 U2FsdGVkX18mUZjlJL/Q/7vYtx2UyDc+NcLKc/BOJUA= encrypted
#  area 0.0.0.4 virtual-link 34.7.35.2 message-digest-key 3 md5 U2FsdGVkX19SlRpqsnpeRmjq7WmtctYtveHlYF0Faqo= encrypted
#  area 0.0.0.3 range 1.1.1.1/24 advertise
#  area 0.0.0.3 range 1.1.1.1/24 substitute 11.2.5.1/24
#  area 0.0.0.3 range 1.1.1.2/24 advertise cost 4
#  area 0.0.0.3 range 1.1.1.3/24 advertise
#  area 0.0.0.3 range 1.1.1.3/24 substitute 2.5.3.78/24
#  network 1.1.1.1/24 area 0.0.0.1
#  network 23.235.75.1/23 area 0.0.0.1
#  network 3.5.1.5/23 area 0.0.0.1
#  network 1.1.1.1/24 area 0.0.0.2
#  network 23.235.75.1/23 area 0.0.0.2
#  network 3.5.1.5/23 area 0.0.0.2
# !
# router ospf vrf Vrf2
# !
# ----------
"""

RETURN = """
before:
  description: The configuration prior to the model invocation.
  returned: always
  type: list
  sample: >
    The configuration returned will always be in the same format
     as the parameters above.
after:
  description: The resulting configuration model invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
     as the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: [{"config": ..., "state": ...}, {"config": ..., "state": ...}]
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ospf_area.ospf_area import Ospf_areaArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.ospf_area.ospf_area import Ospf_area


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Ospf_areaArgs.argument_spec,
                           supports_check_mode=True)

    result = Ospf_area(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
