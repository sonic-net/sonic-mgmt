#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_mclag
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_mclag
version_added: 1.0.0
notes:
  - Tested against Enterprise SONiC Distribution by Dell Technologies.
  - Supports C(check_mode).
short_description: Manage multi chassis link aggregation groups domain (MCLAG) and its parameters
description:
  - Manage multi chassis link aggregation groups domain (MCLAG) and its parameters.
author: Abirami N (@abirami-n)

options:
  config:
    description: Dict of mclag domain configurations.
    type: dict
    suboptions:
      domain_id:
        description:
          - ID of the mclag domain (MCLAG domain).
        type: int
        required: True
      peer_address:
        description:
          - The IPV4 peer-ip for corresponding MCLAG.
        type: str
      source_address:
        description:
          - The IPV4 source-ip for corresponding MCLAG.
        type: str
      peer_link:
        description:
          - Peer-link for corresponding MCLAG.
        type: str
      system_mac:
        description:
          - MAC address of MCLAG.
        type: str
      keepalive:
        description:
          - MCLAG session keepalive-interval in secs.
        type: int
      session_timeout:
        description:
          - MCLAG session timeout value in secs.
        type: int
      session_vrf:
        description:
        - MCLAG session VRF.
        - Session VRF value can be either mgmt or a non-default VRF.
        version_added: 2.5.0
        type: str
      delay_restore:
        description:
          - MCLAG delay restore time in secs.
        type: int
      gateway_mac:
        description:
          - Gateway MAC address for router ports over MCLAG.
          - Configured gateway MAC address can be modified only when I(state=replaced) or I(state=overridden).
        type: str
      unique_ip:
        description: Holds Vlan dictionary for MCLAG unique IP.
        suboptions:
          vlans:
            description:
              - Holds a list of VLANs and VLAN ranges for which a separate IP address is enabled for Layer 3 protocol support over MCLAG.
            type: list
            elements: dict
            suboptions:
              vlan:
                description:
                  - Holds a VLAN name or VLAN range.
                  - Specify a single VLAN eg. Vlan10.
                  - Specify a range of VLANs eg. Vlan10-20.
                type: str
        type: dict
      peer_gateway:
        description: Holds Vlan dictionary for MCLAG peer gateway.
        suboptions:
          vlans:
            description:
              - Holds a list of VLANs and VLAN ranges for which MCLAG peer gateway functionality is enabled.
            type: list
            elements: dict
            suboptions:
              vlan:
                description:
                  - Holds a VLAN name or VLAN range.
                  - Specify a single VLAN eg. Vlan10.
                  - Specify a range of VLANs eg. Vlan10-20.
                type: str
        type: dict
      members:
        description: Holds portchannels dictionary for an MCLAG domain.
        suboptions:
          portchannels:
            description:
              - Holds a list of portchannels for configuring as an MCLAG interface.
            type: list
            elements: dict
            suboptions:
              lag:
                description: Holds a PortChannel ID.
                type: str
        type: dict
      backup_keepalive_source_address:
        version_added: 3.1.0
        description:
          - The IPV4 backup-keepalive-source-ip to establish MCLAG backup keepalive session
        type: str
      backup_keepalive_peer_address:
        version_added: 3.1.0
        description:
          - The IPV4 backup-keepalive-peer-ip to establish MCLAG backup keepalive session
        type: str
      backup_keepalive_interval:
        version_added: 3.1.0
        description:
          - MCLAG backup keepalive session interval in secs. Supported interval range is 1-60.
        type: int
      backup_keepalive_session_vrf:
        version_added: 3.1.0
        description:
          - MCLAG backup keepalive session VRF
        type: str
  state:
    description:
      - The state that the configuration should be left in.
    type: str
    choices:
      - merged
      - deleted
      - replaced
      - overridden
    default: merged
"""

EXAMPLES = """
# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show mclag brief
# MCLAG Not Configured

- name: Merge provided configuration with device configuration
  dellemc.enterprise_sonic.sonic_mclag:
    config:
      domain_id: 1
      peer_address: 1.1.1.1
      source_address: 2.2.2.2
      peer_link: 'Portchannel1'
      session_vrf: 'mgmt'
      keepalive: 1
      session_timeout: 3
      delay_restore: 240
      system_mac: '00:00:00:11:11:11'
      gateway_mac: '00:00:00:12:12:12'
      unique_ip:
        vlans:
          - vlan: Vlan4
          - vlan: Vlan21-25
      peer_gateway:
        vlans:
          - vlan: Vlan4
          - vlan: Vlan21-25
      members:
        portchannels:
          - lag: PortChannel10
      backup_keepalive_source_address: 3.3.3.3
      backup_keepalive_peer_address: 4.4.4.4
      backup_keepalive_interval: 5
      backup_keepalive_session_vrf: mgmt
    state: merged

# After state:
# ------------
#
# sonic# show mclag brief
#
# Domain ID            : 1
# Role                 : standby
# Session Status       : down
# Peer Link Status     : down
# Source Address       : 2.2.2.2
# Peer Address         : 1.1.1.1
# Session Vrf          : mgmt
# Peer Link            : PortChannel1
# Keepalive Interval   : 1 secs
# Session Timeout      : 3 secs
# Delay Restore        : 240 secs
# System Mac           : 20:04:0f:37:bd:c9
# Mclag System Mac     : 00:00:00:11:11:11
# Gateway Mac          : 00:00:00:12:12:12
#
# Backup Keepalive Session Information:
# -----------------------------------
# Session Vrf          : mgmt
# Session Status       : down
# Source Address       : 3.3.3.3
# Peer Address         : 4.4.4.4
# Keepalive Interval   : 5 secs
# -----------------------------------
#
# Number of MLAG Interfaces:1
# -----------------------------------------------------------
#  MLAG Interface       Local/Remote Status
# -----------------------------------------------------------
# PortChannel10            down/down
#
# sonic# show mclag separate-ip-interfaces
# Interface Name
# ==============
# Vlan4
# Vlan21
# Vlan22
# Vlan23
# Vlan24
# Vlan25
# ==============
# Total count :    6
# ==============
# sonic#
# sonic# show mclag peer-gateway-interfaces
# Interface Name
# ==============
# Vlan4
# Vlan21
# Vlan22
# Vlan23
# Vlan24
# Vlan25
# ==============
# Total count :    6
# ==============
# sonic#


# Using "merged" state
#
# Before state:
# ------------
#
# sonic# show mclag brief
#
# Domain ID            : 1
# Role                 : standby
# Session Status       : down
# Peer Link Status     : down
# Source Address       : 2.2.2.2
# Peer Address         : 1.1.1.1
# Session Vrf          : mgmt
# Peer Link            : PortChannel1
# Keepalive Interval   : 1 secs
# Session Timeout      : 3 secs
# Delay Restore        : 240 secs
# System Mac           : 20:04:0f:37:bd:c9
# Mclag System Mac     : 00:00:00:11:11:11
# Gateway Mac          : 00:00:00:12:12:12
#
# Backup Keepalive Session Information:
# -----------------------------------
# Session Vrf          : mgmt
# Session Status       : down
# Source Address       : 3.3.3.3
# Peer Address         : 4.4.4.4
# Keepalive Interval   : 5 secs
# -----------------------------------
#
# Number of MLAG Interfaces:1
# -----------------------------------------------------------
#  MLAG Interface       Local/Remote Status
# -----------------------------------------------------------
# PortChannel10            down/down
#
# sonic# show mclag separate-ip-interfaces
# Interface Name
# ==============
# Vlan4
# Vlan21
# Vlan22
# Vlan23
# Vlan24
# Vlan25
# ==============
# Total count :    6
# ==============
# sonic#
# sonic# show mclag peer-gateway-interfaces
# Interface Name
# ==============
# Vlan4
# Vlan21
# Vlan22
# Vlan23
# Vlan24
# Vlan25
# ==============
# Total count :    6
# ==============
# sonic#

- name: Merge device configuration with the provided configuration
  dellemc.enterprise_sonic.sonic_mclag:
    config:
      domain_id: 1
      source_address: 3.3.3.3
      keepalive: 10
      session_timeout: 30
      session_vrf: VrfRed
      delay_restore: 360
      unique_ip:
        vlans:
          - vlan: Vlan5
          - vlan: Vlan26-28
      peer_gateway:
        vlans:
          - vlan: Vlan5
          - vlan: Vlan26-28
      members:
        portchannels:
          - lag: PortChannel12
      backup_keepalive_source_address: 31.31.31.31
      backup_keepalive_peer_address: 44.44.44.44
      backup_keepalive_interval: 59
      backup_keepalive_session_vrf: VrfRed
    state: merged

# After state:
# ------------
#
# sonic# show mclag brief
#
# Domain ID            : 1
# Role                 : standby
# Session Status       : down
# Peer Link Status     : down
# Source Address       : 3.3.3.3
# Peer Address         : 1.1.1.1
# Session Vrf          : VrfRed
# Peer Link            : PortChannel1
# Keepalive Interval   : 10 secs
# Session Timeout      : 30 secs
# Delay Restore        : 360 secs
# System Mac           : 20:04:0f:37:bd:c9
# Mclag System Mac     : 00:00:00:11:11:11
# Gateway Mac          : 00:00:00:12:12:12
#
# Backup Keepalive Session Information:
# -----------------------------------
# Session Vrf          : VrfRed
# Session Status       : down
# Source Address       : 31.31.31.31
# Peer Address         : 44.44.44.44
# Keepalive Interval   : 59 secs
# -----------------------------------
#
# Number of MLAG Interfaces:2
# -----------------------------------------------------------
#  MLAG Interface       Local/Remote Status
# -----------------------------------------------------------
# PortChannel10            down/down
# PortChannel12            down/down
#
# sonic# show mclag separate-ip-interfaces
# Interface Name
# ==============
# Vlan4
# Vlan5
# Vlan21
# Vlan22
# Vlan23
# Vlan24
# Vlan25
# Vlan26
# Vlan27
# Vlan28
# ==============
# Total count :   10
# ==============
# sonic# show mclag peer-gateway-interfaces
# Interface Name
# ==============
# Vlan4
# Vlan5
# Vlan21
# Vlan22
# Vlan23
# Vlan24
# Vlan25
# Vlan26
# Vlan27
# Vlan28
# ==============
# Total count :   10
# ==============
# sonic#


# Using "deleted" state
#
# Before state:
# ------------
#
# sonic# show mclag brief
#
# Domain ID            : 1
# Role                 : standby
# Session Status       : down
# Peer Link Status     : down
# Source Address       : 3.3.3.3
# Peer Address         : 1.1.1.1
# Session Vrf          : VrfRed
# Peer Link            : PortChannel1
# Keepalive Interval   : 10 secs
# Session Timeout      : 30 secs
# Delay Restore        : 360 secs
# System Mac           : 20:04:0f:37:bd:c9
# Mclag System Mac     : 00:00:00:11:11:11
# Gateway Mac          : 00:00:00:12:12:12
#
# Backup Keepalive Session Information:
# -----------------------------------
# Session Vrf          : VrfRed
# Session Status       : down
# Source Address       : 31.31.31.31
# Peer Address         : 44.44.44.44
# Keepalive Interval   : 59 secs
# -----------------------------------
#
# Number of MLAG Interfaces:1
# -----------------------------------------------------------
#  MLAG Interface       Local/Remote Status
# -----------------------------------------------------------
# PortChannel10            down/down
#
# sonic# show mclag separate-ip-interfaces
# Interface Name
# ==============
# Vlan4
# Vlan21
# Vlan22
# Vlan23
# Vlan24
# Vlan25
# ==============
# Total count :    6
# ==============
# sonic#
# sonic# show mclag peer-gateway-interfaces
# Interface Name
# ==============
# Vlan4
# Vlan21
# Vlan22
# Vlan23
# Vlan24
# Vlan25
# ==============
# Total count :    6
# ==============
# sonic#

- name: Delete device configuration based on the provided configuration
  dellemc.enterprise_sonic.sonic_mclag:
    config:
      domain_id: 1
      source_address: 3.3.3.3
      keepalive: 10
      session_vrf: VrfRed
      unique_ip:
        vlans:
          - vlan: Vlan22
          - vlan: Vlan24-25
      peer_gateway:
        vlans:
          - vlan: Vlan22
          - vlan: Vlan24-25
      members:
        portchannels:
          - lag: PortChannel10
      backup_keepalive_source_address: 31.31.31.31
      backup_keepalive_peer_address: 44.44.44.44
      backup_keepalive_interval: 59
      backup_keepalive_session_vrf: VrfRed
    state: deleted

# After state:
# ------------
#
# sonic# show mclag brief
#
# Domain ID            : 1
# Role                 : standby
# Session Status       : down
# Peer Link Status     : down
# Source Address       :
# Peer Address         : 1.1.1.1
# Session Vrf          : default
# Peer Link            : PortChannel1
# Keepalive Interval   : 1 secs
# Session Timeout      : 30 secs
# Delay Restore        : 360 secs
# System Mac           : 20:04:0f:37:bd:c9
# Mclag System Mac     : 00:00:00:11:11:11
# Gateway Mac          : 00:00:00:12:12:12
#
# Backup Keepalive Session Information:
# -----------------------------------
# Session Vrf          : default
# Session Status       : down
# Source Address       :
# Peer Address         :
# Keepalive Interval   : 30 secs
# -----------------------------------
#
# Number of MLAG Interfaces:0
#
# sonic# show mclag separate-ip-interfaces
# Interface Name
# ==============
# Vlan4
# Vlan21
# Vlan23
# ==============
# Total count :    3
# ==============
# sonic#
# sonic# show mclag peer-gateway-interfaces
# Interface Name
# ==============
# Vlan4
# Vlan21
# Vlan23
# ==============
# Total count :    3
# ==============
# sonic#


# Using "deleted" state
#
# Before state:
# ------------
#
# sonic# show mclag brief
#
# Domain ID            : 1
# Role                 : standby
# Session Status       : down
# Peer Link Status     : down
# Source Address       : 3.3.3.3
# Peer Address         : 1.1.1.1
# Session Vrf          : default
# Peer Link            : PortChannel1
# Keepalive Interval   : 10 secs
# Session Timeout      : 30 secs
# Delay Restore        : 360 secs
# System Mac           : 20:04:0f:37:bd:c9
# Mclag System Mac     : 00:00:00:11:11:11
# Gateway Mac          : 00:00:00:12:12:12
#
# Backup Keepalive Session Information:
# -----------------------------------
# Session Vrf          : default
# Session Status       : down
# Source Address       :
# Peer Address         :
# Keepalive Interval   : 30 secs
# -----------------------------------
#
# Number of MLAG Interfaces:1
# -----------------------------------------------------------
#  MLAG Interface       Local/Remote Status
# -----------------------------------------------------------
# PortChannel10            down/down
#
# sonic# show mclag separate-ip-interfaces
# Interface Name
# ==============
# Vlan4
# ==============
# Total count :    1
# ==============
# sonic#
# sonic# show mclag peer-gateway-interfaces
# Interface Name
# ==============
# Vlan4
# ==============
# Total count :    1
# ==============
# sonic#

- name: Delete all device configuration
  dellemc.enterprise_sonic.sonic_mclag:
    config:
    state: deleted

# After state:
# ------------
#
# sonic# show mclag brief
# MCLAG Not Configured
# sonic# show mclag separate-ip-interfaces
# MCLAG separate IP interface not configured
# sonic# show mclag peer-gateway-interfaces
# MCLAG Peer Gateway interface not configured
# sonic#


# Using "deleted" state
#
# Before state:
# ------------
#
# sonic# show mclag brief
#
# Domain ID            : 1
# Role                 : standby
# Session Status       : down
# Peer Link Status     : down
# Source Address       : 3.3.3.3
# Peer Address         : 1.1.1.1
# Session Vrf          : default
# Peer Link            : PortChannel1
# Keepalive Interval   : 10 secs
# Session Timeout      : 30 secs
# Delay Restore        : 360 secs
# System Mac           : 20:04:0f:37:bd:c9
# Mclag System Mac     : 00:00:00:11:11:11
# Gateway Mac          : 00:00:00:12:12:12
#
# Backup Keepalive Session Information:
# -----------------------------------
# Session Vrf          : VrfRed
# Session Status       : down
# Source Address       : 31.31.31.31
# Peer Address         : 44.44.44.44
# Keepalive Interval   : 59 secs
# -----------------------------------
#
# Number of MLAG Interfaces:2
# -----------------------------------------------------------
#  MLAG Interface       Local/Remote Status
# -----------------------------------------------------------
# PortChannel10            down/down
# PortChannel12            down/down
#
# sonic# show mclag separate-ip-interfaces
# Interface Name
# ==============
# Vlan4
# ==============
# Total count :    1
# ==============
# sonic#
# sonic# show mclag peer-gateway-interfaces
# Interface Name
# ==============
# Vlan4
# ==============
# Total count :    1
# ==============
# sonic#

- name: Delete device configuration based on the provided configuration
  dellemc.enterprise_sonic.sonic_mclag:
    config:
      domain_id: 1
      source_address: 3.3.3.3
      keepalive: 10
      peer_gateway:
        vlans:
      members:
        portchannels:
    state: deleted

# After state:
# ------------
#
# sonic# show mclag brief
#
# Domain ID            : 1
# Role                 : standby
# Session Status       : down
# Peer Link Status     : down
# Source Address       :
# Peer Address         : 1.1.1.1
# Session Vrf          : default
# Peer Link            : PortChannel1
# Keepalive Interval   : 1 secs
# Session Timeout      : 30 secs
# Delay Restore        : 360 secs
# System Mac           : 20:04:0f:37:bd:c9
# Mclag System Mac     : 00:00:00:11:11:11
# Gateway Mac          : 00:00:00:12:12:12
#
# Backup Keepalive Session Information:
# -----------------------------------
# Session Vrf          : VrfRed
# Session Status       : down
# Source Address       : 31.31.31.31
# Peer Address         : 44.44.44.44
# Keepalive Interval   : 59 secs
# -----------------------------------
#
# Number of MLAG Interfaces:0
#
# sonic# show mclag separate-ip-interfaces
# Interface Name
# ==============
# Vlan4
# ==============
# Total count :    1
# ==============
# sonic#
# sonic# show mclag peer-gateway-interfaces
# MCLAG Peer Gateway interface not configured
# sonic#


# Using "replaced" state
#
# Before state:
# ------------
#
# sonic# show mclag brief
#
# Domain ID            : 1
# Role                 : standby
# Session Status       : down
# Peer Link Status     : down
# Source Address       : 2.2.2.2
# Peer Address         : 1.1.1.1
# Session Vrf          : VrfRed
# Peer Link            : PortChannel1
# Keepalive Interval   : 1 secs
# Session Timeout      : 3 secs
# Delay Restore        : 240 secs
# System Mac           : 20:04:0f:37:bd:c9
# Mclag System Mac     : 00:00:00:11:11:11
# Gateway Mac          : 00:00:00:12:12:12
#
#
# Backup Keepalive Session Information:
# -----------------------------------
# Session Vrf          : VrfRed
# Session Status       : down
# Source Address       : 31.31.31.31
# Peer Address         : 44.44.44.44
# Keepalive Interval   : 59 secs
# -----------------------------------
#
# Number of MLAG Interfaces:2
# -----------------------------------------------------------
#  MLAG Interface       Local/Remote Status
# -----------------------------------------------------------
# PortChannel10            down/down
# PortChannel11            down/down
#
# sonic# show mclag separate-ip-interfaces
# Interface Name
# ==============
# Vlan4
# Vlan21
# Vlan22
# Vlan23
# Vlan24
# Vlan25
# ==============
# Total count :    6
# ==============
# sonic#
# sonic# show mclag peer-gateway-interfaces
# Interface Name
# ==============
# Vlan4
# Vlan21
# Vlan22
# Vlan23
# Vlan24
# Vlan25
# ==============
# Total count :    6
# ==============
# sonic#

- name: Replace device configuration with the provided configuration
  dellemc.enterprise_sonic.sonic_mclag:
    config:
      domain_id: 1
      unique_ip:
        vlans:
          - vlan: Vlan5
          - vlan: Vlan24-28
      session_vrf: VrfBlue
      peer_gateway:
        vlans:
          - vlan: Vlan5
          - vlan: Vlan24-28
      members:
        portchannels:
          - lag: PortChannel10
          - lag: PortChannel12
      backup_keepalive_source_address: 131.131.131.131
    state: replaced

# After state:
# ------------
#
# sonic# show mclag brief
#
# Domain ID            : 1
# Role                 : standby
# Session Status       : down
# Peer Link Status     : down
# Source Address       : 2.2.2.2
# Peer Address         : 1.1.1.1
# Session Vrf          : VrfBlue
# Peer Link            : PortChannel1
# Keepalive Interval   : 1 secs
# Session Timeout      : 3 secs
# Delay Restore        : 240 secs
# System Mac           : 20:04:0f:37:bd:c9
# Mclag System Mac     : 00:00:00:11:11:11
# Gateway Mac          : 00:00:00:12:12:12
#
# Backup Keepalive Session Information:
# -----------------------------------
# Session Vrf          : Default
# Session Status       : down
# Source Address       : 131.131.131.131
# Peer Address         :
# Keepalive Interval   : 30 secs
# -----------------------------------
#
# Number of MLAG Interfaces:2
# -----------------------------------------------------------
#  MLAG Interface       Local/Remote Status
# -----------------------------------------------------------
# PortChannel10            down/down
# PortChannel12            down/down
#
# sonic# show mclag separate-ip-interfaces
# Interface Name
# ==============
# Vlan5
# Vlan24
# Vlan25
# Vlan26
# Vlan27
# Vlan28
# ==============
# Total count :   6
# ==============
# sonic# show mclag peer-gateway-interfaces
# Interface Name
# ==============
# Vlan5
# Vlan24
# Vlan25
# Vlan26
# Vlan27
# Vlan28
# ==============
# Total count :   6
# ==============
# sonic#


# Using "overridden" state
#
# Before state:
# ------------
#
# sonic# show mclag brief
#
# Domain ID            : 1
# Role                 : standby
# Session Status       : down
# Peer Link Status     : down
# Source Address       : 2.2.2.2
# Peer Address         : 1.1.1.1
# Session Vrf          : VrfBlue
# Peer Link            : PortChannel1
# Keepalive Interval   : 1 secs
# Session Timeout      : 3 secs
# Delay Restore        : 240 secs
# System Mac           : 20:04:0f:37:bd:c9
# Mclag System Mac     : 00:00:00:11:11:11
# Gateway Mac          : 00:00:00:12:12:12
#
# Backup Keepalive Session Information:
# -----------------------------------
# Session Vrf          : Vrf_Red
# Session Status       : down
# Source Address       : 19.19.19.19
# Peer Address         : 20.20.20.20
# Keepalive Interval   : 3 secs
# -----------------------------------
#
# Number of MLAG Interfaces:2
# -----------------------------------------------------------
#  MLAG Interface       Local/Remote Status
# -----------------------------------------------------------
# PortChannel10            down/down
# PortChannel11            down/down
#
# sonic# show mclag separate-ip-interfaces
# Interface Name
# ==============
# Vlan4
# Vlan21
# Vlan22
# Vlan23
# Vlan24
# Vlan25
# ==============
# Total count :    6
# ==============
# sonic#
# sonic# show mclag peer-gateway-interfaces
# Interface Name
# ==============
# Vlan4
# Vlan21
# Vlan22
# Vlan23
# Vlan24
# Vlan25
# ==============
# Total count :    6
# ==============
# sonic#

- name: Override device configuration with the provided configuration
  dellemc.enterprise_sonic.sonic_mclag:
    config:
      domain_id: 1
      peer_address: 1.1.1.1
      source_address: 3.3.3.3
      peer_link: 'Portchannel1'
      session_vrf: VrfRed
      system_mac: '00:00:00:11:11:11'
      gateway_mac: '00:00:00:12:12:12'
      unique_ip:
        vlans:
          - vlan: Vlan24-28
      peer_gateway:
        vlans:
          - vlan: Vlan24-28
      members:
        portchannels:
          - lag: PortChannel10
          - lag: PortChannel12
      backup_keepalive_source_address: 131.131.131.131
      backup_keepalive_peer_address: 144.144.144.144
    state: overridden

# After state:
# ------------
#
# sonic# show mclag brief
#
# Domain ID            : 1
# Role                 : standby
# Session Status       : down
# Peer Link Status     : down
# Source Address       : 3.3.3.3
# Peer Address         : 1.1.1.1
# Session Vrf          : VrfRed
# Peer Link            : PortChannel1
# Keepalive Interval   : 1 secs
# Session Timeout      : 30 secs
# Delay Restore        : 300 secs
# System Mac           : 20:04:0f:37:bd:c9
# Mclag System Mac     : 00:00:00:11:11:11
# Gateway Mac          : 00:00:00:12:12:12
#
# Backup Keepalive Session Information:
# -----------------------------------
# Session Vrf          : Default
# Session Status       : down
# Source Address       : 131.131.131.131
# Peer Address         : 141.141.141.141
# Keepalive Interval   : 30 secs
# -----------------------------------
#
#
# Number of MLAG Interfaces:2
# -----------------------------------------------------------
#  MLAG Interface       Local/Remote Status
# -----------------------------------------------------------
# PortChannel10            down/down
# PortChannel12            down/down
#
# sonic# show mclag separate-ip-interfaces
# Interface Name
# ==============
# Vlan24
# Vlan25
# Vlan26
# Vlan27
# Vlan28
# ==============
# Total count :   5
# ==============
# sonic# show mclag peer-gateway-interfaces
# Interface Name
# ==============
# Vlan24
# Vlan25
# Vlan26
# Vlan27
# Vlan28
# ==============
# Total count :   5
# ==============
# sonic#
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: list
  sample: >
    The configuration returned always in the same format
    as the parameters above.
after:
  description: The resulting configuration module invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned always in the same format
    as the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.mclag.mclag import MclagArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.mclag.mclag import Mclag


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=MclagArgs.argument_spec,
                           supports_check_mode=True)

    result = Mclag(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
