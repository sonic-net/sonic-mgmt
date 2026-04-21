#!/usr/bin/python
# -*- coding: utf-8 -*-
# © Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_mirroring
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_mirroring
version_added: 3.1.0
author: "M. Zhang (@mingjunzhang2019)"
notes:
  - Tested against Enterprise SONiC Distribution by Dell Technologies.
  - Supports C(check_mode).
short_description: Manage port mirroring configuration on SONiC.
description:
  - This module provides configuration management for port mirroring on devices running SONiC.
options:
  config:
    description:
      - Specifies port mirroring configuration.
    type: dict
    suboptions:
      span:
        description:
          - SPAN mirroring sessions.
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - SPAN mirroring session name.
            required: true
            type: str
          dst_port:
            description:
              - Mirror session destination interface.
              - It may be CPU or an Ethernet interface.
            type: str
          source:
            description:
              - Mirror session source interface.
              - It may be an Ethernet interface or a PortChannel interface.
            type: str
          direction:
            description:
              - Mirror session direction.
            type: str
            choices:
              - rx
              - tx
              - both
      erspan:
        description:
          - ERSPAN mirroring sessions.
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - ERSPAN mirroring session name.
            required: true
            type: str
          dst_ip:
            description:
              - ERSPAN destination IP address.
            type: str
          src_ip:
            description:
              - ERSPAN source IP address.
            type: str
          source:
            description:
              - Mirror session source interface.
              - It may be an Ethernet interface or a PortChannel interface.
            type: str
          direction:
            description:
              - Mirror session direction.
            type: str
            choices:
              - rx
              - tx
              - both
          dscp:
            description:
              - ERSPAN destination DSCP.
              - The range of values is from 0 to 63.
            type: int
          gre:
            description:
              - ERSPAN destination GRE type.
              - A hexadecimal string of the form 0xabcd.
            type: str
          ttl:
            description:
              - ERSPAN destination TTL
              - The range of values is from 0 to 63.
            type: int
          queue:
            description:
              - ERSPAN destination queue number.
              - The range of values is from 0 to 63.
              - Only queue 0 is supported.
            type: int
  state:
    description:
      - Specifies the operation to be performed on the mirroring configured on the device.
      - In case of merged, the input configuration will be merged with the existing configuration on the device.
      - In case of deleted, the input configuration will be removed from the device.
      - In case of overridden, all existing mirroring configuration will be deleted and the specified input configuration will be added.
      - In case of replaced, the existing mirroring configuration on the device will be replaced by the new specified configuration for
        each affected mirroring session.
    type: str
    choices:
      - merged
      - deleted
      - replaced
      - overridden
    default: merged
"""

EXAMPLES = """
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show mirror-session
# ERSPAN Sessions
# -----------------------------------------------------------------------------------------------------------------------------------------
# Name                     Status     SRC-IP           DST-IP           GRE    DSCP   TTL    Queue    Policer    SRC-Port         Direction
# -----------------------------------------------------------------------------------------------------------------------------------------
# dell-2                   inactive   200.22.22.22     100.11.11.11                          0                   Ethernet28       both
# SPAN Sessions
# -------------------------------------------------------------------------------
# Name                     Status     DST-Port         SRC-Port         Direction
# -------------------------------------------------------------------------------
# dell-1                   active     CPU              Ethernet24       both
# dell-3                   active     CPU

- name: Delete mirroring configuration
  dellemc.enterprise_sonic.sonic_mirroring:
    config:
      span:
        - name: dell-3
      erspan:
        - name: dell-2
    state: deleted

# After state:
# ------------
#
# sonic# show mirror-session
# SPAN Sessions
# -------------------------------------------------------------------------------
# Name                     Status     DST-Port         SRC-Port         Direction
# -------------------------------------------------------------------------------
# dell-1                   active     CPU              Ethernet24       both


# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show mirror-session
# No sessions configured

- name: Merge mirroring configuration
  dellemc.enterprise_sonic.sonic_mirroring:
    config:
      span:
        - name: dell-1
          dst_port: CPU
          source: Ethernet24
          direction: both
      erspan:
        - name: dell-2
          dst_ip: 100.11.11.11
          src_ip: 200.22.22.22
          source: Ethernet28
          direction: both
          queue: 0
    state: merged

# After state:
# ------------
#
# sonic# show mirror-session
# ERSPAN Sessions
# -----------------------------------------------------------------------------------------------------------------------------------------
# Name                     Status     SRC-IP           DST-IP           GRE    DSCP   TTL    Queue    Policer    SRC-Port         Direction
# -----------------------------------------------------------------------------------------------------------------------------------------
# dell-2                   inactive   200.22.22.22     100.11.11.11                          0                   Ethernet28       both
# SPAN Sessions
# -------------------------------------------------------------------------------
# Name                     Status     DST-Port         SRC-Port         Direction
# -------------------------------------------------------------------------------
# dell-1                   active     CPU              Ethernet24       both


# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show mirror-session
# SPAN Sessions
# -------------------------------------------------------------------------------
# Name                     Status     DST-Port         SRC-Port         Direction
# -------------------------------------------------------------------------------
# dell-1                   active     CPU              Ethernet24       both

- name: Modify existing mirroring configuration
  dellemc.enterprise_sonic.sonic_mirroring:
    config:
      span:
        - name: dell-1
          dst_port: Ethernet32
          source: Ethernet4
          direction: rx

# After state:
# ------------
#
# sonic# show mirror-session
# SPAN Sessions
# -------------------------------------------------------------------------------
# Name                     Status     DST-Port         SRC-Port         Direction
# -------------------------------------------------------------------------------
# dell-1                   active     Ethernet32       Ethernet4        rx


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show mirror-session
# ERSPAN Sessions
# -----------------------------------------------------------------------------------------------------------------------------------------
# Name                     Status     SRC-IP           DST-IP           GRE    DSCP   TTL    Queue    Policer    SRC-Port         Direction
# -----------------------------------------------------------------------------------------------------------------------------------------
# dell-2                   inactive   200.22.22.22     100.11.11.11                          0                   Ethernet28       both
# SPAN Sessions
# -------------------------------------------------------------------------------
# Name                     Status     DST-Port         SRC-Port         Direction
# -------------------------------------------------------------------------------
# dell-1                   active     CPU              Ethernet24       both
# dell-3                   active     CPU

- name: Replace mirroring configuration
  dellemc.enterprise_sonic.sonic_mirroring:
    config:
      erspan:
        - name: dell-2
          dst_ip: 32.22.22.12
          src_ip: 31.21.21.12
          source: Ethernet28
          dscp: 6
          gre: "0x6689"
          ttl: 9
          queue: 0
          direction: rx
        - name: dell-3
          dst_ip: 22.22.22.12
          src_ip: 21.21.21.12
          source: Ethernet28
          direction: rx
      span:
        - name: dell-1
          dst_port: Ethernet4
          source: Ethernet24
          direction: tx
    state: replaced

# After state:
# ------------
#
# sonic# show mirror-session
# ERSPAN Sessions
# -----------------------------------------------------------------------------------------------------------------------------------------
# Name                     Status     SRC-IP           DST-IP           GRE    DSCP   TTL    Queue    Policer    SRC-Port         Direction
# -----------------------------------------------------------------------------------------------------------------------------------------
# dell-2                   inactive   32.22.22.22      31.11.11.11      0x6689 6      9      0                   Ethernet28       rx
# dell-3                   inactive   21.21.21.12      22.22.22.12                                               Ethernet28       rx
# SPAN Sessions
# -------------------------------------------------------------------------------
# Name                     Status     DST-Port         SRC-Port         Direction
# -------------------------------------------------------------------------------
# dell-1                   active     Ethertnet4       Ethernet24       tx


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show mirror-session
# ERSPAN Sessions
# -----------------------------------------------------------------------------------------------------------------------------------------
# Name                     Status     SRC-IP           DST-IP           GRE    DSCP   TTL    Queue    Policer    SRC-Port         Direction
# -----------------------------------------------------------------------------------------------------------------------------------------
# dell-2                   inactive   200.22.22.22     100.11.11.11                          0                   Ethernet28       both
# SPAN Sessions
# -------------------------------------------------------------------------------
# Name                     Status     DST-Port         SRC-Port         Direction
# -------------------------------------------------------------------------------
# dell-1                   active     CPU              Ethernet24       both
# dell-3                   active     CPU

- name: Override mirroring configuration
  dellemc.enterprise_sonic.sonic_mirroring:
    config:
      erspan:
        - name: dell-2
          dst_ip: 32.22.22.12
          src_ip: 31.21.21.12
          source: Ethernet28
          gre: "0x6689"
          dscp: 6
          ttl: 9
          queue: 0
          direction: rx
        - name: dell-1
          dst_ip: 22.22.22.12
          src_ip: 21.21.21.12
          source: Ethernet28
          direction: rx
      span:
        - name: dell-6
          dst_port: CPU
          source: Ethernet24
          direction: tx
    state: overridden

# After state:
# ------------
#
# sonic# show mirror-session
# ERSPAN Sessions
# -----------------------------------------------------------------------------------------------------------------------------------------
# Name                     Status     SRC-IP           DST-IP           GRE    DSCP   TTL    Queue    Policer    SRC-Port         Direction
# -----------------------------------------------------------------------------------------------------------------------------------------
# dell-1                   inactive   21.21.21.12      22.22.22.12                                               Ethernet28       rx
# dell-2                   inactive   31.21.21.12      32.22.22.12      0x6689 6      9      0                   Ethernet28       rx
# SPAN Sessions
# -------------------------------------------------------------------------------
# Name                     Status     DST-Port         SRC-Port         Direction
# -------------------------------------------------------------------------------
# dell-6                   active     Ethertnet4       Ethernet24       tx
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: dict
after:
  description: The configuration resulting from module invocation.
  returned: when changed
  type: dict
after(generated):
  description: The configuration that would result from non-check-mode module invocation.
  returned: when C(check_mode)
  type: dict
commands:
  description: The set of commands pushed to the remote device. In C(check_mode) the needed commands are displayed, but not pushed to the device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.mirroring.mirroring import MirroringArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.mirroring.mirroring import Mirroring


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=MirroringArgs.argument_spec,
                           supports_check_mode=True)

    result = Mirroring(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
