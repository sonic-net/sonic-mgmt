#!/usr/bin/python
# -*- coding: utf-8 -*-
# © Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_port_group
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_port_group
version_added: 2.1.0
notes:
  - Supports C(check_mode).
short_description: Manages port group configuration on SONiC.
description:
  - This module provides configuration management of port group for devices running SONiC.
author: 'M. Zhang (@mingjunzhang2019)'
options:
  config:
    description:
      - A list of port group configurations.
    type: list
    elements: dict
    suboptions:
      id:
        type: str
        description:
          - The index of the port group.
        required: true
      speed:
        description:
          - Speed for the port group.
          - This configures the speed for all the memebr ports of the prot group.
          - Supported speeds are dependent on the type of switch.
        type: str
        choices:
          - SPEED_10MB
          - SPEED_100MB
          - SPEED_1GB
          - SPEED_2500MB
          - SPEED_5GB
          - SPEED_10GB
          - SPEED_20GB
          - SPEED_25GB
          - SPEED_40GB
          - SPEED_50GB
          - SPEED_100GB
          - SPEED_200GB
          - SPEED_400GB
  state:
    description:
      - The state of the configuration after module completion.
    type: str
    choices:
      - merged
      - replaced
      - overridden
      - deleted
    default: merged
"""

EXAMPLES = """
#
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show port-group
# -------------------------------------------------------------------------------------
# Port-group  Interface range            Valid speeds      Default Speed Current Speed
# -------------------------------------------------------------------------------------
# 1           Ethernet0 - Ethernet3      10G, 25G          25G           10G
# 2           Ethernet4 - Ethernet7      10G, 25G          25G           25G
# 3           Ethernet8 - Ethernet11     10G, 25G          25G           25G
# 4           Ethernet12 - Ethernet15    10G, 25G          25G           25G
# 5           Ethernet16 - Ethernet19    10G, 25G          25G           25G
# 6           Ethernet20 - Ethernet23    10G, 25G          25G           25G
# 7           Ethernet24 - Ethernet27    10G, 25G          25G           25G
# 8           Ethernet28 - Ethernet31    10G, 25G          25G           25G
# 9           Ethernet32 - Ethernet35    10G, 25G          25G           10G
# 10          Ethernet36 - Ethernet39    10G, 25G          25G           25G
#
- name: Configure port group speed
  sonic_port_group:
    config:
      - id: 1
      - id: 10
    state: deleted
#
#
# After state:
# ------------
#
# sonic# show port-group
# -------------------------------------------------------------------------------------
# Port-group  Interface range            Valid speeds      Default Speed Current Speed
# -------------------------------------------------------------------------------------
# 1           Ethernet0 - Ethernet3      10G, 25G          25G           25G
# 2           Ethernet4 - Ethernet7      10G, 25G          25G           25G
# 3           Ethernet8 - Ethernet11     10G, 25G          25G           25G
# 4           Ethernet12 - Ethernet15    10G, 25G          25G           25G
# 5           Ethernet16 - Ethernet19    10G, 25G          25G           25G
# 6           Ethernet20 - Ethernet23    10G, 25G          25G           25G
# 7           Ethernet24 - Ethernet27    10G, 25G          25G           25G
# 8           Ethernet28 - Ethernet31    10G, 25G          25G           25G
# 9           Ethernet32 - Ethernet35    10G, 25G          25G           10G
# 10          Ethernet36 - Ethernet39    10G, 25G          25G           25G
#
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show port-group
# -------------------------------------------------------------------------------------
# Port-group  Interface range            Valid speeds      Default Speed Current Speed
# -------------------------------------------------------------------------------------
# 1           Ethernet0 - Ethernet3      10G, 25G          25G           10G
# 2           Ethernet4 - Ethernet7      10G, 25G          25G           25G
# 3           Ethernet8 - Ethernet11     10G, 25G          25G           25G
# 4           Ethernet12 - Ethernet15    10G, 25G          25G           25G
# 5           Ethernet16 - Ethernet19    10G, 25G          25G           25G
# 6           Ethernet20 - Ethernet23    10G, 25G          25G           25G
# 7           Ethernet24 - Ethernet27    10G, 25G          25G           25G
# 8           Ethernet28 - Ethernet31    10G, 25G          25G           25G
# 9           Ethernet32 - Ethernet35    10G, 25G          25G           10G
# 10          Ethernet36 - Ethernet39    10G, 25G          25G           25G
#
- name: Configure port group speed
  sonic_port_group:
    config:
      - id:
    state: deleted
#
#
# After state:
# ------------
#
# sonic# show port-group
# -------------------------------------------------------------------------------------
# Port-group  Interface range            Valid speeds      Default Speed Current Speed
# -------------------------------------------------------------------------------------
# 1           Ethernet0 - Ethernet3      10G, 25G          25G           25G
# 2           Ethernet4 - Ethernet7      10G, 25G          25G           25G
# 3           Ethernet8 - Ethernet11     10G, 25G          25G           25G
# 4           Ethernet12 - Ethernet15    10G, 25G          25G           25G
# 5           Ethernet16 - Ethernet19    10G, 25G          25G           25G
# 6           Ethernet20 - Ethernet23    10G, 25G          25G           25G
# 7           Ethernet24 - Ethernet27    10G, 25G          25G           25G
# 8           Ethernet28 - Ethernet31    10G, 25G          25G           25G
# 9           Ethernet32 - Ethernet35    10G, 25G          25G           25G
# 10          Ethernet36 - Ethernet39    10G, 25G          25G           25G
#
# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show port-group
# -------------------------------------------------------------------------------------
# Port-group  Interface range            Valid speeds      Default Speed Current Speed
# -------------------------------------------------------------------------------------
# 1           Ethernet0 - Ethernet3      10G, 25G          25G           25G
# 2           Ethernet4 - Ethernet7      10G, 25G          25G           25G
# 3           Ethernet8 - Ethernet11     10G, 25G          25G           25G
# 4           Ethernet12 - Ethernet15    10G, 25G          25G           25G
# 5           Ethernet16 - Ethernet19    10G, 25G          25G           25G
# 6           Ethernet20 - Ethernet23    10G, 25G          25G           25G
# 7           Ethernet24 - Ethernet27    10G, 25G          25G           25G
# 8           Ethernet28 - Ethernet31    10G, 25G          25G           25G
# 9           Ethernet32 - Ethernet35    10G, 25G          25G           25G
# 10          Ethernet36 - Ethernet39    10G, 25G          25G           25G
#
- name: Configure port group speed
  sonic_port_group:
    config:
      - id: 1
        speed: SPEED_10GB
      - id: 9
        speed: SPEED_10GB
    state: merged
#
#
# After state:
# ------------
#
# sonic# show port-group
# -------------------------------------------------------------------------------------
# Port-group  Interface range            Valid speeds      Default Speed Current Speed
# -------------------------------------------------------------------------------------
# 1           Ethernet0 - Ethernet3      10G, 25G          25G           10G
# 2           Ethernet4 - Ethernet7      10G, 25G          25G           25G
# 3           Ethernet8 - Ethernet11     10G, 25G          25G           25G
# 4           Ethernet12 - Ethernet15    10G, 25G          25G           25G
# 5           Ethernet16 - Ethernet19    10G, 25G          25G           25G
# 6           Ethernet20 - Ethernet23    10G, 25G          25G           25G
# 7           Ethernet24 - Ethernet27    10G, 25G          25G           25G
# 8           Ethernet28 - Ethernet31    10G, 25G          25G           25G
# 9           Ethernet32 - Ethernet35    10G, 25G          25G           10G
# 10          Ethernet36 - Ethernet39    10G, 25G          25G           25G
#
# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show port-group
# -------------------------------------------------------------------------------------
# Port-group  Interface range            Valid speeds      Default Speed Current Speed
# -------------------------------------------------------------------------------------
# 1           Ethernet0 - Ethernet3      10G, 25G          25G           25G
# 2           Ethernet4 - Ethernet7      10G, 25G          25G           25G
# 3           Ethernet8 - Ethernet11     10G, 25G          25G           25G
# 4           Ethernet12 - Ethernet15    10G, 25G          25G           10G
# 5           Ethernet16 - Ethernet19    10G, 25G          25G           25G
# 6           Ethernet20 - Ethernet23    10G, 25G          25G           25G
# 7           Ethernet24 - Ethernet27    10G, 25G          25G           25G
# 8           Ethernet28 - Ethernet31    10G, 25G          25G           25G
# 9           Ethernet32 - Ethernet35    10G, 25G          25G           25G
# 10          Ethernet36 - Ethernet39    10G, 25G          25G           25G
#
- name: Replace port group speed
  sonic_port_group:
    config:
      - id: 1
        speed: SPEED_10GB
      - id: 9
        speed: SPEED_10GB
    state: replaced
#
# After state:
# ------------
#
# sonic# show port-group
# -------------------------------------------------------------------------------------
# Port-group  Interface range            Valid speeds      Default Speed Current Speed
# -------------------------------------------------------------------------------------
# 1           Ethernet0 - Ethernet3      10G, 25G          25G           10G
# 2           Ethernet4 - Ethernet7      10G, 25G          25G           25G
# 3           Ethernet8 - Ethernet11     10G, 25G          25G           25G
# 4           Ethernet12 - Ethernet15    10G, 25G          25G           10G
# 5           Ethernet16 - Ethernet19    10G, 25G          25G           25G
# 6           Ethernet20 - Ethernet23    10G, 25G          25G           25G
# 7           Ethernet24 - Ethernet27    10G, 25G          25G           25G
# 8           Ethernet28 - Ethernet31    10G, 25G          25G           25G
# 9           Ethernet32 - Ethernet35    10G, 25G          25G           10G
# 10          Ethernet36 - Ethernet39    10G, 25G          25G           25G
#
# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show port-group
# -------------------------------------------------------------------------------------
# Port-group  Interface range            Valid speeds      Default Speed Current Speed
# -------------------------------------------------------------------------------------
# 1           Ethernet0 - Ethernet3      10G, 25G          25G           25G
# 2           Ethernet4 - Ethernet7      10G, 25G          25G           10G
# 3           Ethernet8 - Ethernet11     10G, 25G          25G           10G
# 4           Ethernet12 - Ethernet15    10G, 25G          25G           25G
# 5           Ethernet16 - Ethernet19    10G, 25G          25G           10G
# 6           Ethernet20 - Ethernet23    10G, 25G          25G           25G
# 7           Ethernet24 - Ethernet27    10G, 25G          25G           10G
# 8           Ethernet28 - Ethernet31    10G, 25G          25G           10G
# 9           Ethernet32 - Ethernet35    10G, 25G          25G           10G
# 10          Ethernet36 - Ethernet39    10G, 25G          25G           10G
#
- name: Override port group speed
  sonic_port_group:
    config:
      - id: 1
        speed: SPEED_10GB
      - id: 9
        speed: SPEED_10GB
    state: overridden
#
# After state:
# ------------
#
# sonic# show port-group
# -------------------------------------------------------------------------------------
# Port-group  Interface range            Valid speeds      Default Speed Current Speed
# -------------------------------------------------------------------------------------
# 1           Ethernet0 - Ethernet3      10G, 25G          25G           10G
# 2           Ethernet4 - Ethernet7      10G, 25G          25G           25G
# 3           Ethernet8 - Ethernet11     10G, 25G          25G           25G
# 4           Ethernet12 - Ethernet15    10G, 25G          25G           25G
# 5           Ethernet16 - Ethernet19    10G, 25G          25G           25G
# 6           Ethernet20 - Ethernet23    10G, 25G          25G           25G
# 7           Ethernet24 - Ethernet27    10G, 25G          25G           25G
# 8           Ethernet28 - Ethernet31    10G, 25G          25G           25G
# 9           Ethernet32 - Ethernet35    10G, 25G          25G           10G
# 10          Ethernet36 - Ethernet39    10G, 25G          25G           25G
#
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.port_group.port_group import Port_groupArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.port_group.port_group import Port_group


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Port_groupArgs.argument_spec,
                           supports_check_mode=True)

    result = Port_group(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
