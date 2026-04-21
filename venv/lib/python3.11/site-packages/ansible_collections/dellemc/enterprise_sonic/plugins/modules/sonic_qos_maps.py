#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_qos_maps
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_qos_maps
version_added: 2.5.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
short_description: Manage QoS maps configuration on SONiC
description:
  - This module provides configuration management of QoS maps for devices running SONiC
author: "S. Talabi (@stalabi1)"
options:
  config:
    description:
      - QoS maps configuration
    type: dict
    suboptions:
      dscp_maps:
        description:
          - DSCP maps configuration
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Name of DSCP map
            type: str
            required: True
          entries:
            description:
              - DSCP map entries configuration
            type: list
            elements: dict
            suboptions:
              dscp:
                description:
                  - DSCP value, range 0-63
                type: int
                required: True
              fwd_group:
                description:
                  - Forwarding group value, range 0-7
                type: str
      dot1p_maps:
        description:
          - DOT1P maps configuration
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Name of DOT1P map
            type: str
            required: True
          entries:
            description:
              - DOT1P map entries configuration
            type: list
            elements: dict
            suboptions:
              dot1p:
                description:
                  - DOT1P value, range 0-7
                type: int
                required: True
              fwd_group:
                description:
                  - Forwarding group value, range 0-7
                type: str
      fwd_group_queue_maps:
        description:
          - Forwarding group queue maps configuration
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Name of forwarding group queue map
            type: str
            required: True
          entries:
            description:
              - Forwarding group queue map entries configuration
            type: list
            elements: dict
            suboptions:
              fwd_group:
                description:
                  - Forwarding group value, range 0-7
                type: str
                required: True
              queue_index:
                description:
                  - Output queue index value, range 0-7
                type: int
      fwd_group_dscp_maps:
        description:
          - Forwarding group DSCP maps configuration
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Name of forwarding group DSCP map
            type: str
            required: True
          entries:
            description:
              - Forwarding group DSCP map entries configuration
            type: list
            elements: dict
            suboptions:
              fwd_group:
                description:
                  - Forwarding group value, range 0-7
                type: str
                required: True
              dscp:
                description:
                  - DSCP value, range 0-63
                type: int
      fwd_group_dot1p_maps:
        description:
          - Forwarding group DOT1P maps configuration
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Name of forwarding group DOT1P map
            type: str
            required: True
          entries:
            description:
              - Forwarding group DOT1P map entries configuration
            type: list
            elements: dict
            suboptions:
              fwd_group:
                description:
                  - Forwarding group value, range 0-7
                type: str
                required: True
              dot1p:
                description:
                  - DOT1P value, range 0-7
                type: int
      fwd_group_pg_maps:
        description:
          - Forwarding group priority group maps configuration
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Name of forwarding group priority group map
            type: str
            required: True
          entries:
            description:
              - Forwarding group priority group entries configuration
            type: list
            elements: dict
            suboptions:
              fwd_group:
                description:
                  - Forwarding group value, range 0-7
                type: str
                required: True
              pg_index:
                description:
                  - Priority group index value, range 0-7
                type: int
      pfc_priority_queue_maps:
        description:
          - PFC priority queue maps configuration
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Name of PFC priority queue map
              - SONiC currently only supports configuration of a single PFC priority queue map
            type: str
            required: True
          entries:
            description:
              - PFC priority queue map entries configuration
            type: list
            elements: dict
            suboptions:
              dot1p:
                description:
                  - DOT1P value, range 0-7
                type: int
                required: True
              queue_index:
                description:
                  - Output queue index value, range 0-7
                type: int
      pfc_priority_pg_maps:
        description:
          - PFC priority priority group maps configuration
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Name of PFC priority priority group map
              - SONiC currently only supports configuration of a single PFC priority priority group map
            type: str
            required: True
          entries:
            description:
              - PFC priority priority group map entries configuration
            type: list
            elements: dict
            suboptions:
              dot1p:
                description:
                  - DOT1P value, range 0-7
                type: int
                required: True
              pg_index:
                description:
                  - Priority group index value, range 0-7
                type: int
  state:
    description:
      - The state of the configuration after module completion.
    type: str
    choices:
      - merged
      - deleted
      - overridden
      - replaced
    default: merged
"""

EXAMPLES = """
# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show qos map dscp-tc
# (No qos map dscp-tc configuration present)

- name: Merge QoS maps configurations
  dellemc.enterprise_sonic.sonic_qos_maps:
    config:
      dscp_maps:
        - name: dscp_map1
          entries:
            - dscp: 0
              fwd_group: 0
            - dscp: 1
              fwd_group: 7
        - name: dscp_map2
          entries:
            - dscp: 2
              fwd_group: 4
    state: merged

# After state:
# ------------
#
# sonic# show qos map dscp-tc
# DSCP-TC-MAP: dscp_map1
# ----------------------------
#     DSCP TC
# ----------------------------
#     0    0
#     1    7
# ----------------------------
# DSCP-TC-MAP: dscp_map2
# ----------------------------
#     DSCP TC
# ----------------------------
#     2    4
# ----------------------------
#
#
# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show qos map dscp-tc
# DSCP-TC-MAP: dscp_map1
# ----------------------------
#     DSCP TC
# ----------------------------
#     0    0
#     1    7
# ----------------------------
# DSCP-TC-MAP: dscp_map2
# ----------------------------
#     DSCP TC
# ----------------------------
#     2    4
# ----------------------------

- name: Replace QoS maps configurations
  dellemc.enterprise_sonic.sonic_qos_maps:
    config:
      dscp_maps:
        - name: dscp_map1
          entries:
            - dscp: 3
              fwd_group: 5
    state: replaced

# After state:
# ------------
#
# sonic# show qos map dscp-tc
# DSCP-TC-MAP: dscp_map1
# ----------------------------
#     DSCP TC
# ----------------------------
#     3    5
# ----------------------------
# DSCP-TC-MAP: dscp_map2
# ----------------------------
#     DSCP TC
# ----------------------------
#     2    4
# ----------------------------
#
#
# Using "overridden" state
# Before state:
# -------------
#
# sonic# show qos map dscp-tc
# DSCP-TC-MAP: dscp_map1
# ----------------------------
#     DSCP TC
# ----------------------------
#     3    5
# ----------------------------
# DSCP-TC-MAP: dscp_map2
# ----------------------------
#     DSCP TC
# ----------------------------
#     2    4
# ----------------------------

- name: Override QoS maps configurations
  dellemc.enterprise_sonic.sonic_qos_maps:
    config:
      pfc_priority_queue_maps:
        - name: pfc_map1
          entries:
            - dot1p: 0
              queue_index: 0
            - dot1p: 4
              queue_index: 5
    state: overridden

# After state:
# ------------
#
# sonic# show qos map pfc-priority-queue
# PFC-Priority-Queue-MAP: pfc_map1
# ----------------------------
#     PFC Priority   Queue
# ----------------------------
#     0              0
#     4              5
# ----------------------------
#
#
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show qos map dot1p-tc
# DOT1P-TC-MAP: dot1p_map1
# ----------------------------
#     DOT1P  TC
# ----------------------------
#     0      0
#     1      6
# ----------------------------
# DOT1P-TC-MAP: dot1p_map2
# ----------------------------
#     DOT1P  TC
# ----------------------------
#     2      5
# ----------------------------

- name: Delete QoS maps configurations
  dellemc.enterprise_sonic.sonic_qos_maps:
    config:
      dot1p_maps:
        - name: dot1p_map1
          entries:
            - dot1p: 0
            - dot1p: 1
              fwd_group: 6
        - name: dot1p_map2
    state: deleted

# After state:
# ------------
#
# sonic# show qos map dot1p-tc
# (No qos map dot1p-tc configuration present)
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.qos_maps.qos_maps import Qos_mapsArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.qos_maps.qos_maps import Qos_maps


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Qos_mapsArgs.argument_spec,
                           supports_check_mode=True)

    result = Qos_maps(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
