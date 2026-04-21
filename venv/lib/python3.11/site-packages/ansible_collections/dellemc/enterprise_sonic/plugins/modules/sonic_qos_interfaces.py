#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_qos_interfaces
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_qos_interfaces
version_added: 2.5.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
short_description: Manage QoS interfaces configuration on SONiC
description:
  - This module provides configuration management of QoS interfaces for devices running SONiC
author: "S. Talabi (@stalabi1)"
options:
  config:
    description:
      - QoS interfaces configuration
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Name of the interface
        type: str
        required: True
      queues:
        description:
          - Queue configuration
        type: list
        elements: dict
        suboptions:
          id:
            description:
              - Queue identification
              - Range 0-7 for interface queues, range 0-47 for CPU queues
            type: int
            required: True
          wred_profile:
            description:
              - Name of the WRED profile
            type: str
      scheduler_policy:
        description:
          - Name of scheduler policy to be applied to traffic on the interface
        type: str
      cable_length:
        version_added: 3.1.0
        description:
          - Cable length of the interface
        type: str
        choices: ['5m', '40m', '300m']
        default: '40m'
      qos_maps:
        description:
          - QoS maps interface configuration
        type: dict
        suboptions:
          dscp_fwd_group:
            description:
              - DSCP to forwarding group map associated with the interface
            type: str
          dot1p_fwd_group:
            description:
              - DOT1P to forwarding group map associated with the interface
            type: str
          fwd_group_dscp:
            description:
              - Forwarding group to DSCP map associated with the interface
            type: str
          fwd_group_dot1p:
            description:
              - Forwarding group to DOT1P map associated with the interface
            type: str
          fwd_group_queue:
            description:
              - Forwarding group to queue map associated with the interface
            type: str
          fwd_group_pg:
            description:
              - Forwading group to priority group map associated with the interface
            type: str
          pfc_priority_queue:
            description:
              - PFC priority to queue map associated with the interface
            type: str
          pfc_priority_pg:
            description:
              - PFC priority to priority group map associated with the interface
            type: str
      pfc:
        description:
          - PFC configuration
        type: dict
        suboptions:
          asymmetric:
            description:
              - Enable or disable asymmetric PFC on the interface
            type: bool
            default: False
          priorities:
            description:
              - PFC priorities configuration
            type: list
            elements: dict
            suboptions:
              dot1p:
                description:
                  - DOT1P value, range 0-7
                  - Maxium of 2 priorities supported
                type: int
                required: True
              enable:
                description:
                  - Enable or disable the priority
                type: bool
                default: False
          watchdog_action:
            description:
              - PFC watchdog storm action
            type: str
            choices:
              - drop
              - forward
              - alert
            default: drop
          watchdog_detect_time:
            description:
              - PFC watchdog detection time in milliseconds, range 100-5000
            type: int
          watchdog_restore_time:
            description:
              - PFC watchdog restoration time milliseconds, range 100-60000
            type: int
  state:
    description:
      - The state of the configuration after module completion
      - Replaced and overridden states are not supported for this module due to configuration constraints
    type: str
    choices:
      - merged
      - deleted
    default: merged
"""

EXAMPLES = """
# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface Eth 1/5
# !
# interface Eth1/5
# (No QoS configuration present for the interface)

- name: Merge QoS interfaces configuration
  dellemc.enterprise_sonic.sonic_qos_interfaces:
    config:
      - name: Eth1/5
        queues:
          - id: 0
            wred_profile: profile1
        scheduler_policy: policy1
        cable_length: 40m
        qos_maps:
          dscp_fwd_group: dscp_map1
          dot1p_fwd_group: dot1p_map1
          fwd_group_dscp: fwd_dscp_map1
          fwd_group_dot1p: fwd_dot1p_map1
          fwd_group_queue: fwd_queue_map1
          fwd_group_pg: fwd_pg_map1
          pfc_priority_queue: pfc_queue_map1
          pfc_priority_pg: pfc_pg_map1
        pfc:
          asymmetric: true
          watchdog_action: alert
          watchdog_detect_time: 100
          watchdog_restore_time: 200
          priorities:
            - dot1p: 0
              enable: true
            - dot1p: 1
              enable: true
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration interface Eth 1/5
# !
# interface Eth1/5
#  queue 0 wred-policy profile1
#  scheduler-policy policy1
#  cable-length 40m
#  qos-map dscp-tc dscp_map1
#  qos-map dot1p-tc dot1p_map1
#  qos-map tc-queue fwd_queue_map1
#  qos-map tc-pg fwd_pg_map1
#  qos-map tc-dscp fwd_dscp_map1
#  qos-map tc-dot1p fwd_dot1p_map1
#  qos-map pfc-priority-queue pfc_queue_map1
#  qos-map pfc-priority-pg pfc_pg_map1
#  priority-flow-control priority 0
#  priority-flow-control priority 1
#  priority-flow-control asymmetric
#  priority-flow-control watchdog action alert
#  priority-flow-control watchdog on detect-time 100
#  priority-flow-control watchdog restore-time 200
#
#
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface Eth 1/5
# !
# interface Eth1/5
#  queue 0 wred-policy profile2
#  queue 1 wred-policy profile1
#  scheduler-policy policy2
#  cable-length 5m
#  qos-map dscp-tc dscp_map2
#  qos-map dot1p-tc dot1p_map2
#  qos-map tc-queue fwd_queue_map2
#  qos-map tc-pg fwd_pg_map2
#  qos-map tc-dscp fwd_dscp_map2
#  qos-map tc-dot1p fwd_dot1p_map2
#  qos-map pfc-priority-queue pfc_queue_map1
#  qos-map pfc-priority-pg pfc_pg_map1
#  priority-flow-control priority 1
#  priority-flow-control watchdog action drop
#  priority-flow-control watchdog on detect-time 150
#  priority-flow-control watchdog restore-time 250
# sonic# show running-configuration interface Eth 1/6
# !
# interface Eth1/6
#  queue 0 wred-policy profile1
#  scheduler-policy policy1
#  cable-length 40m
#  qos-map dscp-tc dscp_map1
#  qos-map dot1p-tc dot1p_map1
#  qos-map tc-queue fwd_queue_map1
#  qos-map tc-pg fwd_pg_map1
#  qos-map tc-dscp fwd_dscp_map1
#  qos-map tc-dot1p fwd_dot1p_map1
#  qos-map pfc-priority-queue pfc_queue_map1
#  qos-map pfc-priority-pg pfc_pg_map1
#  priority-flow-control priority 0
#  priority-flow-control asymmetric
#  priority-flow-control watchdog on detect-time 100
#  priority-flow-control watchdog restore-time 200

- name: Delete QoS interfaces attributes
  dellemc.enterprise_sonic.sonic_interfaces:
    config:
      - name: Eth1/5
        queues:
          - id: 0
            wred_profile: profile2
          - id: 1
        scheduler_policy: policy2
        cable_length: 5m
        qos_maps:
          dscp_fwd_group: dscp_map2
          dot1p_fwd_group: dot1p_map2
          fwd_group_dscp: fwd_dscp_map2
          fwd_group_dot1p: fwd_dot1p_map2
          fwd_group_queue: fwd_queue_map2
          fwd_group_pg: fwd_pg_map2
      - name: Eth1/6
        pfc:
          asymmetric: true
          watchdog_action: drop
          watchdog_detect_time: 100
          watchdog_restore_time: 200
          priorities:
            - dot1p: 0
              enable: true
            - dot1p: 1
              enable: true
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration interface Eth 1/5
# !
# interface Eth1/5
#  cable-length 40m
#  qos-map pfc-priority-queue pfc_queue_map1
#  qos-map pfc-priority-pg pfc_pg_map1
#  priority-flow-control priority 1
#  priority-flow-control watchdog action drop
#  priority-flow-control watchdog on detect-time 150
#  priority-flow-control watchdog restore-time 250
# sonic# show running-configuration interface Eth 1/6
# !
# interface Eth1/6
#  queue 0 wred-policy profile1
#  scheduler-policy policy1
#  cable-length 40m
#  qos-map dscp-tc dscp_map1
#  qos-map dot1p-tc dot1p_map1
#  qos-map tc-queue fwd_queue_map1
#  qos-map tc-pg fwd_pg_map1
#  qos-map tc-dscp fwd_dscp_map1
#  qos-map tc-dot1p fwd_dot1p_map1
#  qos-map pfc-priority-queue pfc_queue_map1
#  qos-map pfc-priority-pg pfc_pg_map1
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
  description: The resulting configuration from module invocation.
  returned: when changed, if C(check_mode) is not set
  type: list
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
after(generated):
  description: The generated (simulated) configuration from module invocation.
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.qos_interfaces.qos_interfaces import Qos_interfacesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.qos_interfaces.qos_interfaces import Qos_interfaces


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Qos_interfacesArgs.argument_spec,
                           supports_check_mode=True)

    result = Qos_interfaces(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
