#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_qos_scheduler
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_qos_scheduler
version_added: "2.5.0"
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
short_description: Manage QoS scheduler configuration on SONiC
description:
  - This module provides configuration management of QoS scheduler for devices running SONiC
author: "S. Talabi (@stalabi1)"
options:
  config:
    description:
      - QoS scheduler configuration
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Name of scheduler policy
        type: str
        required: True
      schedulers:
        description:
          - Schedulers configuration for the scheduler policy
        type: list
        elements: dict
        suboptions:
          sequence:
            description:
              - Sequence number of the scheduler
              - Range 0-7 for interface queues
              - Range 0-47 for CPU queues
              - Specify 255 for port queues
            type: int
            required: True
          scheduler_type:
            description:
              - Specifies the type of scheduler
              - Strict priority scheduling cannot be configured with weight
            type: str
            choices:
              - dwrr
              - wrr
              - strict
          weight:
            description:
              - Weight of the scheduler
              - Range 1-100
            type: int
          meter_type:
            description:
              - Metering method used by the scheduler
            type: str
            choices:
              - packets
              - bytes
          cir:
            description:
              - Committed information rate measured in bps
              - Range 0-400000000000
            type: int
          pir:
            description:
              - Peak information rate measured in bps
              - Range 0-400000000000, must be greater than or equal to cir
            type: int
          cbs:
            description:
              - Committed burst size measured in bytes
              - Range 0-125000000
            type: int
          pbs:
            description:
              - Excess burst size measured in bytes
              - Range 0-125000000
            type: int
  state:
    description:
      - The state of the configuration after module completion
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
# sonic# show qos scheduler-policy
# (No qos scheduler-policy configuration present)

- name: Merge QoS scheduler configurations
  dellemc.enterprise_sonic.sonic_qos_scheduler:
    config:
      - name: policy1
        schedulers:
          - sequence: 0
            scheduler_type: dwrr
            weight: 10
            meter_type: packets
            cir: 32000
            pir: 40000
            cbs: 30000
            pbs: 35000
    state: merged

# After state:
# ------------
#
# sonic# show qos scheduler-policy
# Scheduler Policy: policy1
#   Queue: 0
#              type: dwrr
#              weight: 10
#              meter-type: packets
#              cir: 32000       Pps
#              cbs: 30000       Packets
#              pir: 40000       Pps
#              pbs: 35000       Packets
#
#
# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show qos scheduler-policy
# Scheduler Policy: policy1
#   Queue: 0
#              type: dwrr
#              weight: 10
#              meter-type: packets
#              cir: 32000       Pps
#              cbs: 30000       Packets
#              pir: 40000       Pps
#              pbs: 35000       Packets

- name: Replace QoS scheduler configurations
  dellemc.enterprise_sonic.sonic_qos_scheduler:
    config:
      - name: policy1
        schedulers:
          - sequence: 0
            weight: 12
    state: replaced

# After state:
# ------------
#
# sonic# show qos scheduler-policy
# Scheduler Policy: policy1
#   Queue: 0
#              weight: 12
#
#
# Using "overridden" state
# Before state:
# -------------
#
# sonic# show qos scheduler-policy
# Scheduler Policy: policy1
#   Queue: 0
#              type: dwrr
#              weight: 10
#              meter-type: packets
#              cir: 32000       Pps
#              cbs: 30000       Packets
#              pir: 40000       Pps
#              pbs: 35000       Packets
#   Queue: 1
#              type: dwrr
#              weight: 14
#              meter-type: packets

- name: Override QoS scheduler configurations
  dellemc.enterprise_sonic.sonic_qos_scheduler:
    config:
      - name: policy2
        schedulers:
          - sequence: 0
            scheduler_type: wrr
            weight: 5
            meter_type: bytes
            cir: 50000
            pir: 60000
            cbs: 800000
            pbs: 900000
    state: overridden

# After state:
# ------------
#
# sonic# show qos scheduler-policy
# Scheduler Policy: policy2
#   Queue: 0
#              type: wrr
#              weight: 5
#              meter-type: bytes
#              cir: 50          Kbps
#              cbs: 800000      Bytes
#              pir: 60          Kbps
#              pbs: 900000      Bytes
#
#
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show qos scheduler-policy
# Scheduler Policy: policy1
#   Queue: 0
#              type: dwrr
#              weight: 10
#              meter-type: packets
#              cir: 32000       Pps
#              cbs: 30000       Packets
#              pir: 40000       Pps
#              pbs: 35000       Packets
#   Queue: 1
#              type: dwrr
#              weight: 14
#              meter-type: packets
# Scheduler Policy: policy2
#   Queue: 0
#              type: wrr
#              weight: 5
#              meter-type: bytes
#              cir: 50          Kbps
#              cbs: 800000      Bytes
#              pir: 60          Kbps
#              pbs: 900000      Bytes

- name: Delete QoS scheduler configurations
  dellemc.enterprise_sonic.sonic_qos_scheduler:
    config:
      - name: policy1
        schedulers:
          - sequence: 0
            cir: 32000
            pir: 40000
            cbs: 30000
            pbs: 35000
          - sequence: 1
      - name: policy2
    state: deleted

# After state:
# -------------
#
# sonic# show qos scheduler-policy
# Scheduler Policy: policy1
#   Queue: 0
#              type: dwrr
#              weight: 10
#              meter-type: packets
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.qos_scheduler.qos_scheduler import Qos_schedulerArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.qos_scheduler.qos_scheduler import Qos_scheduler


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Qos_schedulerArgs.argument_spec,
                           supports_check_mode=True)

    result = Qos_scheduler(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
