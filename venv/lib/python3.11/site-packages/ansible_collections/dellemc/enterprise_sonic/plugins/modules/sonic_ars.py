#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_ars
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_ars
version_added: "3.1.0"
notes:
  - Tested against Enterprise SONiC Distribution by Dell Technologies.
  - Supports C(check_mode).
short_description: Manage adaptive routing and switching (ARS) configuration on SONiC
description:
  - This module provides configuration management of ARS for devices running SONiC
author: "S. Talabi (@stalabi1)"
options:
  config:
    description:
      - ARS configuration
    type: dict
    suboptions:
      profiles:
        description:
          - List of ARS profiles configuration
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Name of profile
            type: str
            required: true
          algorithm:
            description:
              - ARS algorithm used for quality computation
              - C(EWMA) - Exponential Weighted Moving Average
            type: str
            choices: [EWMA]
          load_current_max_val:
            description:
              - Maximum current load threshold value for the quantization process
              - Range 0-133169151
            type: int
          load_current_min_val:
            description:
              - Minimum current load threshold value for the quantization process
              - Range 0-133169151
            type: int
          load_future_max_val:
            description:
              - Maximum future load threshold value for the quantization process
              - Range 0-266338303
            type: int
          load_future_min_val:
            description:
              - Minimum future load threshold value for the quantization process
              - Range 0-266338303
            type: int
          load_past_max_val:
            description:
              - Maximum past load threshold value for the quantization process
              - Range 0-10000
            type: int
          load_past_min_val:
            description:
              - Minimum past load threshold value for the quantization process
              - Range 0-10000
            type: int
          port_load_current:
            description:
              - Set port load to current sampled value when sampled value is less than the average
            type: bool
          port_load_exponent:
            description:
              - EWMA exponent used in port loading computation
              - Range 1-16
            type: int
          port_load_future:
            description:
              - Enable/disable future port load, the average queued bytes measured on a port
            type: bool
          port_load_future_weight:
            description:
              - Weight of future port load used in EWMA calculations
              - Range 1-16
            type: int
          port_load_past:
            description:
              - Enable/disable past port load, the average egress bytes measured on a port
            type: bool
          port_load_past_weight:
            description:
              - Weight of past port load used in EWMA calculations
              - Range 1-16
            type: int
          random_seed:
            description:
              - Random seed value
              - Range 0-16777214
            type: int
          sampling_interval:
            description:
              - Sampling interval in microseconds
              - Range 1-255
            type: int
      port_profiles:
        description:
          - List of ARS port profiles configuration
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Name of port profile
            type: str
            required: true
          enable:
            description:
              - Enable/disable ARS for the port
            type: bool
          load_future_weight:
            description:
              - Weight of future port load used in EWMA calculations
              - Range 1-16
            type: int
          load_past_weight:
            description:
              - Weight as a percentage of the past port load
              - Range 0-100
            type: int
          load_scaling_factor:
            description:
              - Port load scaling factor
            type: float
            choices: [0, 1, 2.5, 4, 5, 10, 20, 40, 80]
      port_bindings:
        description:
          - List of ARS port bindings configuration
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Name of port
            type: str
            required: true
          profile:
            description:
              - ARS port profile to bind to port
              - Required for modifcation
            type: str
      switch_binding:
        description:
          - ARS switch binding configuration
        type: dict
        suboptions:
          profile:
            description:
              - ARS profile to bind to switch
            type: str
      ars_objects:
        description:
          - List of ARS next-hop group objects configuration
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Name of next-hop group object
            type: str
            required: true
          idle_time:
            description:
              - Idle time in microseconds
              - Range 16-32767
            type: int
          max_flows:
            description:
              - Maximum number of flows that can be maintained by the ARS object
            type: int
            choices: [256, 512, 1024, 2048, 4096, 8192, 16384, 32768]
          mode:
            description:
              - ARS path reassignment mode
            type: str
            choices: [fixed, flowlet-quality, flowlet-random, packet-quality, packet-random]
  state:
    description:
      - The state of the configuration after module completion
    type: str
    choices: [merged, deleted, replaced, overridden]
    default: merged
"""

EXAMPLES = """
# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration ars
# (No ARS configuration present)

- name: Merge ARS configuration
  dellemc.enterprise_sonic.sonic_ars:
    config:
      ars_objects:
        - name: obj1
          idle_time: 100
          max_flows: 1024
          mode: flowlet-quality
      port_profiles:
        - name: pp1
          enable: true
          load_future_weight: 9
          load_past_weight: 20
          load_scaling_factor: 0
      profiles:
        - name: p1
          algorithm: EWMA
          load_current_max_val: 10000
          load_current_min_val: 100
          load_future_max_val: 20000
          load_future_min_val: 200
          load_past_max_val: 500
          load_past_min_val: 50
          port_load_current: true
          port_load_exponent: 7
          port_load_future: true
          port_load_future_weight: 9
          port_load_past: true
          port_load_past_weight: 11
          random_seed: 800000
          sampling_interval: 140
      port_bindings:
        - name: Ethernet20
          profile: pp1
      switch_binding:
        profile: p1
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration ars
# ars profile p1
#  sampling-interval 140
#  random-seed 800000
#  port-load-past-weight 11
#  port-load-future-weight 9
#  port-load-current
#  port-load-exponent 7
#  load-past-min-val 50
#  load-past-max-val 500
#  load-future-min-val 200
#  load-future-max-val 20000
#  load-current-min-val 100
#  load-current-max-val 10000
# !
# ars port-profile pp1
#  enable
#  load-past-weight 20
#  load-future-weight 9
# !
# ars object obj1
#  idle-time 100
#  max-flows 1024
# !
# interface Ethernet20
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  shutdown
#  ars bind pp1
# !
# ars bind profile p1


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration ars
# ars profile p1
#  sampling-interval 140
#  random-seed 800000
#  port-load-past-weight 11
#  port-load-future-weight 9
#  port-load-current
#  port-load-exponent 7
#  load-past-min-val 50
#  load-past-max-val 500
#  load-future-min-val 200
#  load-future-max-val 20000
#  load-current-min-val 100
#  load-current-max-val 10000
# !
# ars port-profile pp1
#  enable
#  load-past-weight 20
#  load-future-weight 9
# !
# ars object obj1
#  idle-time 100
#  max-flows 1024
# !
# interface Ethernet20
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  shutdown
#  ars bind pp1
# !
# ars bind profile p1

- name: Replace ARS configuration
  dellemc.enterprise_sonic.sonic_ars:
    config:
      port_profiles:
        - name: pp2
          enable: true
          load_future_weight: 8
          load_past_weight: 15
      port_bindings:
        - name: Ethernet20
          profile: pp2
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration ars
# ars profile p1
#  sampling-interval 140
#  random-seed 800000
#  port-load-past-weight 11
#  port-load-future-weight 9
#  port-load-current
#  port-load-exponent 7
#  load-past-min-val 50
#  load-past-max-val 500
#  load-future-min-val 200
#  load-future-max-val 20000
#  load-current-min-val 100
#  load-current-max-val 10000
# !
# ars port-profile pp2
#  enable
#  load-past-weight 15
#  load-future-weight 8
# !
# ars object obj1
#  idle-time 100
#  max-flows 1024
# !
# interface Ethernet20
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  shutdown
#  ars bind pp2
# !
# ars bind profile p1


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show running-configuration ars
# ars profile p1
#  sampling-interval 140
#  random-seed 800000
#  port-load-past-weight 11
#  port-load-future-weight 9
#  port-load-current
#  port-load-exponent 7
#  load-past-min-val 50
#  load-past-max-val 500
#  load-future-min-val 200
#  load-future-max-val 20000
#  load-current-min-val 100
#  load-current-max-val 10000
# !
# ars port-profile pp2
#  enable
#  load-past-weight 15
#  load-future-weight 8
# !
# ars object obj1
#  idle-time 100
#  max-flows 1024
# !
# interface Ethernet20
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  shutdown
#  ars bind pp1
# !
# ars bind profile p1

- name: Override ARS configuration
  dellemc.enterprise_sonic.sonic_ars:
    config:
      ars_objects:
        - name: obj4
          idle_time: 65
          max_flows: 4096
          mode: flowlet-quality
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration ars
# ars object obj4
#  idle-time 65
#  max-flows 4096


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration ars
# ars profile p1
#  sampling-interval 140
#  random-seed 800000
#  port-load-past-weight 11
#  port-load-future-weight 9
#  port-load-current
#  port-load-exponent 7
#  load-past-min-val 50
#  load-past-max-val 500
#  load-future-min-val 200
#  load-future-max-val 20000
#  load-current-min-val 100
#  load-current-max-val 10000
# !
# ars port-profile pp2
#  enable
#  load-past-weight 15
#  load-future-weight 8

- name: Delete specified ARS configuration
  dellemc.enterprise_sonic.sonic_ars:
    config:
      port_profiles:
        - name: pp2
      profiles:
        - name: p1
          load_current_max_val: 10000
          load_future_max_val: 20000
          load_past_max_val: 500
          random_seed: 800000
          sampling_interval: 140
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration ars
# ars profile p1
#  port-load-past-weight 11
#  port-load-future-weight 9
#  port-load-current
#  port-load-exponent 7
#  load-past-min-val 50
#  load-future-min-val 200
#  load-current-min-val 100


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration ars
# ars profile p1
#  sampling-interval 140
#  random-seed 800000
#  port-load-past-weight 11
#  port-load-future-weight 9
#  port-load-current
#  port-load-exponent 7
#  load-past-min-val 50
#  load-past-max-val 500
#  load-future-min-val 200
#  load-future-max-val 20000
#  load-current-min-val 100
#  load-current-max-val 10000
# !
# ars port-profile pp1
#  enable
#  load-past-weight 20
#  load-future-weight 9
# !
# ars object obj1
#  idle-time 100
#  max-flows 1024
# !
# interface Ethernet20
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  shutdown
#  ars bind pp1
# !
# ars bind profile p1

- name: Delete all ARS configuration
  dellemc.enterprise_sonic.sonic_ars:
    config:
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration ars
# (No ARS configuration present)
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
  description: The generated configuration from module invocation.
  returned: when C(check_mode)
  type: dict
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ars.ars import ArsArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.ars.ars import Ars


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=ArsArgs.argument_spec,
                           supports_check_mode=True)

    result = Ars(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
