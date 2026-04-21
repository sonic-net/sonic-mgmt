#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_qos_buffer
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_qos_buffer
version_added: 2.5.0
notes:
  - Tested against Enterprise SONiC Distribution by Dell Technologies.
  - Supports C(check_mode).
short_description: Manage QoS buffer configuration on SONiC
description:
  - This module provides configuration management of QoS buffer for devices running SONiC
author: "S. Talabi (@stalabi1)"
options:
  config:
    description:
      - QoS buffer configuration
    type: dict
    suboptions:
      buffer_init:
        description:
          - Initialize QoS buffer based on system defaults
        type: bool
        version_added: 3.0.0
      buffer_pools:
        description:
          - Buffer pools configuration
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Name of buffer pool
            type: str
            choices:
              - ingress_lossless_pool
            required: True
          xoff:
            description:
              - Amount of shared buffer space in bytes, must be less than pool size
              - Required non-key attribute
            type: int
      buffer_profiles:
        description:
          - Buffer profiles configuration
          - I(static_threshold) and I(dynamic_threshold) are mutually exclusive required non-key attributes
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Name of buffer profile
            type: str
            required: True
          pool:
            description:
              - Name of buffer pool
              - Required non-key attribute
            type: str
            choices:
              - ingress_lossless_pool
              - egress_lossless_pool
              - egress_lossy_pool
          size:
            description:
              - Size of reserved buffer in bytes
              - Required non-key attribute
            type: int
          static_threshold:
            description:
              - Static threshold for the shared usage in bytes
            type: int
          dynamic_threshold:
            description:
              - Dynamic threshold value
              - Range -6-3
            type: int
          pause_threshold:
            description:
              - Threshold value at which to stop traffic from peer
              - Range 46080-8388608
              - Configurable for ingress lossless pool
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
# sonic# show running-configuration | grep buffer
# buffer init lossless
# buffer pool ingress_lossless_pool shared-headroom-size 1000000

- name: Merge QoS buffer configuration
  dellemc.enterprise_sonic.sonic_qos_buffer:
    config:
      buffer_init: true
      buffer_pools:
        - name: ingress_lossless_pool
          xoff: 3500000
      buffer_profiles:
        - name: profile1
          pool: ingress_lossless_pool
          size: 45
          static_threshold: 25
          pause_threshold: 55000
        - name: profile2
          pool: egress_lossless_pool
          size: 85
          dynamic_threshold: -2
        - name: profile3
          pool: egress_lossy_pool
          size: 90
          static_threshold: 30
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration | grep buffer
# buffer init lossless
# buffer pool ingress_lossless_pool shared-headroom-size 3500000
# buffer profile profile1 ingress_lossless_pool 45 static-threshold 25 pause pause-threshold 55000
# buffer profile profile2 egress_lossy_pool 85 dynamic-threshold -2
# buffer profile profile3 egress_lossless_pool 90 static-threshold 30
#
#
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep buffer
# buffer init lossless
# buffer pool ingress_lossless_pool shared-headroom-size 3500000
# buffer profile profile1 ingress_lossless_pool 45 static-threshold 25 pause pause-threshold 55000
# buffer profile profile2 egress_lossy_pool 85 dynamic-threshold -2
# buffer profile profile3 egress_lossless_pool 90 static-threshold 30

- name: Delete QoS buffer profile configuration
  dellemc.enterprise_sonic.sonic_qos_buffer:
    config:
      buffer_profiles:
        - name: profile1
          static_threshold: 25
          pause_threshold: 55000
        - name: profile2
          dynamic_threshold: -2
        - name: profile3
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration | grep buffer
# buffer init lossless
# buffer pool ingress_lossless_pool shared-headroom-size 3500000
# buffer profile profile1 ingress_lossless_pool 45
# buffer profile profile2 egress_lossy_pool 85
"""

RETURN = """
before:
  description: The configuration prior to the model invocation.
  returned: always
  type: list
  sample: >
    The configuration returned will always be in the same format
    of the parameters above.
after:
  description: The resulting configuration model invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
    of the parameters above.
after(generated):
  description: The generated configuration model invocation.
  returned: when C(check_mode)
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.qos_buffer.qos_buffer import Qos_bufferArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.qos_buffer.qos_buffer import Qos_buffer


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Qos_bufferArgs.argument_spec,
                           supports_check_mode=True)

    result = Qos_buffer(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
