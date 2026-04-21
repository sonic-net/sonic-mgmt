#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_qos_wred
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_qos_wred
version_added: 2.5.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
short_description: Manage QoS WRED profiles configuration on SONiC
description:
  - This module provides configuration management of QoS WRED profiles for devices running SONiC
author: "S. Talabi (@stalabi1)"
options:
  config:
    description:
      - QoS WRED profile configuration
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Name of the WRED profile
        type: str
        required: True
      ecn:
        description:
          - ECN setting for colored packets
        type: str
        choices:
          - green
      green:
        description:
          - WRED configuration for green packets
        type: dict
        suboptions:
          enable:
            description:
              - Enable or disable WRED for green packets
            type: bool
          min_threshold:
            description:
              - Minimum threshold set for green packets in bytes
              - Range 1000-12480000
            type: int
          max_threshold:
            description:
              - Maximum threshold set for green packets in bytes
              - Range 1000-12480000
            type: int
          drop_probability:
            description:
              - Drop probablity percentage rate for green packets
              - Range 0-100
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
# sonic# show qos wred-policy
# (No qos wred-policy configuration present)

- name: Merge QoS WRED policy configuration
  dellemc.enterprise_sonic.sonic_qos_wred:
    config:
      - name: profile1
        ecn: green
        green:
          enable: true
          min_threshold: 1000
          max_threshold: 5000
          drop_probability: 25
    state: merged

# After state:
# ------------
#
# sonic# show qos wred-policy
# ---------------------------------------------------
# Policy                 : profile1
# ---------------------------------------------------
# ecn                    : ecn_green
# green-min-threshold    : 1           KBytes
# green-max-threshold    : 5           KBytes
# green-drop-probability : 25
#
#
# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show qos wred-policy
# ---------------------------------------------------
# Policy                 : profile1
# ---------------------------------------------------
# ecn                    : ecn_green
# green-min-threshold    : 1           KBytes
# green-max-threshold    : 5           KBytes
# green-drop-probability : 25

- name: Replace QoS WRED policy configuration
  dellemc.enterprise_sonic.sonic_qos_wred:
    config:
      - name: profile1
        green:
          drop_probability: 75
    state: replaced

# After state:
# ------------
#
# sonic# show qos wred-policy
# ---------------------------------------------------
# Policy                 : profile1
# ---------------------------------------------------
# green-drop-probability : 75

# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show qos wred-policy
# ---------------------------------------------------
# Policy                 : profile1
# ---------------------------------------------------
# ecn                    : ecn_green
# green-min-threshold    : 1           KBytes
# green-max-threshold    : 5           KBytes
# green-drop-probability : 25

- name: Override QoS WRED policy configuration
  dellemc.enterprise_sonic.sonic_qos_wred:
    config:
      - name: profile2
        ecn: green
        green:
          enable: false
          min_threshold: 3000
          max_threshold: 9000
          drop_probability: 75
    state: overridden

# After state:
# ------------
#
# sonic# show qos wred-policy
# ---------------------------------------------------
# Policy                 : profile2
# ---------------------------------------------------
# ecn                    : ecn_green
# green-min-threshold    : 3           KBytes
# green-max-threshold    : 9           KBytes
# green-drop-probability : 75
#
#
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show qos wred-policy
# ---------------------------------------------------
# Policy                 : profile1
# ---------------------------------------------------
# ecn                    : ecn_green
# green-min-threshold    : 1           KBytes
# green-max-threshold    : 5           KBytes
# green-drop-probability : 25
# ---------------------------------------------------
# Policy                 : profile2
# ---------------------------------------------------
# ecn                    : ecn_green
# green-min-threshold    : 3           KBytes
# green-max-threshold    : 9           KBytes
# green-drop-probability : 75

- name: Delete QoS WRED policy configuration
  dellemc.enterprise_sonic.sonic_qos_wred:
    config:
      - name: profile1
      - name: profile2
        green:
          enable: false
          min_threshold: 3000
          max_threshold: 9000
    state: deleted

# After state:
# ------------
#
# sonic# show qos wred-policy
# ---------------------------------------------------
# Policy                 : profile2
# ---------------------------------------------------
# ecn                    : ecn_green
# green-drop-probability : 75
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.qos_wred.qos_wred import Qos_wredArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.qos_wred.qos_wred import Qos_wred


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Qos_wredArgs.argument_spec,
                           supports_check_mode=True)

    result = Qos_wred(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
