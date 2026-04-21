#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_drop_counter
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_drop_counter
version_added: 3.1.0
notes:
  - Tested against Enterprise SONiC Distribution by Dell Technologies
  - Supports C(check_mode)
short_description: Manage drop counter configuration on SONiC
description:
  - This module provides configuration management of drop counter for devices running SONiC
author: S. Talabi (@stalabi1)
options:
  config:
    description:
      - List of drop counter configurations
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Name of drop counter
        type: str
        required: true
      alias:
        description:
          - Alias of drop counter
        type: str
      counter_description:
        description:
          - Description of drop counter
        type: str
      counter_type:
        description:
          - Type of drop counter
        type: str
        choices:
          - PORT_INGRESS_DROPS
      enable:
        description:
          - Enable drop counter
        type: bool
      group:
        description:
          - Group of drop counter
        type: str
      mirror:
        description:
          - Mirror session to mirror the drop counter
        type: str
      reasons:
        description:
          - List of drop counter reasons
        type: list
        elements: str
        choices:
          - ACL_ANY
          - ANY
          - DIP_LINK_LOCAL
          - EXCEEDS_L3_MTU
          - FDB_AND_BLACKHOLE_DISCARDS
          - IP_HEADER_ERROR
          - L3_EGRESS_LINK_DOWN
          - MPLS_MISS
          - SIP_LINK_LOCAL
          - SMAC_EQUALS_DMAC
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
# sonic# show running-configuration dropcounters
# (No 'dropcounters' configuration present)

- name: Merge drop counter configuration
  dellemc.enterprise_sonic.sonic_drop_counter:
    config:
      - name: counter1
        alias: c1
        counter_description: abc
        counter_type: PORT_INGRESS_DROPS
        enable: true
        group: group1
        mirror: session1
        reasons:
          - ANY
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration dropcounters
# !
# dropcounters counter1
#  enable
#  type PORT_INGRESS_DROPS
#  alias c1
#  group group1
#  description "abc"
#  mirror session1
#  add-reason ANY


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration dropcounters
# !
# dropcounters counter1
#  enable
#  type PORT_INGRESS_DROPS
#  alias c1
#  group group1
#  description "abc"
#  mirror session1
#  add-reason ANY
# !
# dropcounters counter2
#  no enable
#  type PORT_INGRESS_DROPS
#  alias drop2
#  group group2
#  description "xyz789"
#  add-reason IP_HEADER_ERROR,L3_EGRESS_LINK_DOWN,SMAC_EQUALS_DMAC

- name: Replace drop counter configuration
  dellemc.enterprise_sonic.sonic_drop_counter:
    config:
      - name: counter1
        counter_description: abc123
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration dropcounters
# !
# dropcounters counter1
#  description "abc123"
# !
# dropcounters counter2
#  no enable
#  type PORT_INGRESS_DROPS
#  alias drop2
#  group group2
#  description "xyz789"
#  add-reason IP_HEADER_ERROR,L3_EGRESS_LINK_DOWN,SMAC_EQUALS_DMAC


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show running-configuration dropcounters
# !
# dropcounters counter1
#  enable
#  type PORT_INGRESS_DROPS
#  alias c1
#  group group1
#  description "abc"
#  mirror session1
#  add-reason ANY
# !
# dropcounters counter2
#  no enable
#  type PORT_INGRESS_DROPS
#  alias drop2
#  group group2
#  description "xyz789"
#  add-reason IP_HEADER_ERROR,L3_EGRESS_LINK_DOWN,SMAC_EQUALS_DMAC

- name: Override drop counter configuration
  dellemc.enterprise_sonic.sonic_drop_counter:
    config:
      - name: counter3
        alias: c3
        counter_description: qwerty
        counter_type: PORT_INGRESS_DROPS
        enable: true
        group: group3
        mirror: session2
        reasons:
          - ACL_ANY
          - FDB_AND_BLACKHOLE_DISCARDS
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration dropcounters
# !
# dropcounters counter3
#  enable
#  type PORT_INGRESS_DROPS
#  alias c3
#  group group3
#  description "qwerty"
#  mirror session2
#  add-reason ACL_ANY,FDB_AND_BLACKHOLE_DISCARDS


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration dropcounters
# !
# dropcounters counter1
#  enable
#  type PORT_INGRESS_DROPS
#  alias c1
#  group group1
#  description "abc"
#  mirror session1
#  add-reason ANY
# !
# dropcounters counter2
#  no enable
#  type PORT_INGRESS_DROPS
#  alias drop2
#  group group2
#  description "xyz789"
#  add-reason IP_HEADER_ERROR,L3_EGRESS_LINK_DOWN,SMAC_EQUALS_DMAC

- name: Delete drop counter configuration
  dellemc.enterprise_sonic.sonic_drop_counter:
    config:
      - name: counter1
        alias: c1
        counter_description: abc
      - name: counter2
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration dropcounters
# !
# dropcounters counter1
#  enable
#  type PORT_INGRESS_DROPS
#  group group1
#  mirror session1
#  add-reason ANY


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration dropcounters
# !
# dropcounters counter1
#  enable
#  type PORT_INGRESS_DROPS
#  group group1
#  mirror session1
#  add-reason ANY

- name: Delete all drop counter configuration
  dellemc.enterprise_sonic.sonic_drop_counter:
    config:
    state: deleted

# After state:
# ------------
#
# (No 'dropcounters' configuration present)
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: list
after:
  description: The configuration resulting from module invocation.
  returned: when changed
  type: list
after(generated):
  description: The generated configuration from module invocation.
  returned: when C(check_mode)
  type: list
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.drop_counter.drop_counter import Drop_counterArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.drop_counter.drop_counter import Drop_counter


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Drop_counterArgs.argument_spec,
                           supports_check_mode=True)

    result = Drop_counter(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
