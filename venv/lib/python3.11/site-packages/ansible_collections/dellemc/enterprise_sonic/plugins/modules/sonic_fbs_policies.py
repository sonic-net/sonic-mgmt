#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_fbs_policies
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_fbs_policies
version_added: 3.1.0
notes:
  - Tested against Enterprise SONiC Distribution by Dell Technologies.
  - Supports C(check_mode).
short_description: Manage flow based services (FBS) policies configuration on SONiC
description:
  - This module provides configuration management of FBS policies for devices running SONiC
author: S. Talabi (@stalabi1)
options:
  config:
    description:
      - FBS policies configuration
    type: list
    elements: dict
    suboptions:
      policy_name:
        description:
          - Name of policy
        type: str
        required: true
      policy_type:
        description:
          - Type of policy
        type: str
        choices: ['acl-copp', 'copp', 'forwarding', 'monitoring', 'qos']
      policy_description:
        description:
          - Description of policy
        type: str
      sections:
        description:
          - Policy sections configuration
        type: list
        elements: dict
        suboptions:
          class:
            description:
              - Name of classifier
            type: str
            required: true
          priority:
            description:
              - Flow priority in the policy, range 0-4095
            type: int
          section_description:
            description:
              - Description of section
            type: str
          acl_copp:
            description:
              - ACL CoPP configuration
              - I(policy_type) must be configured to C(acl-copp) for user-assigned policy names
              - or C(copp) for I(policy_name = copp-system-policy)
            type: dict
            suboptions:
              cpu_queue_index:
                description:
                  - CPU queue index, range 0-31
                type: int
              policer:
                description:
                  - Traffic policing configuration
                type: dict
                suboptions:
                  cir:
                    description:
                      - Committed information rate measured in bps, range 1-4294967295
                    type: int
                  pir:
                    description:
                      - Peak information rate measured in bps, range 1-4294967295
                    type: int
                  cbs:
                    description:
                      - Committed burst size measured Bps, range 1-4294967295
                    type: int
                  pbs:
                    description:
                      - Peak burst size measured in Bps, range 1-4294967295
                    type: int
          qos:
            description:
              - QoS action configuration
              - I(policy_type) must be configured to C(qos)
            type: dict
            suboptions:
              output_queue_index:
                description:
                  - Output queue index, range 0-7
                type: int
              policer:
                description:
                  - Traffic policing configuration
                type: dict
                suboptions:
                  cir:
                    description:
                      - Committed information rate measured in bps, range 1-4294967295
                    type: int
                  pir:
                    description:
                      - Peak information rate measured in bps, range 1-4294967295
                    type: int
                  cbs:
                    description:
                      - Committed burst size measured Bps, range 1-4294967295
                    type: int
                  pbs:
                    description:
                      - Peak burst size measured in Bps, range 1-4294967295
                    type: int
              remark:
                description:
                  - Remark configuration
                type: dict
                suboptions:
                  set_dscp:
                    description:
                      - Set DSCP remarking value, range 0-63
                    type: int
                  set_dot1p:
                    description:
                      - Set Dot1p remarking value, range 0-7
                    type: int
          mirror_sessions:
            description:
              - Mirroring sessions configuration
              - I(policy_type) must be configured to C(monitoring)
            type: list
            elements: dict
            suboptions:
              session_name:
                description:
                  - Name of the mirror session
                type: str
                required: true
          forwarding:
            description:
              - Forwarding actions configuration
              - I(policy_type) must be configured to C(forwarding)
            type: dict
            suboptions:
              ars_disable:
                description:
                  - Enable/disable adaptive routing and switching forwarding
                  - Functional default is C(false)
                type: bool
              egress_interfaces:
                description:
                  - Egress interfaces configuration
                type: list
                elements: dict
                suboptions:
                  intf_name:
                    description:
                      - Name of interface
                    type: str
                    required: true
                  priority:
                    description:
                      - Priority of the egress interfaces to be selected for forwarding, range 1-65535
                    type: int
              next_hops:
                description:
                  - Next hops configuration for L3 forwarding
                type: list
                elements: dict
                suboptions:
                  address:
                    description:
                      - Forwarding IP/IPv6 address
                    type: str
                    required: true
                  vrf:
                    description:
                      - Forwarding network instance
                    type: str
                  priority:
                    description:
                      - Priority of the next hop to be selected for forwarding, range 1-65535
                    type: int
              next_hop_groups:
                description:
                  - Next hop groups configuration for L3 forwarding
                type: list
                elements: dict
                suboptions:
                  group_name:
                    description:
                      - Name of next hop group
                    type: str
                    required: true
                  group_type:
                    description:
                      - Type of next hop group
                    type: str
                    choices: ['ipv4', 'ipv6']
                  priority:
                    description:
                      - Priority of the next hop group to be selected for forwarding, range 1-65535
                    type: int
              replication_groups:
                description:
                  - Replication groups configuration for L3 forwarding
                type: list
                elements: dict
                suboptions:
                  group_name:
                    description:
                      - Name of replication group
                    type: str
                    required: true
                  group_type:
                    description:
                      - Type of replication group
                    type: str
                    choices: ['ipv4', 'ipv6']
                  priority:
                    description:
                      - Priority of the replication group to be selected for forwarding, range 1-65535
                    type: int
  state:
    description:
      - The state of the configuration after module completion
    type: str
    choices: ['merged', 'deleted', 'replaced', 'overridden']
    default: merged
"""

EXAMPLES = """
# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration policy-map
# (No policy-map configuration present)

- name: Merge FBS policies configuration
  dellemc.enterprise_sonic.sonic_fbs_policies:
    config:
      - policy_name: policy1
        policy_description: abc
        policy_type: forwarding
        sections:
          - class: class1
            forwarding:
              ars_disable: true
              egress_interfaces:
                - intf_name: Ethernet96
                  priority: 1
            priority: 0
            section_description: xyz
      - policy_name: policy2
        policy_description: qwerty
        policy_type: acl-copp
        sections:
          - class: class1
            acl_copp:
              cpu_queue_index: 0
              policer:
                cbs: 80
                cir: 75
                pbs: 95
                pir: 96
            priority: 0
      - policy_name: policy3
        policy_description: 'this is policy 3'
        policy_type: qos
        sections:
          - class: class1
            qos:
              output_queue_index: 0
              policer:
                cbs: 15
                cir: 20
                pbs: 21
                pir: 24
              remark:
                set_dot1p: 0
                set_dscp: 0
            priority: 0
      - policy_name: policy4
        policy_description: 'this is policy 4'
        policy_type: monitoring
        sections:
          - class: class1
            mirror_sessions:
              - session_name: session1
            priority: 0
      - policy_name: policy5
        policy_description: abc
        policy_type: forwarding
        sections:
          - class: class1
            forwarding:
              next_hops:
                - address: 1.1.1.1
                  vrf: default
                  priority: 1
              next_hop_groups:
                - group_name: hop1
                  group_type: ipv4
                  priority: 1
              replication_groups:
                - group_name: rep1
                  group_type: ipv4
                  priority: 1
            priority: 0
            section_description: 'section for class1'
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration policy-map
# !
# policy-map policy1 type forwarding
#  description abc
#  class class1 priority 0
#  description xyz
#   set interface Ethernet96 priority 1
#   set ars disable
#  !
# !
# policy-map policy2 type acl-copp
#  description qwerty
#  class class1 priority 0
#   set trap-queue 0
#   police cir 75 cbs 80 pir 96 pbs 95
#  !
# !
# policy-map policy3 type qos
#  description "this is policy 3"
#  class class1 priority 0
#   set pcp 0
#   set dscp 0
#   set traffic-class 0
#   police cir 20 cbs 15 pir 24 pbs 21
#  !
# !
# policy-map policy4 type monitoring
#  description "this is policy 4"
#  class class1 priority 0
#   set mirror-session session1
#  !
# !
# policy-map policy5 type forwarding
#  description abc
#  class class1 priority 0
#  description "section for class1"
#   set ip next-hop 1.1.1.1 vrf default priority 1
#   set ip next-hop-group hop1 priority 1
#   set ip replication-group rep1 priority 1
#  !


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration policy-map
# !
# policy-map policy1 type forwarding
#  description abc
#  class class1 priority 0
#  description xyz
#   set interface Ethernet20 priority 1
#   set ars disable
#  !
# !
# policy-map policy2 type acl-copp
#  description qwerty
#  class class1 priority 0
#   set trap-queue 0
#   police cir 75 cbs 80 pir 96 pbs 95
#  !

- name: Replace FBS policies configuration
  dellemc.enterprise_sonic.sonic_fbs_policies:
    config:
      - policy_name: policy1
        policy_description: 'abc123'
        policy_type: monitoring
        sections:
          - class: class1
            mirror_sessions:
              - session_name: mirror1
            priority: 0
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration policy-map
# !
# policy-map policy1 type monitoring
#  description "abc123"
#  class class1 priority 0
#   set mirror-session mirror1
#  !
# !
# policy-map policy2 type acl-copp
#  description qwerty
#  class class1 priority 0
#   set trap-queue 0
#   police cir 75 cbs 80 pir 96 pbs 95
#  !


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show running-configuration policy-map
# !
# policy-map policy1 type forwarding
#  description abc
#  class class1 priority 0
#  description xyz
#   set interface Ethernet20 priority 1
#   set ars disable
#  !

- name: Override FBS policies configuration
  dellemc.enterprise_sonic.sonic_fbs_policies:
    config:
      - policy_name: policy2
        policy_description: qwerty
        policy_type: copp
        sections:
          - class: class1
            acl_copp:
              cpu_queue_index: 0
              policer:
                cbs: 80
                cir: 75
                pbs: 95
                pir: 96
            priority: 0
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration policy-map
# !
# policy-map policy2 type acl-copp
#  description qwerty
#  class class1 priority 0
#   set trap-queue 0
#   police cir 75 cbs 80 pir 96 pbs 95
#  !


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration policy-map
# !
# policy-map policy1 type forwarding
#  description abc
#  class class1 priority 0
#  description xyz
#   set interface Ethernet20 priority 1
#   set ars disable
#  !
# !
# policy-map policy2 type acl-copp
#  description qwerty
#  class class1 priority 0
#   set trap-queue 0
#   police cir 75 cbs 80 pir 96 pbs 95
#  !
# !
# policy-map policy3 type monitoring
#  description "this is policy 3"
#  class class1 priority 0
#   set mirror-session mirror1
#  !

- name: Delete FBS policies configuration
  dellemc.enterprise_sonic.sonic_fbs_policies:
    config:
      - policy_name: policy1
      - policy_name: policy2
        sections:
          - class: class1
            acl_copp:
              policer:
                cbs: 80
                cir: 75
                pbs: 95
                pir: 96
      - policy_name: policy3
        sections:
          - class: class1
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration policy-map
# !
# policy-map policy2 type acl-copp
#  description qwerty
#  class class1 priority 0
#   set trap-queue 0
#  !
# !
# policy-map policy3 type monitoring
#  description "this is policy 3"
#  !


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration policy-map
# !
# policy-map policy2 type acl-copp
#  description qwerty
#  class class1 priority 0
#   set trap-queue 0
#  !
# !
# policy-map policy3 type monitoring
#  description "this is policy 3"
#  !

- name: Delete all FBS policies configuration
  dellemc.enterprise_sonic.sonic_fbs_policies:
    config:
    state: deleted

# After state:
# -------------
#
# sonic# show running-configuration policy-map
# (No policy-map configuration present)
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.fbs_policies.fbs_policies import Fbs_policiesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.fbs_policies.fbs_policies import Fbs_policies


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Fbs_policiesArgs.argument_spec,
                           supports_check_mode=True)

    result = Fbs_policies(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
