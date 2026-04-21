#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_vlan_mapping
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_vlan_mapping
author: "Cypher Miller (@Cypher-Miller)"
version_added: "2.1.0"
short_description: Configure vlan mappings on SONiC.
description:
  - This module provides configuration management for vlan mappings on devices running SONiC.
  - Vlan mappings only available on TD3 and TD4 devices.
  - For TD4 devices must enable vlan mapping first (can enable in config-switch-resource).
options:
  config:
    description:
      - Specifies the vlan mapping related configurations.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Full name of the interface, i.e. Ethernet8, PortChannel2, Eth1/2.
        required: true
        type: str
      mapping:
        description:
          - Define vlan mappings.
          - dot1q_tunnel and vlan_translation are mutually exclusive.
        type: list
        elements: dict
        suboptions:
          service_vlan:
            description:
              - Configure service provider VLAN ID.
              - VLAN ID range is 1-4094.
            required: true
            type: int
          dot1q_tunnel:
            description:
              - Specify a vlan stacking.
            type: dict
            suboptions:
              vlan_ids:
                description:
                  - Configure customer VLAN IDs.
                  - It can pass ranges and/or multiple list entries.
                  - Individual VLAN ID or (-) separated range of VLAN IDs.
                type: list
                elements: str
              priority:
                description:
                  - Set priority level of the vlan stacking.
                  - Priority range is 0-7.
                type: int
          vlan_translation:
            description:
              - Specify a vlan translation.
            version_added: '3.0.0'
            type: dict
            suboptions:
              multi_tag:
                description:
                  - Indicate if there are multiple tags.
                type: bool
              match_single_tags:
                description:
                  - Configure single tagged vlan translation.
                type: list
                elements: dict
                suboptions:
                  outer_vlan:
                    description:
                      - Configure outer customer VLAN ID.
                      - VLAN ID range is 1-4094.
                    required: true
                    type: int
                  priority:
                    description:
                      - Set priority level of the vlan translation.
                      - Priority range is 0-7.
                    type: int
              match_double_tags:
                description:
                  - Configure double tagged vlan translation.
                type: list
                elements: dict
                suboptions:
                  inner_vlan:
                    description:
                      - Configure inner customer VLAN ID.
                      - VLAN ID range is 1-4094.
                      - Only available for double tagged translations.
                    required: true
                    type: int
                  outer_vlan:
                    description:
                      - Configure outer customer VLAN ID.
                      - VLAN ID range is 1-4094.
                    required: true
                    type: int
                  priority:
                    description:
                      - Set priority level of the vlan translation.
                      - Priority range is 0-7.
                    type: int
  state:
    description:
      - Specifies the operation to be performed on the vlan mappings configured on the device.
      - In case of merged, the input configuration will be merged with the existing vlan mappings on the device.
      - In case of deleted, the existing vlan mapping configuration will be removed from the device.
      - In case of overridden, all existing vlan mappings will be deleted and the specified input configuration will be add.
      - In case of replaced, the existing vlan mappings on the device will be replaced by the configuration for each vlan mapping.
    type: str
    default: merged
    choices:
      - merged
      - deleted
      - replaced
      - overridden
"""

EXAMPLES = """
#
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show interface vlan-mappings dot1q-tunnel
# --------------------------------------------------------------------
# Name            Vlan                     dot1q-tunnel Vlan  Priority
# --------------------------------------------------------------------
# Ethernet4       360-366,392              2755               3
#
#  - name: Delete dot1q_tunnel configuration
#    sonic_vlan_mapping:
#      config:
#        - name: Ethernet4
#          mapping:
#            - service_vlan: 2755
#              dot1q_tunnel:
#                vlan_ids:
#                  - 392
#                  - 360-362
#      state: deleted
#
# After state:
# ------------
#
# sonic# show interface vlan-mappings dot1q-tunnel
# --------------------------------------------------------------------
# Name            Vlan                     dot1q-tunnel Vlan  Priority
# --------------------------------------------------------------------
# Ethernet4       363-366                  2755               3
#
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show interface vlan-mappings
# Flags: M - Multi-tag
# ---------------------------------------------------------
# Name            Outer  Inner  Mapped Vlan  Priority Flags
# ---------------------------------------------------------
# Ethernet8       610    600    2567         -        -
# Ethernet8       611    601    2567         1        -
# Ethernet8       612    602    2567         2        -
#
#  - name: Delete vlan translation configuration
#    sonic_vlan_mapping:
#      config:
#        - name: Ethernet8
#          mapping:
#          - service_vlan: 2567
#            vlan_translation:
#              match_double_tags:
#                - inner_vlan: 602
#                  outer_vlan: 612
#                  priority: 2
#      state: deleted
#
# After state:
# ------------
#
# sonic# show interface vlan-mappings
# Flags: M - Multi-tag
# ---------------------------------------------------------
# Name            Outer  Inner  Mapped Vlan  Priority Flags
# ---------------------------------------------------------
# Ethernet8       610    600    2567         -        -
# Ethernet8       611    601    2567         1        -
#
#
# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show interface vlan-mappings dot1q-tunnel
#
#  - name: Merge dot1q_tunnel configuration
#    sonic_vlan_mapping:
#      config:
#        - name: Ethernet4
#          mapping:
#            - service_vlan: 2755
#              dot1q_tunnel:
#                vlan_ids:
#                  - 392
#                  - 360-366
#                priority: 3
#      state: merged
#
# After state:
# ------------
#
# sonic# show interface vlan-mappings dot1q-tunnel
# --------------------------------------------------------------------
# Name            Vlan                     dot1q-tunnel Vlan  Priority
# --------------------------------------------------------------------
# Ethernet4       360-366,392              2755               3
#
# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show interface vlan-mappings dot1q-tunnel
# --------------------------------------------------------------------
# Name            Vlan                     dot1q-tunnel Vlan  Priority
# --------------------------------------------------------------------
# Ethernet4       360-366,392              2755               3
#
#  - name: Merge vlan translation configuration
#    sonic_vlan_mapping:
#      config:
#        - name: Ethernet8
#          mapping:
#          - service_vlan: 2567
#            vlan_translation:
#              match_double_tags:
#                - inner_vlan: 600
#                  outer_vlan: 610
#                - inner_vlan: 601
#                  outer_vlan: 611
#                  priority: 1
#                - inner_vlan: 602
#                  outer_vlan: 612
#                  priority: 2
#      state: merged
#
# After state:
# ------------
#
# sonic# show interface vlan-mappings
# Flags: M - Multi-tag
# ---------------------------------------------------------
# Name            Outer  Inner  Mapped Vlan  Priority Flags
# ---------------------------------------------------------
# Ethernet8       610    600    2567         -        -
# Ethernet8       611    601    2567         1        -
# Ethernet8       612    602    2567         2        -
#
# sonic# show interface vlan-mappings dot1q-tunnel
# --------------------------------------------------------------------
# Name            Vlan                     dot1q-tunnel Vlan  Priority
# --------------------------------------------------------------------
# Ethernet4       360-366,392              2755               3
#
#
# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show interface vlan-mappings dot1q-tunnel
# --------------------------------------------------------------------
# Name            Vlan                     dot1q-tunnel Vlan  Priority
# --------------------------------------------------------------------
# Ethernet4       360-366,392              2755               3
#
#  - name: Replace dot1q_tunnel configuration
#    sonic_vlan_mapping:
#      config:
#        - name: Ethernet4
#          mapping:
#            - service_vlan: 2755
#              dot1q_tunnel:
#                vlan_ids:
#                  - 660-666
#                priority: 6
#      state: replaced
#
# After state:
# ------------
#
# sonic# show interface vlan-mappings dot1q-tunnel
# --------------------------------------------------------------------
# Name            Vlan                     dot1q-tunnel Vlan  Priority
# --------------------------------------------------------------------
# Ethernet4       660-666                  2755               6
#
# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show interface vlan-mappings
# Flags: M - Multi-tag
# ---------------------------------------------------------
# Name            Outer  Inner  Mapped Vlan  Priority Flags
# ---------------------------------------------------------
# Ethernet8       610    600    2567         -        -
# Ethernet8       611    601    2567         1        -
# Ethernet8       612    602    2567         2        -
#
#  - name: Override vlan translation configuration
#    sonic_vlan_mapping:
#      config:
#        - name: Ethernet8
#          mapping:
#          - service_vlan: 2567
#            vlan_translation:
#              match_double_tags:
#                - inner_vlan: 701
#                  outer_vlan: 711
#                  priority: 5
#                - inner_vlan: 702
#                  outer_vlan: 712
#                  priority: 6
#      state: overridden
#
# After state:
# ------------
#
# sonic# show interface vlan-mappings
# Flags: M - Multi-tag
# ---------------------------------------------------------
# Name            Outer  Inner  Mapped Vlan  Priority Flags
# ---------------------------------------------------------
# Ethernet8       711    701    2567         5        -
# Ethernet8       712    702    2567         6        -
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
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.vlan_mapping.vlan_mapping import Vlan_mappingArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.vlan_mapping.vlan_mapping import Vlan_mapping


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Vlan_mappingArgs.argument_spec,
                           supports_check_mode=True)

    result = Vlan_mapping(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
