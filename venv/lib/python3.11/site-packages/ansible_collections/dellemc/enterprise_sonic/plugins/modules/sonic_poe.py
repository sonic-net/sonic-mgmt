#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_poe
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_poe
version_added: "2.5.0"
short_description: Manage PoE configuration on SONiC
description:
  - This module provides configuration management of PoE at global and card level for devices running SONiC
author: "S. Talabi (@stalabi1), Xiao Han (@Xiao_Han2)"
options:
  config:
    description:
      - Specifies PoE configurations
    type: dict
    suboptions:
      global:
        description: configuration for global PoE card
        type: dict
        suboptions:
          power_mgmt_model:
            description:
            - the power management algorithm to use.
            - dynamic means that power consumption of each port is measured and calculated in real-time.
            - static means that power allocated for each port depends on the type of power threshold configured on the port.
            - currently only 'dynamic' and 'class' values are supported
            type: str
            choices: ['dynamic', 'dynamic-priority', 'static', 'static-priority', 'class']
          usage_threshold:
            description:
              - Inline power usage threshold.
              - Range is 0-99 inclusive.
              - currently not supported on platforms.
            type: int
          auto_reset:
            description:
            - enable PoE auto reset mode for global.
            - currently not supported on platforms.
            type: bool
      cards:
        description:
         - PoE card (power controller hardware) configuration.
         - currently not supported on platforms.
        type: list
        elements: dict
        suboptions:
          card_id:
            description:
              - Identifier for the card.
              - must be number in range of 0-7.
            type: int
            required: True
          power_mgmt_model:
            description:
            - the power management algorithm.
            - dynamic means that power consumption of each port is measured and calculated in real-time.
            - static means that power allocated for each port depends on the type of power threshold configured on the port
            type: str
            choices: ['dynamic', 'dynamic-priority', 'static', 'static-priority', 'class']
          usage_threshold:
            description:
              - Inline power usage threshold.
              - Range is 0-99 inclusive
            type: int
          auto_reset:
            description: enable PoE auto reset mode for this card
            type: bool
      interfaces:
        description: PoE configuration for ethernet interfaces
        type: list
        elements: dict
        suboptions:
          name:
            description: Name of the interface
            type: str
            required: True
          enabled:
            description: enable PoE per port
            type: bool
          priority:
            description:
              - PoE port priority in power management algorithm.
              - Priority could be used by a control mechanism
                that prevents over current situations by disconnecting
                ports with lower power priority first.
              - currently only 'low', 'high' and 'critical' values are supported
            type: str
            choices: ['low', 'medium', 'high', 'critical']
          detection:
            description:
              - Device detection mechanism performed by this PSE port.
              - Legacy is capacitive detection scheme, which can be used alone or as a backup if other detection schemes fail.
              - Those schemes are IEEE 802 standard schemes.
              - None cannot be forcibly set by adminstrator.
              - currently only 'dot3bt' and 'dot3bt+legacy' values are supported
            type: str
            choices: ['2pt-dot3af', '2pt-dot3af+legacy', '4pt-dot3af', '4pt-dot3af+legacy', 'dot3bt', 'dot3bt+legacy', 'legacy']
          power_up_mode:
            description:
              - The mode configured for a PSE port to deliver high power.
              - pre-dot3at means that a port is powered in the IEEE 802.3af mode initially, switched to the high-power IEEE 802.3at mode.
              - dot3at means that a port is powered in the IEEE 802.3at mode.
              - dot3bt, type3 and pre-dot3bt are to support 802.3bt interfaces.
              - currently not supported on platforms.
            type: str
            choices: ['dot3af', 'dot3at', 'dot3bt', 'dot3bt-type3', 'dot3bt-type4', 'high-inrush', 'pre-dot3at', 'pre-dot3bt']
          power_pairs:
            description:
              - PoE port power-pairs settings.
              - currently not supported on platforms.
            type: str
            choices: ['signal', 'spare']
          power_limit_type:
            description:
              - Controls the maximum power that a port can deliver.
              - class-based means that the port power limit is as per the dot3af class of the powered device attached.
              - user-defined means limit is specified by config.
              - currently not supported on platforms.
            type: str
            choices: ['class-based', 'user-defined']
          power_limit:
            description:
              - The configured maximum power this port can provide to an attached device measured in Milliwatts.
              - Range is 0-99900 inclusive.
              - currently not supported on platforms.
            type: int
          high_power:
            description:
              - Enables high power mode on a PSE port.
              - currently not supported on platforms.
            type: bool
          disconnect_type:
            description:
            - PoE port disconnect type.
            - currently not supported on platforms.
            type: str
            choices: ['ac', 'dc']
          four_pair:
            description:
              - Enables four pair mode for port.
              - currently not supported on platforms.
            type: bool
          use_spare_pair:
            description:
              - Enables spare pair power for port.
              - currently not supported on platforms.
            type: bool
          power_classification:
            description:
            - PoE power-classification mode for port.
            - currently not supported on platforms.
            type: str
            choices: ['normal', 'bypass']
  state:
    description:
      - The state of the configuration after module completion
    type: str
    choices: ['merged', 'deleted', 'replaced', 'overridden']
    default: merged
"""

EXAMPLES = """
# Using "merged" state to add or change poe global settings
# Before state:
# config:
#   global:
#     auto_reset: false

# Example:
- name: "add poe global settings"
  sonic_poe:
    config:
      global:
        auto_reset: true
        power_mgmt_model: 'class'
        usage_threshold: 300
    state: merged

# After state:
# config:
#   global:
#     auto_reset: true
#     power_mgmt_model: 'class'
#     usage_threshold: 300
# ------

# Using "merged" state to add cards
# Note that platform must support adding multiple cards to do this
# Before state:
# config:
#   global:
#     auto_reset: true

# Example:
- name: "add poe cards"
  sonic_poe:
    config:
      cards:
        - card_id: 0
          usage_threshold: 39
    state: merged

# After state:
# config:
#   global:
#     auto_reset: true
#   cards:
#     - card_id: 0
#       usage_threshold: 39
# ------

# Using "merged" state to add or change card settings
# Before state:
# config:
#   cards:
#     - card_id: 0
#       usage_threshold: 39

# Example:
- name: "add poe cards settings"
  sonic_poe:
    config:
      cards:
        - card_id: 0
          usage_threshold: 60
          power_mgmt_model: dymanic
    state: merged

# After state:
# config:
#   cards:
#     - card_id: 0
#       usage_threshold: 60
#       power_mgmt_model: dymanic
# ------

# Using "merged" state to add interfaces
# Before state:
# config: {}

# Example:
- name: "add poe interfaces"
  sonic_poe:
    config:
      interfaces:
        - name: Ethernet0
          enabled: true
    state: merged

# After state:
# config:
#   interfaces:
#     - name: Ethernet0
#       enabled: true
# ------

# Using "merged" state to add or change interface settings
# Before state:
# config:
#   interfaces:
#     - name: Ethernet0
#       enabled: true
#       disconnect_type: dc

# Example:
- name: "add poe interface settings"
  sonic_poe:
    config:
      interfaces:
        - name: Ethernet0
          four_pair: true
          high_power: true
          detection: dot3bt
          power_classification: normal
          power_limit: 5000
          power_limit_type: class-based
          power_pairs: signal
          power_up_mode: dot3bt
          priority: medium
          use_spare_pair: false
          disconnect_type: ac
    state: merged

# After state:
# config:
#   interfaces:
#     - name: Ethernet0
#       four_pair: true
#       high_power: true
#       detection: dot3bt
#       power_classification: normal
#       power_limit: 5000
#       power_limit_type: class-based
#       power_pairs: signal
#       power_up_mode: dot3bt
#       priority: medium
#       use_spare_pair: false
#       disconnect_type: ac
#       enabled: true
# ------


# Using "deleted" state to remove poe global settings
# Before state:
# config:
#   global:
#     auto_reset: true
#     power_mgmt_model: 'class'
#     usage_threshold: 300

# Example:
- name: "delete matching poe global settings"
  sonic_poe:
    config:
      global:
        auto_reset: false
        usage_threshold: 300
    state: deleted

# After state:
# config:
#   global:
#     power_mgmt_model: 'class'
#     auto_reset: true
# ------

# Using "deleted" state to delete cards or card settings
# Note: to delete whole card, either need just the name or specify all current settings and values
# Before state:
# config:
#   global:
#     auto_reset: true
#   cards:
#     - card_id: 0
#       usage_threshold: 39
#     - card_id: 1
#       auto_reset: true
#       usage_threshold: 60
#       power_mgmt_model: class
#     - card_id: 2
#       usage_threshold: 39
#       power_mgmt_model: dymanic

# Example:
- name: "delete poe cards"
  sonic_poe:
    config:
      cards:
        - card_id: 0
        - card_id: 1
          auto_reset: true
          usage_threshold: 60
          power_mgmt_model: class
        - card_id: 2
          usage_threshold: 39
          power_mgmt_model: static
    state: deleted

# After state:
# config:
#   global:
#     auto_reset: true
#   cards:
#     - card_id: 2
#       power_mgmt_model: dymanic
# ------

# Using "deleted" state to delete interfaces or interface settings
# Note: to delete whole interface, either need just the name or specify all current settings and values
# Before state:
# config:
#   interfaces:
#     - name: Ethernet0
#       enabled: true
#     - name: Ethernet1
#       enabled: false
#       four_pair: true
#     - name: Ethernet2
#       detection: 4pt-dot3af+legacy
#       power_up_mode: dot3bt
#       use_spare_pair: true

# Example:
- name: "delete poe interfaces"
  sonic_poe:
    config:
      interfaces:
        - name: Ethernet0
        - name: Ethernet1
          enabled: false
          four_pair: true
        - name: Ethernet2
          detection: 4pt-dot3af+legacy
          power_up_mode: pre-dot3at
    state: deleted

# After state:
# config:
#   interfaces:
#     - name: Ethernet2
#       power_up_mode: dot3bt
#       use_spare_pair: true
# ------

# Using "deleted" state to clear all interfaces or cards
# Before state:
# config:
#   cards:
#     - card_id: 0
#       usage_threshold: 39
#   interfaces:
#     - name: Ethernet0
#       enabled: true

# Example:
- name: "clear poe interfaces and cards"
  sonic_poe:
    config:
      interfaces: []
      cards: []
    state: deleted

# After state:
# config: {}
# ------

# Using "deleted" state to delete attributes of interfaces or cards
# Before state:
# config:
#   cards:
#     - card_id: 1
#       auto_reset: true
#       usage_threshold: 60
#   interfaces:
#     - name: Ethernet1
#       enabled: false
#       four_pair: true
#       power_classification: normal

# Example:
- name: "clear poe interfaces and cards"
  sonic_poe:
    config:
      interfaces:
        - name: Ethernet1
          four_pair: true
          cards:
            - card_id: 1
              usage_threshold: 60
    state: deleted

# After state:
# config:
#   interfaces:
#     - name: Ethernet1
#       enabled: false
#       power_classification: normal
#   cards:
#     - card_id: 1
#       auto_reset: true
# ------


# Using "overridden" state to set poe config
# Before state:
# config:
#   global:
#     auto_reset: true
#     power_mgmt_model: 'class'
#     usage_threshold: 300
#   interfaces:
#     - name: Ethernet1
#       power_classification: normal
#       enabled: true
#   cards:
#     - card_id: 0
#       usage_threshold: 60
#       power_mgmt_model: dymanic

# Example:
- name: "overridden to exactly specified"
  sonic_poe:
    config:
      global:
        auto_reset: false
      interfaces:
        - name: Ethernet0
          enabled: true
          disconnect_type: ac
        - name: Ethernet1
          power_pairs: signal
    state: overridden

# After state:
# config:
#   global:
#     auto_reset: false
#   interfaces:
#     - name: Ethernet0
#       disconnect_type: ac
#       enabled: true
#     - name: Ethernet1
#       power_pairs: signal
# ------


# Using "replaced" state to replace sections of poe config
# Before state:
# config:
#   global:
#     auto_reset: true
#     power_mgmt_model: 'class'
#     usage_threshold: 300
#   interfaces:
#     - name: Ethernet1
#       power_classification: normal
#       enabled: true
#     - name: Ethernet0
#       enabled: true
#       power_limit_type: class-based
#   cards:
#     - card_id: 0
#       usage_threshold: 60
#       power_mgmt_model: dymanic

# Example:
- name: "replace sections of config to exactly specified"
  sonic_poe:
    config:
      global:
        auto_reset: false
      interfaces:
        - name: Ethernet0
          enabled: true
          disconnect_type: ac
    state: repalced

# After state:
# config:
#   global:
#     auto_reset: false
#   interfaces:
#     - name: Ethernet0
#       disconnect_type: ac
#       enabled: true
#   cards:
#     - card_id: 0
#       usage_threshold: 60
#       power_mgmt_model: dymanic
# ------
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: dict
  sample: >
    The configuration returned will always be in the same format
     as the parameters above.
after:
  description: The resulting configuration after module invocation.
  returned: when changed
  type: dict
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.poe.poe import PoeArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.poe.poe import Poe


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=PoeArgs.argument_spec,
                           supports_check_mode=True)

    result = Poe(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
