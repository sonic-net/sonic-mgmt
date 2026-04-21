#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_sflow
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_sflow
description: This module provides configuration for sflow sampling on devices running SONiC
version_added: "2.5.0"
short_description: configure sflow settings on SONiC
author: "Xiao Han (@Xiao_Han2)"
options:
  config:
    description:
      - Defines configuration and operational state data related to data plane traffic sampling based on sflow.
    type: dict
    suboptions:
      enabled:
        type: bool
        description: Enables or disables sflow sampling for the device.
      polling_interval:
        type: int
        description:
          - sflow polling interval (in seconds).
          - must be 0 or in range 5-300
      max_header_size:
         type: int
         description:
           - sflow maximum header size in bytes.
           - must be in multiple of 128 bytes from 128 to 1024.
      agent:
        type: str
        description: The Agent interface
      sampling_rate:
        type: int
        description:
          - Sets global packet sampling rate.
          - Sample 1 packet for every sampling_rate number of packets flowing through the interface
      collectors:
        description: Configuration data for sflow collectors.
        type: list
        elements: dict
        suboptions:
          address:
            type: str
            description: IP address of the sflow collector.
            required: True
          port:
            type: int
            description: UDP port number for the sflow collector.
            default: 6343
          network_instance:
            type: str
            description: name of the network instance containing the sflow collector
            default: "default"
      interfaces:
        description: Configuration data for sflow data on interfaces.
        type: list
        elements: dict
        suboptions:
          name:
            required: True
            type: str
            description: Name of the interface
          enabled:
            type: bool
            description: If sflow is globally enabled, enables or disables sflow on the interface
          sampling_rate:
            type: int
            description: Override the global sampling rate for this interface
  state:
    description:
    - Specifies the type of configuration update to be performed on the device.
    type: str
    choices:
    - merged
    - replaced
    - overridden
    - deleted
    default: merged
"""

EXAMPLES = """
# Using "deleted" state to clear all configuration
# Before state:
# config:
#   enabled: false
#   polling_interval: 40
#   max_header_size: 256
#   collectors:
#     - address: 1.1.1.1
#       port: 6343
#       network_instance: default
#   interfaces:
#     - name: Ethernet0
#       sampling_rate: 400000

# Example
- name: "clear all sflow config and disable"
  sonic_sflow:
    config: {}
    state: deleted

# After state:
# Note, "enabled" can't be deleted. It's just set to default. All values that can be cleared are deleted.
# config:
#   enabled: false
#   (no other recorded config)
# ------

# Using "deleted" state to clear just the interfaces and collectors
# Before state:
# config:
#   enabled: True
#   polling_interval: 40
#   max_header_size: 256
#   collectors:
#     - address: 1.1.1.1
#       port: 6343
#       network_instance: default
#   interfaces:
#     - name: Ethernet0
#       sampling_rate: 400000

# Example
- name: "clear all sflow interfaces and collectors"
  sonic_sflow:
    config:
      interfaces: []
      collectors: []
    state: deleted

# After state:
# config:
#   enabled: true
#   polling_interval: 40
#   max_header_size: 256
# Note: deletes list of items if empty list is provided. Otherwise must specify key and have values match to delete, see other Example
# ------

# Using "deleted" state to delete individual interfaces
# Before state:
# config:
#   enabled: false
#   polling_interval: 40
#   max_header_size: 256
#   collectors:
#     - address: 1.1.1.1
#       port: 6343
#       network_instance: default
#   interfaces:
#     - name: Ethernet0
#       sampling_rate: 400000
#     - name: Ethernet8
#       enabled: false
#     - name: Ethernet16
#       sampling_rate: 400000

# Example
# note: to delete the whole interface, just the name needs to specify the name, nothing else
- name: "delete individual interfaces"
  sonic_sflow:
    config:
      interfaces:
        - name: Ethernet8
        - name: Ethernet16
  state: deleted

# After state:
# All configuration deleted for the listed interfaces
# config:
#   enabled: false
#   polling_interval: 40
#   max_header_size: 256
#   collectors:
#     - address: 1.1.1.1
#       port: 6343
#       network_instance: default
#   interfaces:
#     - name: Ethernet0
#       sampling_rate: 400000
# ------

# Using "deleted" state to delete collectors
# Before state:
# config:
#   enabled: false
#   polling_interval: 40
#   max_header_size: 256
#   collectors:
#     - address: 1.1.1.1
#       port: 6343
#       network_instance: default
#     - address: 1.1.1.2
#       port: 6000
#       network_instance: "vrf_1"
#   interfaces:
#     - name: Ethernet0
#       sampling_rate: 400000

# Example:
# Note: The values of all three fields must be known to identify a collector, but
# the "port" and "network instance" attributes have default values. These default
# values do not need to be explicitly specified in a playbook for deletion of a
# collector having default values configured for these attributes.
- name: "delete individual collectors"
  sonic_sflow:
    config:
      collectors:
        - address: 1.1.1.2
          port: 6000
          network_instance: "vrf_1"
        - address: 1.1.1.1
    state: deleted

# After state:
# config:
#   enabled: false
#   polling_interval: 40
#   max_header_size: 256
#   interfaces:
#     - name: Ethernet0
#       sampling_rate: 400000
# ------

# Using "deleted" state to clear individual values
# Before state:
# config:
#   enabled: true
#   polling_interval: 30
#   max_header_size: 128
#   sampling_rate: 400000
#   collectors:
#     - address: 1.1.1.1
#       port: 6343
#       network_instance: default
#   interfaces:
#     - name: Ethernet0
#       enabled: true
#       sampling_rate: 400000
#     - name: Ethernet4
#       enabled: true
#       sampling_rate: 400002

# Example
- name: "clear specific config attributes if values match"
  sonic_sflow:
    config:
      enabled: false
      polling_interval: 30
      max_header_size: 128
      sampling_rate: 400000
      interfaces:
        - name: Ethernet0
          sampling_rate: 400000
    state: deleted

# After state:
# config:
#   enabled: true
#   collectors:
#     - address: 1.1.1.1
#       port: 6343
#       network_instance: default
#   interfaces:
#     - name: Ethernet0
#       enabled: true
#     - name: Ethernet4
#       enabled: true
#       sampling_rate: 400002

# ------------


# Using "merged" state to add sflow collector
# Before state:
# config:
#   enabled: false

# Example:
- name: "Add an sflow collector with default values for 'port' and 'network_instance"
  sonic_sflow:
    config:
      collectors:
        - address: 1.1.1.2
    state: merged
# note: There can only be two collectors configured at a time.
# note: Only "port" and and "network_instance" have default values.

# After state:
# config:
#   enabled: false
#   collectors:
#     - address: 1.1.1.2
#       port: 6343
#       network_instance: default
# ------

# Using "merged" state to add and modify interface configuration
# Before state:
# config:
#   enabled: false
#   interfaces:
#     - name: Ethernet0
#       sampling_rate: 400002
#     - name: Ethernet8
#       enabled: true
#       sampling_rate: 400001

# Example
- name: "Add/modify interface settings"
  sonic_sflow:
    config:
      interfaces:
        - name: Ethernet0
          enabled: true
        - name: Ethernet8
          enabled: false
          sampling_rate: 400003
        - name: Ethernet16
        - name: Ethernet32
          sampling_rate: 400001
    state: merged
# Note: must set at least one of enabled or sampling_rate for interface to be added

# After state
# config:
#   enabled: false
#   interfaces:
#     - name: Ethernet0
#       sampling_rate: 400002
#       enabled: true
#     - name: Ethernet8
#       enabled: false
#       sampling_rate: 400003
#     - name: Ethernet32
#       sampling_rate: 400001
# ------

# Using "merged" state to add/modify global settings
# Before state:
# config:
#   enabled: false
#   polling_interval: 40
#   max_header_size: 256

# Example
- name: "Adding/modifying other settings using 'merged'"
  sonic_sflow:
    config:
      polling_interval: 50
      enabled: true
      agent: Ethernet0
      max_header_size: 128
    state: merged

# After state
# config:
#   enabled: true
#   polling_interval: 50
#   max_header_size: 128
#   agent: Ethernet0

# -----------


# using overridden to override all existing sflow config with the given settings
# Before state:
# config:
#   enabled: false
#   polling_interval: 50
#   max_header_size: 128
#   collectors:
#     - address: 1.1.1.1
#       port: 6343
#       network_instance: default
#   interfaces:
#     - name: Ethernet0
#       enabled: false
#     - name: Ethernet8
#       enabled: false
#     - name: Ethernet16
#       enabled: false
#     - name: Ethernet24
#       enabled: false

# Example:
- name: "override all existing sflow config with input config from a playbook task"
  sonic_sflow:
    config:
      enabled: true
      agent: Ethernet0
      interfaces:
        - name: Ethernet0
          enabled: true
    state: overridden

# After state:
# config:
#   enabled: true
#   agent: Ethernet0
#   interfaces:
#     - name: Ethernet0
#       enabled: true
# ------------


# Using "replaced" state to replace specific interface settings
# Before state:
# config:
#   enabled: false
#   polling_interval: 50
#   max_header_size: 128
#   collectors:
#     - address: 1.1.1.1
#       port: 6343
#       network_instance: default
#   interfaces:
#     - name: Ethernet0
#       enabled: true
#       sampling_rate: 400002
#     - name: Ethernet4
#       enabled: false
#     - name: Ethernet8
#       enabled: false
#       sampling_rate: 400010
#     - name: Ethernet24
#       enabled: false

# Example:
- name: "only add or substitute certain interfaces"
  sonic_sflow:
    config:
      enabled: false
      polling_interval: 50
      max_header_size: 128
      interfaces:
        - name: Ethernet0
          sampling_rate: 400010
        - name: Ethernet4
          sampling_rate: 400010
        - name: Ethernet16
          enabled: false
    state: replaced

# After state:
# config:
#   enabled: false
#   polling_interval: 50
#   max_header_size: 128
#   collectors:
#     - address: 1.1.1.1
#       port: 6343
#       network_instance: default
#   interfaces:
#     - name: Ethernet0
#       sampling_rate: 400010
#     - name: Ethernet4
#       sampling_rate: 400010
#     - name: Ethernet8
#       enabled: false
#       sampling_rate: 400010
#     - name: Ethernet16
#       enabled: false
#     - name: Ethernet24
#       enabled: false
# ------

# Using "replaced" state with different top level values replaces nested components.
# Before state:
# config:
#   enabled: false
#   polling_interval: 50
#   max_header_size: 128
#   collectors:
#     - address: 1.1.1.1
#       port: 6343
#       network_instance: default
#   interfaces:
#     - name: Ethernet0
#       enabled: false
#     - name: Ethernet8
#       enabled: false
#     - name: Ethernet16
#       enabled: false
#     - name: Ethernet24
#       enabled: false

# Example:
- name: "replaces everything"
  sonic_sflow:
    config:
      enabled: false
      polling_interval: 30
      max_header_size: 128
    state: replaced

# After state:
# config:
#   enabled: false
#   polling_interval: 30
#   max_header_size: 128
# -----------
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
  description: The resulting configuration module invocation.
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.sflow.sflow import SflowArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.sflow.sflow import Sflow


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=SflowArgs.argument_spec,
                           supports_check_mode=True)

    result = Sflow(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
