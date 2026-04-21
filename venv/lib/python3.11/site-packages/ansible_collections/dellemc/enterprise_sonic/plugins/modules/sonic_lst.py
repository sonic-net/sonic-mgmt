#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved..
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_lst
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_lst
version_added: 3.1.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
short_description: Manage link state tracking (LST) configuration on SONiC
description:
  - This module provides configuration management of LST for devices running SONiC
author: S. Talabi (@stalabi1)
options:
  config:
    description:
      - LST configuration
    type: dict
    suboptions:
      lst_groups:
        description:
          - LST groups configuration
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Name of LST group
            type: str
            required: true
          all_evpn_es_downstream:
            description:
              - Indicates that the LST group tracks all EVPN ethernet segments as downstream interfaces
            type: bool
          all_mclags_downstream:
            description:
              - Indicates that the LST group tracks all MCLAGs as downstream interfaces
            type: bool
          group_description:
            description:
              - Description of LST group
            type: str
          group_type:
            description:
              - LST group type
            type: str
            choices: ['l3']
          threshold_down:
            description:
              - Downstream ports will shut down if the threshold falls below this value
              - Range 0-100
            type: int
          threshold_type:
            description:
              - Type of threshold calculation scheme to use
            type: str
            choices: ['percentage']
          threshold_up:
            description:
              - Downstream ports will go online if the threshold is greater than or equal to this value
              - Range 0-100
            type: int
          timeout:
            description:
              - Time in seconds to wait to bring up the downstream ports after the first upstream port is online
              - Range 1-1800
            type: int
      interfaces:
        description:
          - LST configuration for interfaces
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Name of interface
            type: str
            required: true
          downstream_group:
            description:
              - LST group name used to track the interface as downstream
            type: str
          upstream_groups:
            description:
              - Upstream groups configuration
            type: list
            elements: dict
            suboptions:
              group_name:
                description:
                  - LST group name used to track the interface as upstream
                type: str
                required: true
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
# sonic# show running-configuration link state tracking
# (No link state tracking configuration present)
# sonic# show running-configuration interface Ethernet 20
# !
# interface Ethernet20
# (No link state tracking configuration present for interface Ethernet20)
# sonic# show running-configuration interface Ethernet 24
# !
# interface Ethernet24
# (No link state tracking configuration present for interface Ethernet24)

- name: Merge LST configuration
  dellemc.enterprise_sonic.sonic_lst:
    config:
      lst_groups:
        - name: lst
          all_evpn_es_downstream: true
          group_description: abc
          group_type: l3
          threshold_down: 20
          threshold_type: percentage
          threshold_up: 40
          timeout: 120
      interfaces:
        - name: Ethernet20
          downstream_group: lst
        - name: Ethernet24
          upstream_groups:
            - group_name: lst
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration link state tracking
# !
# link state track lst
#   timeout 120
#   description abc
#   downstream all-evpn-es
#   threshold type percentage up 40 down 20
# sonic# show running-configuration interface Ethernet 20
# !
# interface Ethernet20
#  link state track lst downstream
# sonic# show running-configuration interface Ethernet 24
# !
# interface Ethernet24
#  link state track lst upstream


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration link state tracking
# !
# link state track lst
#   timeout 120
#   description abc
#   downstream all-evpn-es
#   threshold type percentage up 40 down 20
# sonic# show running-configuration interface Ethernet 20
# !
# interface Ethernet20
#  link state track lst downstream
# sonic# show running-configuration interface Ethernet 24
# !
# interface Ethernet24
#  link state track lst upstream

- name: Replace LST configuration
  dellemc.enterprise_sonic.sonic_lst:
    config:
      lst_groups:
        - name: lst
          all_mclags_downstream: true
          timeout: 75
      interfaces:
        - name: Ethernet20
          upstream_groups:
            - group_name: lst
        - name: Ethernet24
          downstream_group: lst
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration link state tracking
# !
# link state track lst
#   timeout 75
#   downstream all-mclag
# sonic# show running-configuration interface Ethernet 20
# !
# interface Ethernet20
#  link state track lst upstream
# sonic# show running-configuration interface Ethernet 24
# !
# interface Ethernet24
#  link state track lst downstream


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show running-configuration link state tracking
# !
# link state track lst
#   timeout 75
#   downstream all-mclag
# sonic# show running-configuration interface Ethernet 20
# !
# interface Ethernet20
#  link state track lst upstream
# sonic# show running-configuration interface Ethernet 24
# !
# interface Ethernet24
#  link state track lst downstream

- name: Override LST configuration
  dellemc.enterprise_sonic.sonic_lst:
    config:
      lst_groups:
        - name: lst2
          all_evpn_es_downstream: true
          group_description: xyz
          group_type: l3
          threshold_down: 30
          threshold_type: percentage
          threshold_up: 50
          timeout: 130
      interfaces:
        - name: Ethernet20
          downstream_group: lst2
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration link state tracking
# !
# link state track lst2
#   timeout 130
#   description xyz
#   downstream all-evpn-es
#   threshold type percentage up 50 down 30
# sonic# show running-configuration interface Ethernet 20
# !
# interface Ethernet20
#  link state track lst2 downstream
# sonic# show running-configuration interface Ethernet 24
# !
# interface Ethernet24
# (No link state configuration present for interface Ethernet24)


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration link state tracking
# !
# link state track lst2
#   timeout 130
#   description xyz
#   downstream all-evpn-es
#   threshold type percentage up 50 down 30
# sonic# show running-configuration interface Ethernet 20
# !
# interface Ethernet20
#  link state track lst2 downstream
# sonic# show running-configuration interface Ethernet 24
# !
# interface Ethernet24
#  link state track lst2 upstream

- name: Delete LST configuration
  dellemc.enterprise_sonic.sonic_lst:
    config:
      lst_groups:
        - name: lst2
          all_evpn_es_downstream: true
          group_description: xyz
          threshold_down: 30
          threshold_type: percentage
          threshold_up: 50
          timeout: 130
      interfaces:
        - name: Ethernet20
          downstream_group: lst2
        - name: Ethernet24
          upstream_groups:
            - group_name: lst2
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration link state tracking
# !
# link state track lst2
# sonic# show running-configuration interface Ethernet 20
# !
# interface Ethernet20
# (No link state configuration present for interface Ethernet20)
# sonic# show running-configuration interface Ethernet 24
# !
# interface Ethernet24
# (No link state configuration present for interface Ethernet24)


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration link state tracking
# !
# link state track lst
#   timeout 120
#   description abc
#   downstream all-evpn-es
#   threshold type percentage up 40 down 20
# sonic# show running-configuration interface Ethernet 20
# !
# interface Ethernet20
#  link state track lst downstream
# sonic# show running-configuration interface Ethernet 24
# !
# interface Ethernet24
#  link state track lst upstream

- name: Delete LST configuration
  dellemc.enterprise_sonic.sonic_lst:
    config: {}
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration link state tracking
# (No link state tracking configuration present)
# sonic# show running-configuration interface Ethernet 20
# !
# interface Ethernet20
# (No link state tracking configuration present for interface Ethernet20)
# sonic# show running-configuration interface Ethernet 24
# !
# interface Ethernet24
# (No link state tracking configuration present for interface Ethernet24)
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
  description: The resulting configuration from module invocation.
  returned: when changed
  type: dict
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
after(generated):
  description: The generated configuration from module invocation.
  returned: when C(check_mode)
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.lst.lst import LstArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.lst.lst import Lst


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=LstArgs.argument_spec,
                           supports_check_mode=True)

    result = Lst(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
