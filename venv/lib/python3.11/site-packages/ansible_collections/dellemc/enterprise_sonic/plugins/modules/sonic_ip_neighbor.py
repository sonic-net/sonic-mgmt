#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_ip_neighbor
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_ip_neighbor
version_added: 2.1.0
notes:
  - Supports C(check_mode).
short_description: Manage IP neighbor global configuration on SONiC.
description:
  - This module provides configuration management of IP neighbor global for devices running SONiC.
author: "M. Zhang (@mingjunzhang2019)"
options:
  config:
    description:
      - Specifies IP neighbor global configurations.
    type: dict
    suboptions:
      ipv4_arp_timeout:
        type: int
        description:
          - IPv4 ARP timeout.
          - The range is from 60 to 14400.
      ipv6_nd_cache_expiry:
        type: int
        description:
          - IPv6 ND cache expiry.
          - The range is from 60 to 14400.
      num_local_neigh:
        type: int
        description:
          - The number of reserved local neighbors.
          - The range is from 0 to 32000.
      ipv4_drop_neighbor_aging_time:
        type: int
        description:
          - IPv4 drop neighbor aging time.
          - The range is from 60 to 14400.
      ipv6_drop_neighbor_aging_time:
        type: int
        description:
          - IPv6 drop neighbor aging time.
          - The range is from 60 to 14400.
  state:
    description:
      - The state of the configuration after module completion.
    type: str
    choices:
      - merged
      - replaced
      - overridden
      - deleted
    default: merged
"""

EXAMPLES = """
#
# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration
# !
# ip arp timeout 180
# ip drop-neighbor aging-time 300
# ipv6 drop-neighbor aging-time 300
# ip reserve local-neigh 0
# ipv6 nd cache expire 180
# !
- name: Configure IP neighbor global
  sonic_ip_neighbor:
    config:
      ipv4_arp_timeout: 1200
      ipv4_drop_neighbor_aging_time: 600
      ipv6_drop_neighbor_aging_time: 600
      ipv6_nd_cache_expiry: 1200
      num_local_neigh: 1000
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration
# !
# ip arp timeout 1200
# ip drop-neighbor aging-time 600
# ipv6 drop-neighbor aging-time 600
# ip reserve local-neigh 1000
# ipv6 nd cache expire 1200
# !
#
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration
# !
# ip arp timeout 1200
# ip drop-neighbor aging-time 600
# ipv6 drop-neighbor aging-time 600
# ip reserve local-neigh 1000
# ipv6 nd cache expire 1200
# !
- name: Delete some IP neighbor configuration
  sonic_ip_neighbor:
    config:
      ipv4_arp_timeout: 0
      ipv4_drop_neighbor_aging_time: 0
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration
# !
# ip arp timeout 180
# ip drop-neighbor aging-time 300
# ipv6 drop-neighbor aging-time 600
# ip reserve local-neigh 1000
# ipv6 nd cache expire 1200
# !
#
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration
# !
# ip arp timeout 1200
# ip drop-neighbor aging-time 600
# ipv6 drop-neighbor aging-time 600
# ip reserve local-neigh 1000
# ipv6 nd cache expire 1200
# !
- name: Delete all IP neighbor configuration
  sonic_ip_neighbor:
    config: {}
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration
# !
# ip arp timeout 180
# ip drop-neighbor aging-time 300
# ipv6 drop-neighbor aging-time 300
# ip reserve local-neigh 0
# ipv6 nd cache expire 180
# !
#
# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration
# !
# ip arp timeout 1200
# ip drop-neighbor aging-time 600
# ipv6 drop-neighbor aging-time 300
# ip reserve local-neigh 0
# ipv6 nd cache expire 180
# !
- name: Change some IP neighbor configuration
  sonic_ip_neighbor:
    config:
      ipv6_drop_neighbor_aging_time: 600
      ipv6_nd_cache_expiry: 1200
      num_local_neigh: 1000
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration
# !
# ip arp timeout 1200
# ip drop-neighbor aging-time 600
# ipv6 drop-neighbor aging-time 600
# ip reserve local-neigh 1000
# ipv6 nd cache expire 1200
# !
#
# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show running-configuration
# !
# ip arp timeout 1200
# ip drop-neighbor aging-time 600
# ipv6 drop-neighbor aging-time 300
# ip reserve local-neigh 0
# ipv6 nd cache expire 180
# !
- name: Reset IP neighbor configuration, then configure some
  sonic_ip_neighbor:
    config:
      ipv6_drop_neighbor_aging_time: 600
      ipv6_nd_cache_expiry: 1200
      num_local_neigh: 1000
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration
# !
# ip arp timeout 180
# ip drop-neighbor aging-time 300
# ipv6 drop-neighbor aging-time 600
# ip reserve local-neigh 1000
# ipv6 nd cache expire 1200
# !
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ip_neighbor.ip_neighbor import Ip_neighborArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.ip_neighbor.ip_neighbor import Ip_neighbor


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Ip_neighborArgs.argument_spec,
                           supports_check_mode=True)

    result = Ip_neighbor(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
