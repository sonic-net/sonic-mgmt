#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_ptp_default_ds
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_ptp_default_ds
version_added: '3.1.0'
short_description: Manage global PTP configurations on SONiC
description:
  - This module provides configuration management of global PTP
    parameters for devices running SONiC.
  - The device should have timing chip support.
author: 'Pranesh Raagav S (@PraneshRaagavS)'
options:
  config:
    description:
      - Specifies global PTP clock configurations.
    type: dict
    suboptions:
      priority1:
        description:
          - The priority1 attribute of the local clock.
          - The range is from 0 to 255.
        type: int
      priority2:
        description:
          - The priority2 attribute of the local clock.
          - The range is from 0 to 255.
        type: int
      domain_number:
        description:
          - The domain number of the current syntonization domain.
          - The range is from 0 to 127.
        type: int
      log_announce_interval:
        description:
          - The base-2 logarithm of the mean announceInterval (mean time
            interval between successive Announce messages).
        type: int
      announce_receipt_timeout:
        description:
          - The number of announceIntervals that have to pass
            without receipt of an Announce message before the
            occurrence of the event ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES.
        type: int
      log_sync_interval:
        description:
          - The base-2 logarithm of the mean SyncInterval for multicast messages.
        type: int
      log_min_delay_req_interval:
        description:
          - The base-2 logarithm of the minDelayReqInterval.
          - The minimum permitted mean time interval between successive Delay_Req messages.
        type: int
      two_step_flag:
        description:
          - The clockAccuracy indicates the expected accuracy of the clock.
        type: int
      clock_type:
        description:
          - Specifies the type of clock configured in the PTP domain.
        type: str
        choices: ['BC', 'E2E_TC', 'P2P_TC', 'disable']
      network_transport:
        description:
          - The network transport used for communication.
        type: str
        choices: ['L2', 'UDPv4', 'UDPv6']
      unicast_multicast:
        description:
          - Specifies whether the network transport uses unicast or multicast communication.
        type: str
        choices: ['unicast', 'multicast']
      domain_profile:
        description:
          - The method to be used when comparing data sets during the Best Master Clock Algorithm.
        type: str
        choices: ['ieee1588', 'G.8275.1', 'G.8275.2']
      source_interface:
        description:
          - Source interface whose IP to use as source ip for PTP IPv4
            and IPv6 multicast transport mode.
        type: str

  state:
    description:
      - The state of the configuration after module completion.
      - C(merged) - Merges provided PTP configuration with on-device
        configuration.
      - C(replaced) - Replaces on-device PTP configuration with provided
        configuration.
      - C(overridden) - Overrides all on-device PTP configurations with the
        provided configuration.
      - C(deleted) - Deletes on-device PTP configuration.
    type: str
    choices:
      - merged
      - deleted
      - replaced
      - overridden
    default: merged
"""
EXAMPLES = """
# Using deleted
#
# Before State:
# -------------
#
# sonic# show running-configuration ptp
# ptp network-transport l2 multicast
# ptp domain 25
# ptp domain-profile default
# ptp priority1 101
# ptp priority2 91
# ptp log-announce-interval 1
# ptp log-sync-interval -3
# sonic#

- name: Delete specified PTP configurations
  dellemc.enterprise_sonic.sonic_ptp:
    config:
      log-sync-interval: -3
      log-announce-interval: 1
      network-transport: 'L2'
      unicast-multicast: 'multicast'
      priority1: 101
      priority2: 91
      domain-number: 25
    state: deleted

# After State:
# ------------
#
# sonic# show running-configuration ptp
# ptp domain-profile default
# sonic#


# Using deleted
#
# Before State:
# -------------
#
# sonic# show running-configuration ptp
# ptp mode boundary-clock
# ptp network-transport ipv6 unicast
# ptp domain 45
# ptp domain-profile g8275.2
# ptp announce-timeout 3
# sonic#

- name: Delete all PTP configurations
  dellemc.enterprise_sonic.sonic_ptp:
    config:
    state: deleted

# After State:
# ------------
#
# sonic# show running-configuration ptp
# sonic#


# Using merged
#
# Before State:
# -------------
#
# sonic# show running-configuration ptp
# ptp domain 35
# ptp domain-profile default
# ptp priority2 100
# sonic#

- name: Merge provided global PTP configurations
  dellemc.enterprise_sonic.sonic_ptp:
    config:
      domain-profile: 'G.8275.1'
      log-sync-interval: -4
      log-announce-interval: -3
      announce-receipt-timeout: 5
      log-min-delay-req-interval: -4
      clock-type: 'BC'
      network-transport: 'L2'
      unicast-multicast: 'multicast'
    state: merged

# After State:
# ------------
#
# sonic# show running-configuration ptp
# ptp mode boundary-clock
# ptp network-transport l2 multicast
# ptp domain 35
# ptp domain-profile g8275.1
# ptp priority2 100
# ptp log-announce-interval -3
# ptp announce-timeout 5
# ptp log-sync-interval -4
# ptp log-min-delay-req-interval -4
# sonic#


# Using replaced
#
# Before State:
# -------------
#
# sonic# show running-configuration ptp
# ptp network-transport ipv4 unicast
# ptp domain 44
# ptp domain-profile default
# ptp priority1 100
# ptp priority2 90
# ptp log-announce-interval -2
# ptp log-sync-interval -4
# sonic#

- name: Replace global PTP configurations
  dellemc.enterprise_sonic.sonic_ptp:
    config:
      log-sync-interval: -3
      log-announce-interval: 1
      network-transport: 'L2'
      unicast-multicast: 'multicast'
      priority1: 101
      priority2: 91
      domain-number: 25
    state: replaced

# After State:
# ------------
#
# sonic# show running-configuration ptp
# ptp network-transport l2 multicast
# ptp domain 25
# ptp domain-profile default
# ptp priority1 101
# ptp priority2 91
# ptp log-announce-interval 1
# ptp log-sync-interval -3
# sonic#


# Using overridden
#
# Before State:
# -------------
#
# sonic# show running-configuration ptp
# ptp mode boundary-clock
# ptp network-transport l2 multicast
# ptp domain 35
# ptp domain-profile g8275.1
# ptp priority2 100
# ptp log-announce-interval -3
# ptp announce-timeout 5
# ptp log-sync-interval -4
# ptp log-min-delay-req-interval -4
# sonic#

- name: Override device configuration of ptp with provided configuration
  dellemc.enterprise_sonic.sonic_ptp:
    config:
      domain-number: 44
      domain-profile: 'G.8275.2'
      network-transport: 'ipv4'
      unicast-multicast: 'unicast'
    state: overridden

# After State:
# ------------
#
# sonic# show running-configuration ptp
# ptp network-transport ipv4 unicast
# ptp domain 44
# ptp domain-profile g8275.2
# sonic#
"""
RETURN = """
before:
  description: The configuration prior to the model invocation.
  returned: always
  type: dict
after:
  description: The configuration resulting from module invocation.
  returned: when changed
  type: dict
after(generated):
  description: The configuration that would be generated by module invocation in non-check mode.
  returned: when C(check_mode)
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
  type: dict
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ptp_default_ds.ptp_default_ds import Ptp_default_dsArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.ptp_default_ds.ptp_default_ds import Ptp_default_ds


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Ptp_default_dsArgs.argument_spec,
                           supports_check_mode=True)

    result = Ptp_default_ds(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
