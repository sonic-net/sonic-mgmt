#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_bfd
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_bfd
version_added: "2.1.0"
notes:
  - Tested against Enterprise SONiC Distribution by Dell Technologies.
  - Supports C(check_mode).
short_description: Manage BFD configuration on SONiC
description:
  - This module provides configuration management of BFD for devices running SONiC
author: "S. Talabi (@stalabi1)"
options:
  config:
    description:
      - Specifies BFD configurations
    type: dict
    suboptions:
      profiles:
        description:
          - List of preconfiguration profiles
        type: list
        elements: dict
        suboptions:
          profile_name:
            description:
              - BFD profile name
            type: str
            required: True
          enabled:
            description:
              - Enables BFD session when set to true
            type: bool
            default: True
          transmit_interval:
            description:
              - Specifies peer transmit interval
            type: int
            default: 300
          receive_interval:
            description:
              - Specifies peer receive interval
            type: int
            default: 300
          detect_multiplier:
            description:
              - Number of missed packets to bring down a BFD session
            type: int
            default: 3
          passive_mode:
            description:
              - Specifies BFD peer as passive when set to true
            type: bool
            default: false
          min_ttl:
            description:
              - Minimum expected TTL on received packets
            type: int
            default: 254
          echo_interval:
            description:
              - Specifies echo interval
            type: int
            default: 300
          echo_mode:
            description:
              - Echo mode is enabled when set to true
            type: bool
            default: false
      single_hops:
        description:
          - List of single-hop sessions
        type: list
        elements: dict
        suboptions:
          remote_address:
            description:
              - IP address used by the remote system for the BFD session
            type: str
            required: True
          vrf:
            description:
              - Name of the configured VRF on the device
            type: str
            required: True
          interface:
            description:
              - Interface to use to contact peer
            type: str
            required: True
          local_address:
            description:
              - Source IP address to be used for BFD sessions over the interface
            type: str
            required: True
          enabled:
            description:
              - Enables BFD session when set to true
            type: bool
            default: True
          transmit_interval:
            description:
              - Specifies peer transmit interval
            type: int
            default: 300
          receive_interval:
            description:
              - Specifies peer receive interval
            type: int
            default: 300
          detect_multiplier:
            description:
              - Number of missed packets to bring down a BFD session
            type: int
            default: 3
          passive_mode:
            description:
              - Specifies BFD peer as passive when set to true
            type: bool
            default: false
          echo_interval:
            description:
              - Specifies echo interval
            type: int
            default: 300
          echo_mode:
            description:
              - Echo mode is enabled when set to true
            type: bool
            default: false
          profile_name:
            description:
              - BFD profile name
            type: str
      multi_hops:
        description:
          - List of multi-hop sessions
        type: list
        elements: dict
        suboptions:
          remote_address:
            description:
              - IP address used by the remote system for the BFD session
            type: str
            required: True
          vrf:
            description:
              - Name of the configured VRF on the device
            type: str
            required: True
          local_address:
            description:
              - Source IP address to be used for BFD sessions over the interface
            type: str
            required: True
          enabled:
            description:
              - Enables BFD session when set to true
            type: bool
            default: True
          transmit_interval:
            description:
              - Specifies peer transmit interval
            type: int
            default: 300
          receive_interval:
            description:
              - Specifies peer receive interval
            type: int
            default: 300
          detect_multiplier:
            description:
              - Number of missed packets to bring down a BFD session
            type: int
            default: 3
          passive_mode:
            description:
              - Specifies BFD peer as passive when set to true
            type: bool
            default: false
          min_ttl:
            description:
              - Minimum expected TTL on received packets
            type: int
            default: 254
          profile_name:
            description:
              - BFD profile name
            type: str
  state:
    description:
      - The state of the configuration after module completion.
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
# sonic# show bfd profile
# (No "bfd profile" configuration present)
# sonic# show bfd peers
# (No "bfd peers" configuration present)

- name: Merge BFD configuration
  dellemc.enterprise_sonic.sonic_bfd:
  config:
    profiles:
      - profile_name: 'p1'
        enabled: true
        transmit_interval: 120
        receive_interval: 200
        detect_multiplier: 2
        passive_mode: true
        min_ttl: 140
        echo_interval: 150
        echo_mode: true
    single_hops:
      - remote_address: '196.88.6.1'
        vrf: 'default'
        interface: 'Ethernet20'
        local_address: '1.1.1.1'
        enabled: true
        transmit_interval: 50
        receive_interval: 80
        detect_multiplier: 4
        passive_mode: true
        echo_interval: 110
        echo_mode: true
        profile_name: 'p1'
    multi_hops:
      - remote_address: '192.40.1.3'
        vrf: 'default'
        local_address: '3.3.3.3'
        enabled: true
        transmit_interval: 75
        receive_interval: 100
        detect_multiplier: 3
        passive_mode: true
        min_ttl: 125
        profile_name: 'p1'
  state: merged

# After state:
# ------------
#
# sonic# show bfd profile
# BFD Profile:
#     Profile-name: p1
#         Enabled: True
#         Echo-mode: Enabled
#         Passive-mode: Enabled
#         Minimum-Ttl: 140
#         Detect-multiplier: 2
#         Receive interval: 200ms
#         Transmission interval: 120ms
#         Echo transmission interval: 150ms
# sonic# show bfd peers
# BFD Peers:
#
#     peer 192.40.1.3 multihop local-address 3.3.3.3 vrf default
#         ID: 989720421
#         Remote ID: 0
#         Passive mode: Enabled
#         Profile: p1
#         Minimum TTL: 125
#         Status: down
#         Downtime: 0 day(s), 0 hour(s), 1 min(s), 46 sec(s)
#         Diagnostics: ok
#         Remote diagnostics: ok
#         Peer Type: configured
#         Local timers:
#             Detect-multiplier: 2
#             Receive interval: 100ms
#             Transmission interval: 75ms
#             Echo transmission interval: ms
#         Remote timers:
#             Detect-multiplier: 3
#             Receive interval: 1000ms
#             Transmission interval: 1000ms
#             Echo transmission interval: 0ms
#
#     peer 196.88.6.1 local-address 1.1.1.1 vrf default interface Ethernet20
#         ID: 1134635660
#         Remote ID: 0
#         Passive mode: Enabled
#         Profile: p1
#         Status: down
#         Downtime: 0 day(s), 1 hour(s), 50 min(s), 48 sec(s)
#         Diagnostics: ok
#         Remote diagnostics: ok
#         Peer Type: configured
#         Local timers:
#             Detect-multiplier: 4
#             Receive interval: 80ms
#             Transmission interval: 50ms
#             Echo transmission interval: 110ms
#         Remote timers:
#             Detect-multiplier: 3
#             Receive interval: 1000ms
#             Transmission interval: 1000ms
#             Echo transmission interval: 0ms
#
#
# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show bfd profile
# BFD Profile:
#     Profile-name: p1
#         Enabled: True
#         Echo-mode: Enabled
#         Passive-mode: Enabled
#         Minimum-Ttl: 140
#         Detect-multiplier: 2
#         Receive interval: 200ms
#         Transmission interval: 120ms
#         Echo transmission interval: 150ms
#     Profile-name: p2
#         Enabled: True
#         Echo-mode: Disabled
#         Passive-mode: Disabled
#         Minimum-Ttl: 254
#         Detect-multiplier: 3
#         Receive interval: 300ms
#         Transmission interval: 300ms
#         Echo transmission interval: 300ms

- name: Replace BFD configuration
  dellemc.enterprise_sonic.sonic_bfd:
  config:
    profiles:
      - profile_name: 'p1'
        transmit_interval: 144
      - profile_name: 'p2'
        enabled: false
        transmit_interval: 110
        receive_interval: 235
        detect_multiplier: 5
        passive_mode: true
        min_ttl: 155
        echo_interval: 163
        echo_mode: true
  state: replaced

# After state:
# ------------
#
# sonic# show bfd profile
# BFD Profile:
#     Profile-name: p1
#         Enabled: True
#         Echo-mode: Enabled
#         Passive-mode: Enabled
#         Minimum-Ttl: 140
#         Detect-multiplier: 2
#         Receive interval: 200ms
#         Transmission interval: 144ms
#         Echo transmission interval: 150ms
#     Profile-name: p2
#         Enabled: False
#         Echo-mode: Enabled
#         Passive-mode: Enabled
#         Minimum-Ttl: 155
#         Detect-multiplier: 5
#         Receive interval: 235ms
#         Transmission interval: 110ms
#         Echo transmission interval: 163ms
#
#
# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show bfd peers
# BFD Peers:
#
#     peer 192.40.1.3 multihop local-address 3.3.3.3 vrf default
#         ID: 989720421
#         Remote ID: 0
#         Passive mode: Enabled
#         Profile: p1
#         Minimum TTL: 125
#         Status: down
#         Downtime: 0 day(s), 0 hour(s), 1 min(s), 46 sec(s)
#         Diagnostics: ok
#         Remote diagnostics: ok
#         Peer Type: configured
#         Local timers:
#             Detect-multiplier: 2
#             Receive interval: 100ms
#             Transmission interval: 75ms
#             Echo transmission interval: ms
#         Remote timers:
#             Detect-multiplier: 3
#             Receive interval: 1000ms
#             Transmission interval: 1000ms
#             Echo transmission interval: 0ms
#
#     peer 196.88.6.1 local-address 1.1.1.1 vrf default interface Ethernet20
#         ID: 1134635660
#         Remote ID: 0
#         Passive mode: Enabled
#         Profile: p1
#         Status: down
#         Downtime: 0 day(s), 1 hour(s), 50 min(s), 48 sec(s)
#         Diagnostics: ok
#         Remote diagnostics: ok
#         Peer Type: configured
#         Local timers:
#             Detect-multiplier: 4
#             Receive interval: 80ms
#             Transmission interval: 50ms
#             Echo transmission interval: 110ms
#         Remote timers:
#             Detect-multiplier: 3
#             Receive interval: 1000ms
#             Transmission interval: 1000ms
#             Echo transmission interval: 0ms

- name: Override BFD configuration
  dellemc.enterprise_sonic.sonic_bfd:
  config:
    single_hops:
      - remote_address: '172.68.2.1'
        vrf: 'default'
        interface: 'Ethernet16'
        local_address: '2.2.2.2'
        enabled: true
        transmit_interval: 60
        receive_interval: 88
        detect_multiplier: 6
        passive_mode: true
        echo_interval: 112
        echo_mode: true
        profile_name: 'p3'
    multi_hops:
      - remote_address: '186.42.1.2'
        vrf: 'default'
        local_address: '1.1.1.1'
        enabled: false
        transmit_interval: 85
        receive_interval: 122
        detect_multiplier: 4
        passive_mode: false
        min_ttl: 120
        profile_name: 'p3'
  state: overridden

# After state:
# ------------
#
# sonic# show bfd peers
# BFD Peers:
#
#     peer 186.42.1.2 multihop local-address 1.1.1.1 vrf default
#         ID: 989720421
#         Remote ID: 0
#         Passive mode: Disabled
#         Profile: p3
#         Minimum TTL: 120
#         Status: down
#         Downtime: 0 day(s), 0 hour(s), 1 min(s), 46 sec(s)
#         Diagnostics: ok
#         Remote diagnostics: ok
#         Peer Type: configured
#         Local timers:
#             Detect-multiplier: 4
#             Receive interval: 122ms
#             Transmission interval: 85ms
#             Echo transmission interval: ms
#         Remote timers:
#             Detect-multiplier: 3
#             Receive interval: 1000ms
#             Transmission interval: 1000ms
#             Echo transmission interval: 0ms
#
#     peer 172.68.2.1 local-address 2.2.2.2 vrf default interface Ethernet16
#         ID: 1134635660
#         Remote ID: 0
#         Passive mode: Enabled
#         Profile: p3
#         Status: down
#         Downtime: 0 day(s), 1 hour(s), 50 min(s), 48 sec(s)
#         Diagnostics: ok
#         Remote diagnostics: ok
#         Peer Type: configured
#         Local timers:
#             Detect-multiplier: 6
#             Receive interval: 88ms
#             Transmission interval: 60ms
#             Echo transmission interval: 112ms
#         Remote timers:
#             Detect-multiplier: 3
#             Receive interval: 1000ms
#             Transmission interval: 1000ms
#             Echo transmission interval: 0ms
#
#
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show bfd profile
# BFD Profile:
#     Profile-name: p1
#         Enabled: True
#         Echo-mode: Enabled
#         Passive-mode: Enabled
#         Minimum-Ttl: 140
#         Detect-multiplier: 2
#         Receive interval: 200ms
#         Transmission interval: 120ms
#         Echo transmission interval: 150ms
# sonic# show bfd peers
# BFD Peers:
#
#     peer 192.40.1.3 multihop local-address 3.3.3.3 vrf default
#         ID: 989720421
#         Remote ID: 0
#         Passive mode: Enabled
#         Profile: p1
#         Minimum TTL: 125
#         Status: down
#         Downtime: 0 day(s), 0 hour(s), 1 min(s), 46 sec(s)
#         Diagnostics: ok
#         Remote diagnostics: ok
#         Peer Type: configured
#         Local timers:
#             Detect-multiplier: 2
#             Receive interval: 100ms
#             Transmission interval: 75ms
#             Echo transmission interval: ms
#         Remote timers:
#             Detect-multiplier: 3
#             Receive interval: 1000ms
#             Transmission interval: 1000ms
#             Echo transmission interval: 0ms
#
#     peer 196.88.6.1 local-address 1.1.1.1 vrf default interface Ethernet20
#         ID: 1134635660
#         Remote ID: 0
#         Passive mode: Enabled
#         Profile: p1
#         Status: down
#         Downtime: 0 day(s), 1 hour(s), 50 min(s), 48 sec(s)
#         Diagnostics: ok
#         Remote diagnostics: ok
#         Peer Type: configured
#         Local timers:
#             Detect-multiplier: 4
#             Receive interval: 80ms
#             Transmission interval: 50ms
#             Echo transmission interval: 110ms
#         Remote timers:
#             Detect-multiplier: 3
#             Receive interval: 1000ms
#             Transmission interval: 1000ms
#             Echo transmission interval: 0ms

- name: Delete BFD configuration
  dellemc.enterprise_sonic.sonic_bfd:
  config:
    profiles:
      - profile_name: 'p1'
        enabled: true
        transmit_interval: 120
        receive_interval: 200
        detect_multiplier: 2
        passive_mode: true
        min_ttl: 140
        echo_interval: 150
        echo_mode: true
    single_hops:
      - remote_address: '196.88.6.1'
        vrf: 'default'
        interface: 'Ethernet20'
        local_address: '1.1.1.1'
    multi_hops:
      - remote_address: '192.40.1.3'
        vrf: 'default'
        local_address: '3.3.3.3'
  state: deleted

# After state
# -----------
#
# sonic# show bfd profile
# BFD Profile:
#     Profile-name: p1
#         Enabled: True
#         Echo-mode: Disabled
#         Passive-mode: Disabled
#         Minimum-Ttl: 254
#         Detect-multiplier: 3
#         Receive interval: 300ms
#         Transmission interval: 300ms
#         Echo transmission interval: 300ms
# sonic# show bfd peers
# (No "bfd peers" configuration present)
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.bfd.bfd import BfdArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.bfd.bfd import Bfd


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=BfdArgs.argument_spec,
                           supports_check_mode=True)

    result = Bfd(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
