#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for iosxr_vrf_global
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: iosxr_vrf_global
short_description: Manages global VRF configuration.
description:
  - This module manages VRF configurations on Cisco IOS-XR devices.
  - It enables playbooks to handle either individual VRFs or the complete VRF collection.
  - It also permits removing non-explicitly stated VRF definitions from the setup.
version_added: 9.0.0
author: Ruchi Pakhle (@Ruchip16)
notes:
  - Tested against Cisco IOS-XR Version 9.0.0
  - This module works with connection C(network_cli).
  - See L(the IOS_XR Platform Options, https://github.com/ansible-collections/cisco.iosxr/blob/main/platform_guide.rst).
  - The module examples uses callback plugin (stdout_callback = yaml) to generate task output in yaml format.
options:
  config:
    description: A dictionary of options for VRF configurations.
    type: list
    elements: dict
    suboptions:
      name:
        description: Name of the VRF.
        type: str
        required: true
      description:
        description: A description for the VRF.
        type: str
      evpn_route_sync:
        description: EVPN Instance VPN ID used to synchronize the VRF route(s).
        type: int
      fallback_vrf:
        description: Fallback VRF name
        type: str
      mhost:
        description: Multicast host stack options
        type: dict
        suboptions:
          afi:
            description: Address Family Identifier (AFI)
            type: str
            choices: ['ipv4', 'ipv6']
          default_interface:
            description: Default interface for multicast.
            type: str
      rd:
        description: VPN Route Distinguisher (RD).
        type: str
      remote_route_filtering:
        description: Enable/Disable remote route filtering per VRF
        type: dict
        suboptions:
          disable:
            description: Disable remote route filtering per VRF
            type: bool
      vpn:
        description: VPN ID for the VRF
        type: dict
        suboptions:
          id:
            description: VPN ID for the VRF.
            type: str
  running_config:
    description:
      - This option is used only with state I(parsed).
      - The value of this option should be the output received from the IOS-XR device by
        executing the command B(show running-config vrf).
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into Ansible structured data as per the resource module's argspec
        and the value is then returned in the I(parsed) key within the result.
    type: str
  state:
    choices: [parsed, gathered, deleted, merged, replaced, rendered, overridden, purged]
    default: merged
    description:
      - The state the configuration should be left in
      - The states I(rendered), I(gathered) and I(parsed) does not perform any change
        on the device.
      - The state I(rendered) will transform the configuration in C(config) option to
        platform specific CLI commands which will be returned in the I(rendered) key
        within the result. For state I(rendered) active connection to remote host is
        not required.
      - The state I(gathered) will fetch the running configuration from device and transform
        it into structured data in the format as per the resource module argspec and
        the value is returned in the I(gathered) key within the result.
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into JSON format as per the resource module parameters and the
        value is returned in the I(parsed) key within the result. The value of C(running_config)
        option should be the same format as the output of command I(show running-config vrf).
        connection to remote host is not required.
      - The state I(purged) removes all the VRF configurations from the
        target device. Use caution with this state.
      - The state I(deleted) only removes the VRF attributes that this module
        manages and does not negate the VRF completely. Thereby, preserving
        address-family related configurations under VRF context.
      - Refer to examples for more details.
    type: str
"""

EXAMPLES = """

# Using merged
#
# Before state:
# -------------
#
# RP/0/0/CPU0:iosxr-02#show running-config vrf
# Fri Feb  9 07:02:35.789 UTC
# !
# vrf test
#

- name: Merge provided configuration with device configuration
  cisco.iosxr.iosxr_vrf_global:
    config:
      - name: VRF4
        description: VRF4 Description
        evpn_route_sync: 793
        fallback_vrf: "test-vrf"
        remote_route_filtering:
          disable: "true"
        rd: "3:4"
        mhost:
          afi: "ipv4"
          default_interface: "Loopback0"
        vpn:
          id: "2:3"
    state: merged

# Task Output:
# ------------
#
# before: []
#
# commands:
# - vrf VRF4
# - description VRF4 Description
# - evpn-route-sync 793
# - fallback-vrf test-vrf
# - mhost ipv4 default-interface Loopback0
# - rd 3:4
# - remote-route-filtering disable
# - vpn id 2:3
#
# after:
# - name: VRF4
#   description: VRF4 Description
#   evpn_route_sync: 793
#   fallback_vrf: "test-vrf"
#   mhost:
#     afi: "ipv4"
#     default_interface: "Loopback0"
#   rd: "3:4"
#   remote_route_filtering:
#     disable: "true"
#   vpn:
#     id: "2:3"
#
# After state:
# ------------
#
# RP/0/0/CPU0:iosxr-02#show running-config vrf
# Sat Feb 20 03:49:43.618 UTC
# vrf VRF4
#  description "VRF4 Description"
#  mhost ipv4 default-interface Loopback0
#  evpn-route-sync 793
#  vpn id 2:3
#  fallback-vrf "test-vrf"
#  remote-route-filtering disable
#  rd "3:4"

# Using replaced
#
# Before state:
# -------------
#
# RP/0/0/CPU0:iosxr-02#show running-config vrf
# Sat Feb 20 03:49:43.618 UTC
# vrf VRF4
#  description "VRF4 Description"
#  mhost ipv4 default-interface Loopback0
#  evpn-route-sync 793
#  vpn id 2:3
#  fallback-vrf "test-vrf"
#  remote-route-filtering disable
#  rd "3:4"

- name: Replace the provided configuration with the existing running configuration
  cisco.iosxr.iosxr_vrf_global:
    config:
      - name: VRF7
        description: VRF7 description
        evpn_route_sync: 398
        fallback_vrf: "replaced-vrf"
        remote_route_filtering:
          disable: "true"
        rd: "67:9"
        mhost:
          afi: "ipv4"
          default_interface: "Loopback0"
        vpn:
          id: "4:5"
    state: replaced

# Task Output:
# ------------
#
# before:
# - name: VRF4
#   description: VRF4 Description
#   evpn_route_sync: 793
#   fallback_vrf: "test-vrf"
#   mhost:
#     afi: "ipv4"
#     default_interface: "Loopback0"
#   rd: "3:4"
#   remote_route_filtering:
#     disable: "true"
#   vpn:
#     id: "2:3"
#
# commands:
# - vrf VRF4
# - no vpn id 2:3
# - vrf VRF7
# - description VRF7 description
# - evpn-route-sync 398
# - fallback-vrf replaced-vrf
# - mhost ipv4 default-interface Loopback0
# - rd 6:9
# - remote-route-filtering disable
# - vpn id 4:5
#
# after:
#   - name: VRF4
#     description: VRF4 Description
#     evpn_route_sync: 793
#     fallback_vrf: "test-vrf"
#     mhost:
#       afi: "ipv4"
#       default_interface: "Loopback0"
#     rd: "3:4"
#     remote_route_filtering:
#       disable: "true"
#   - name: VRF7
#     description: VRF7 description
#     evpn_route_sync: 398
#     fallback_vrf: "replaced-vrf"
#     remote_route_filtering:
#       disable: true
#     rd: "67:9"
#     mhost:
#       afi: "ipv4"
#       default_interface: "Loopback0"
#     vpn:
#       id: "4:5"
#
# After state:
# ------------
#
# RP/0/RP0/CPU0:ios(config)#show running-config vrf
# Sun Mar 10 16:48:53.204 UTC
# vrf VRF4
#  mhost ipv4 default-interface Loopback0
#  evpn-route-sync 793
#  description VRF4 Description
#  fallback-vrf test-vrf
#  remote-route-filtering disable
#  rd 3:4
# !
# vrf VRF7
#  mhost ipv4 default-interface Loopback0
#  evpn-route-sync 398
#  description VRF7 description
#  vpn id 4:5
#  fallback-vrf replaced-vrf
#  remote-route-filtering disable
#  rd 67:9
#  !
# !

# Using overridden
#
# Before state:
# -------------
#
# RP/0/RP0/CPU0:ios(config)#show running-config vrf
# Sun Mar 10 16:48:53.204 UTC
# vrf VRF4
#  mhost ipv4 default-interface Loopback0
#  evpn-route-sync 793
#  description VRF4 Description
#  fallback-vrf test-vrf
#  remote-route-filtering disable
#  rd 3:4
#  !
# !
# vrf VRF7
#  mhost ipv4 default-interface Loopback0
#  evpn-route-sync 398
#  description VRF7 description
#  vpn id 4:5
#  fallback-vrf replaced-vrf
#  remote-route-filtering disable
#  rd 67:9
#  !
# !

- name: Override the provided configuration with the existing running configuration
  cisco.iosxr.iosxr_vrf_global:
    state: overridden
    config:
      - name: VRF6
        description: VRF6 Description
        evpn_route_sync: 101
        fallback_vrf: "overridden-vrf"
        remote_route_filtering:
          disable: "true"
        rd: "9:8"
        mhost:
          afi: "ipv4"
          default_interface: "Loopback0"
        vpn:
          id: "23:3"

# Task Output:
# ------------
#
# before:
# - name: VRF4
#   description: VRF4 Description
#   evpn_route_sync: 793
#   fallback_vrf: "test-vrf"
#   mhost:
#     afi: "ipv4"
#     default_interface: "Loopback0"
#   rd: "3:4"
#   remote_route_filtering:
#     disable: "true"
# - name: VRF7
#   description: VRF7 description
#   evpn_route_sync: 398
#   fallback_vrf: "replaced-vrf"
#   remote_route_filtering:
#     disable: true
#   rd: "67:9"
#   mhost:
#     afi: "ipv4"
#     default_interface: "Loopback0"
#   vpn:
#     id: "4:5"
#
# commands:
# - vrf VRF4
# - no description VRF4 Description
# - no evpn-route-sync 793
# - no fallback-vrf test-vrf
# - no mhost ipv4 default-interface Loopback0
# - no rd 3:4
# - no remote-route-filtering disable
# - vrf VRF7
# - no description VRF7 description
# - no evpn-route-sync 398
# - no fallback-vrf replaced-vrf
# - no mhost ipv4 default-interface Loopback0
# - no rd 67:9
# - no remote-route-filtering disable
# - no vpn id 4:5
# - vrf VRF6
# - description VRF6 Description
# - evpn-route-sync 101
# - fallback-vrf overridden-vrf
# - mhost ipv4 default-interface Loopback0
# - rd 9:8
# - remote-route-filtering disable
# - vpn id 23:3
#
# after:
# - name: VRF4
# - name: VRF6
#   description: VRF6 Description
#   evpn_route_sync: 101
#   fallback_vrf: "overridden-vrf"
#   remote_route_filtering:
#     disable: "true"
#   rd: "9:8"
#   mhost:
#     afi: "ipv4"
#     default_interface: "Loopback0"
#   vpn:
#     id: "23:3"
# - name: VRF7
#
# After state:
# -------------
# RP/0/RP0/CPU0:ios(config)#show running-config vrf
# Sun Mar 10 16:54:53.007 UTC
# vrf VRF4
# vrf VRF6
#  mhost ipv4 default-interface Loopback0
#  evpn-route-sync 101
#  description VRF6 Description
#  vpn id 23:3
#  fallback-vrf overridden-vrf
#  remote-route-filtering disable
#  rd 9:8
# vrf VRF7

# Using deleted
#
# Before state:
# -------------
#
# RP/0/RP0/CPU0:ios(config)#show running-config vrf
# Sun Mar 10 16:54:53.007 UTC
# vrf VRF4
# vrf VRF6
#  mhost ipv4 default-interface Loopback0
#  evpn-route-sync 101
#  description VRF6 Description
#  vpn id 23:3
#  fallback-vrf overridden-vrf
#  remote-route-filtering disable
#  rd 9:8
# vrf VRF7

- name: Delete the provided configuration
  cisco.iosxr.iosxr_vrf_global:
    config:
    state: deleted

# Task Output:
# ------------
#
# before:
# - name: VRF4
# - name: VRF6
#   description: VRF6 Description
#   evpn_route_sync: 101
#   fallback_vrf: "overridden-vrf"
#   remote_route_filtering:
#     disable: "true"
#   rd: "9:8"
#   mhost:
#     afi: "ipv4"
#     default_interface: "Loopback0"
#   vpn:
#     id: "23:3"
# - name: VRF7

# commands:
# - vrf VRF4
# - vrf VRF6
# - no description VRF6 Description
# - no evpn-route-sync 101
# - no fallback-vrf overridden-vrf
# - no mhost ipv4 default-interface Loopback0
# - no rd 9:8
# - no remote-route-filtering disable
# - no vpn id 23:3
# - vrf VRF7
#
# after:
# - name: VRF4
# - name: VRF6
# - name: VRF7
#
# After state:
# ------------
#
# RP/0/RP0/CPU0:ios(config)#show running-config vrf
# Sun Mar 10 17:02:38.981 UTC
# vrf VRF4
# vrf VRF6
# vrf VRF7

# Using purged
#
# Before state:
# -------------
#
# RP/0/RP0/CPU0:ios(config)#show running-config vrf
# vrf VRF4
# vrf VRF6
# vrf VRF7

- name: Purge all the configuration from the device
  cisco.iosxr.iosxr_vrf_global:
    state: purged

# Task Output:
# ------------
#
# before:
# - name: VRF4
# - name: VRF6
# - name: VRF7
#
# commands:
# - no vrf VRF4
# - no vrf VRF6
# - no vrf VRF7
#
# after: []
#
# After state:
# -------------
# RP/0/RP0/CPU0:ios(config)#show running-config vrf
# Sun Mar 10 17:02:38.981 UTC
# -

# Using rendered
#
- name: Render provided configuration with device configuration
  cisco.iosxr.iosxr_vrf_global:
    config:
      - name: VRF4
        description: VRF4 Description
        evpn_route_sync: 793
        fallback_vrf: "test-vrf"
        remote_route_filtering:
          disable: "true"
        rd: "3:4"
        mhost:
          afi: "ipv4"
          default_interface: "Loopback0"
        vpn:
          id: "2:3"
    state: rendered

# Task Output:
# ------------
#
# rendered:
# - vrf VRF4
# - description VRF4 Description
# - evpn-route-sync 793
# - fallback-vrf test-vrf
# - mhost ipv4 default-interface Loopback0
# - rd 3:4
# - remote-route-filtering disable
# - vpn id 2:3

# Using gathered
#
# Before state:
# -------------
#
# RP/0/RP0/CPU0:ios(config)#show running-config vrf
# Sun Mar 10 17:02:38.981 UTC
# vrf VRF4
#  description "VRF4 Description"
#  mhost ipv4 default-interface Loopback0
#  evpn-route-sync 793
#  vpn id 2:3
#  fallback-vrf "test-vrf"
#  remote-route-filtering disable
#  rd "3:4"

- name: Gather existing running configuration
  cisco.iosxr.iosxr_vrf_global:
    state: gathered

# Task Output:
# ------------
#
# gathered:
# - name: VRF4
#   description: VRF4 Description
#   evpn_route_sync: 793
#   fallback_vrf: "test-vrf"
#   mhost:
#     afi: "ipv4"
#     default_interface: "Loopback0"
#   rd: "3:4"
#   remote_route_filtering:
#     disable: "true"
#   vpn:
#     id: "2:3"

# Using parsed
#
# File: parsed.cfg
# ----------------
#
# vrf test
#  description "This is test VRF"
#  mhost ipv4 default-interface Loopback0
#  evpn-route-sync 456
#  vpn id 56
#  fallback-vrf "test-vrf"
#  remote-route-filtering disable
#  rd "testing"
#  !
# !
# vrf my_vrf
#  mhost ipv4 default-interface Loopback0
#  evpn-route-sync 235
#  description "this is sample vrf for feature testing"
#  fallback-vrf "parsed-vrf"
#  rd "2:3"
#  remote-route-filtering disable
#  vpn id 23
#  !
# !

- name: Parse the provided configuration
  cisco.iosxr.iosxr_vrf_global:
    running_config: "{{ lookup('file', 'parsed.cfg') }}"
    state: parsed

# Task Output:
# ------------
#
# parsed:
# - description: This is test VRF
#   evpn_route_sync: 456
#   fallback_vrf: test-vrf
#   mhost:
#     afi: ipv4
#     default_interface: Loopback0
#   name: test
#   rd: testing
#   remote_route_filtering:
#     disable: true
#   vpn:
#     id: '56'
# - description: this is sample vrf for feature testing
#   evpn_route_sync: 235
#   fallback_vrf: parsed-vrf
#   mhost:
#     afi: ipv4
#     default_interface: Loopback0
#   name: my_vrf
#   rd: '2:3'
#   remote_route_filtering:
#     disable: true
#   vpn:
#     id: '23'
"""

RETURN = """
before:
  description: The configuration prior to the model invocation.
  returned: always
  type: dict
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
after:
  description: The resulting configuration model invocation.
  returned: when changed
  type: dict
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample:
  - vrf VRF7
  - description VRF7 description
  - rd: 67:9
  - fallback-vrf replaced-vrf
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
  - vrf VRF4
  - description VRF4 Description
  - evpn-route-sync 793
  - fallback-vrf parsed-vrf
gathered:
  description: Facts about the network resource gathered from the remote device as structured data.
  returned: when I(state) is C(gathered)
  type: list
  sample: >
    This output will always be in the same format as the
    module argspec.
parsed:
  description: The device native config provided in I(running_config) option parsed into structured data as per module argspec.
  returned: when I(state) is C(parsed)
  type: list
  sample: >
    This output will always be in the same format as the
    module argspec.
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.vrf_global.vrf_global import (
    Vrf_globalArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.config.vrf_global.vrf_global import (
    Vrf_global,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=Vrf_globalArgs.argument_spec,
        mutually_exclusive=[["config", "running_config"]],
        required_if=[
            ["state", "merged", ["config"]],
            ["state", "replaced", ["config"]],
            ["state", "overridden", ["config"]],
            ["state", "rendered", ["config"]],
            ["state", "parsed", ["running_config"]],
        ],
        supports_check_mode=True,
    )

    result = Vrf_global(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
