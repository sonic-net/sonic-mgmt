#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for iosxr_vrf_address_family
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: iosxr_vrf_address_family
short_description: Resource module to configure VRF Address family.
description:
  - This module configures and manages the attributes of VRF address family on Cisco IOS-XR devices.
version_added: 10.0.0
author: Ruchi Pakhle (@Ruchip16)
notes:
  - Tested against Cisco IOSXR Version 10.0.0
  - This module works with connection C(network_cli). See L(the IOS_XR Platform Options,../network/user_guide/platform_iosxr.html)
  - For more information on using Ansible to manage network devices see the :ref:`Ansible Network Guide <network_guide>`
  - For more information on using Ansible to manage Cisco devices see the `Cisco integration page <https://www.ansible.com/integrations/networks/cisco>`.
options:
  config:
    description: VRF address family configuration.
    type: list
    elements: dict
    suboptions:
      name:
        description: Name of the VRF.
        type: str
        required: true
      address_families:
        description: Enable address family and enter its config mode - AFI/SAFI configuration
        type: list
        elements: dict
        suboptions:
          afi:
            description: Address Family Identifier (AFI)
            type: str
            choices: ['ipv4', 'ipv6']
          safi:
            description: Address Family modifier
            type: str
            choices: [ 'flowspec', 'multicast', 'unicast']
          export:
            description: VRF export
            type: dict
            suboptions:
              route_policy: &route_policy
                description: Use route_policy for export
                type: str
              route_target: &route_target
                description: Specify export route target extended communities.
                type: str
              to:
                description: Export routes to a VRF
                type: dict
                suboptions:
                  default_vrf: &default_vrf
                    description: Export routes to default VRF
                    type: dict
                    suboptions:
                      route_policy: *route_policy
                  vrf:
                    description: Export routes to a VRF
                    type: dict
                    suboptions:
                      allow_imported_vpn:
                        description: Allow export of imported VPN routes to non-default VRF
                        type: bool
          import_config:
            description: VRF import
            type: dict
            suboptions:
              route_policy: *route_policy
              route_target: *route_target
              from_config:
                description: Import routes from a VRF
                type: dict
                suboptions:
                  bridge_domain:
                    description: VRF import
                    type: dict
                    suboptions:
                      advertise_as_vpn: &advertise_as_vpn
                        description: Advertise local EVPN imported routes to PEs
                        type: bool
                  default_vrf: *default_vrf
                  vrf:
                    description: Import routes from a VRF
                    type: dict
                    suboptions:
                      advertise_as_vpn: *advertise_as_vpn
          maximum:
            description: Set maximum prefix limit
            type: dict
            suboptions:
              prefix:
                description:  Set table's maximum prefix limit.
                type: int
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
    choices: [parsed, gathered, deleted, merged, replaced, rendered, overridden]
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
    type: str
"""

EXAMPLES = """

# Using merged
#
# Before state:
# -------------
#
# RP/0/0/CPU0:iosxr#show running-config vrf
# vrf test
#

- name: Merge provided configuration with device configuration
  cisco.iosxr.iosxr_vrf_address_family:
    config:
      - name: VRF4
        address_families:
          - afi: "ipv4"
            safi: "unicast"
            export:
              route_target: "192.0.2.1:400"
              route_policy: "rm-policy"
              to:
                default_vrf:
                  route_policy: "rm-policy"
                vrf:
                  allow_imported_vpn: true
            import_config:
              route_target: "192.0.2.6:200"
              route_policy: "test-policy"
              from_config:
                bridge_domain:
                  advertise_as_vpn: true
                default_vrf:
                  route_policy: "test-policy"
                vrf:
                  advertise_as_vpn: true
            maximum:
              prefix: 100
    state: merged

# Task Output:
# ------------
#
# before: []
#
# commands:
# - vrf VRF4
# - address-family ipv4 unicast
# - export route-policy rm-policy
# - export route-target 192.0.2.1:400
# - export to default-vrf route-policy rm-policy
# - export to vrf allow-imported-vpn
# - import route-target 192.0.2.6:200
# - import route-policy test-policy
# - import from bridge-domain advertise-as-vpn
# - import from default-vrf route-policy test-policy
# - import from vrf advertise-as-vpn
# - maximum prefix 100
#
# after:
# - name: VRF4
#   address_families:
#     - afi: "ipv4"
#       safi: "unicast"
#       export:
#         route_target: "192.0.2.1:400"
#         route_policy: "rm-policy"
#         to:
#           default_vrf:
#             route_policy: "rm-policy"
#           vrf:
#             allow_imported_vpn: true
#       import_config:
#         route_target: "192.0.2.6:200"
#         route_policy: "test-policy"
#         from_config:
#           bridge_domain:
#             advertise_as_vpn: true
#           default_vrf:
#             route_policy: "test-policy"
#           vrf:
#             advertise_as_vpn: true
#       maximum:
#         prefix: 100
#
# After state:
# ------------
#
# RP/0/0/CPU0:iosxr#show running-config vrf
# vrf VRF4
#  address-family ipv4 unicast
#   export route-policy rm-policy
#   export route-target 192.0.2.1:400
#   export to default-vrf route-policy rm-policy
#   export to vrf allow-imported-vpn
#   import route-target 192.0.2.6:200
#   import route-policy test-policy
#   import from bridge-domain advertise-as-vpn
#   import from default-vrf route-policy test-policy
#   import from vrf advertise-as-vpn
#   maximum prefix 100

# Using replaced
#
# Before state:
# -------------
#
# RP/0/0/CPU0:iosxr#show running-config vrf
# vrf VRF4
#  address-family ipv4 unicast
#   export route-policy rm-policy
#   export route-target 192.0.2.1:400
#   export to default-vrf route-policy rm-policy
#   export to vrf allow-imported-vpn
#   import route-target 192.0.2.6:200
#   import route-policy test-policy
#   import from bridge-domain advertise-as-vpn
#   import from default-vrf route-policy test-policy
#   import from vrf advertise-as-vpn
#   maximum prefix 100

- name: Replace the provided configuration with the existing running configuration
  cisco.iosxr.iosxr_vrf_address_family:
    config:
      - name: VRF7
        address_families:
          - afi: "ipv4"
            safi: "unicast"
            export:
              route_target: "192.0.2.2:400"
              route_policy: "rm-policy"
              to:
                default_vrf:
                  route_policy: "rm-policy"
                vrf:
                  allow_imported_vpn: true
            import_config:
              route_target: "192.0.2.4:400"
              route_policy: "test-policy"
              from_config:
                bridge_domain:
                  advertise_as_vpn: true
                default_vrf:
                  route_policy: "test-policy"
                vrf:
                  advertise_as_vpn: true
            maximum:
              prefix: 200
    state: replaced

# Task Output:
# ------------
#
# - name: VRF4
#   address_families:
#     - afi: "ipv4"
#       safi: "unicast"
#       export:
#         route_target: "192.0.2.1:400"
#         route_policy: "rm-policy"
#         to:
#           default_vrf:
#             route_policy: "rm-policy"
#           vrf:
#             allow_imported_vpn: true
#       import_config:
#         route_target: "192.0.2.6:200"
#         route_policy: "test-policy"
#         from_config:
#           bridge_domain:
#             advertise_as_vpn: true
#           default_vrf:
#             route_policy: "test-policy"
#           vrf:
#             advertise_as_vpn: true
#       maximum:
#         prefix: 100
#
# commands:
# - vrf VRF7
# - address-family ipv4 unicast
# - export route-policy rm-policy
# - export route-target 192.0.2.2:400
# - export to default-vrf route-policy rm-policy
# - export to vrf allow-imported-vpn
# - import route-target 192.0.2.4:400
# - import route-policy test-policy
# - import from bridge-domain advertise-as-vpn
# - import from default-vrf route-policy test-policy
# - import from vrf advertise-as-vpn
# - maximum prefix 200
#
# after:
# - name: VRF7
#   address_families:
#     - afi: "ipv4"
#       safi: "unicast"
#       export:
#         route_target: "192.0.2.2:400"
#         route_policy: "rm-policy"
#         to:
#           default_vrf:
#             route_policy: "rm-policy"
#           vrf:
#             allow_imported_vpn: true
#       import_config:
#         route_target: "192.0.2.4:400"
#         route_policy: "test-policy"
#         from_config:
#           bridge_domain:
#             advertise_as_vpn: true
#           default_vrf:
#             route_policy: "test-policy"
#           vrf:
#             advertise_as_vpn: true
#       maximum:
#         prefix: 200
#
# After state:
# ------------
#
# RP/0/RP0/CPU0:iosxr(config)#show running-config vrf
# vrf VRF7
#  address-family ipv4 unicast
#   import route-policy test-policy
#   import from bridge-domain advertise-as-vpn
#   import from default-vrf route-policy test-policy
#   import from vrf advertise-as-vpn
#   import route-target
#    192.0.2.4:400
#   !
#   export route-policy rm-policy
#   export to vrf allow-imported-vpn
#   export to default-vrf route-policy rm-policy
#   export route-target
#    192.0.2.2:400
#   !
#   maximum prefix 200

# Using overridden
#
# Before state:
# -------------
#
# RP/0/RP0/CPU0:iosxr(config)#show running-config vrf
# vrf VRF7
#  address-family ipv4 unicast
#   import route-policy test-policy
#   import from bridge-domain advertise-as-vpn
#   import from default-vrf route-policy test-policy
#   import from vrf advertise-as-vpn
#   import route-target
#    192.0.2.4:400
#   !
#   export route-policy rm-policy
#   export to vrf allow-imported-vpn
#   export to default-vrf route-policy rm-policy
#   export route-target
#    192.0.2.2:400
#   !
#   maximum prefix 200

- name: Override the provided configuration with the existing running configuration
  cisco.iosxr.iosxr_vrf_address_family:
    state: overridden
    config:
      - name: VRF6
        address_families:
          - afi: "ipv4"
            safi: "unicast"
            export:
              route_target: "192.0.2.8:200"
              route_policy: "rm-policy1"
              to:
                default_vrf:
                  route_policy: "rm-policy"
                vrf:
                  allow_imported_vpn: "true"
            import_config:
              route_target: "192.0.2.2:200"
              route_policy: "test-policy"
              from_config:
                bridge_domain:
                  advertise_as_vpn: "true"
                default_vrf:
                  route_policy: "test-policy"
                vrf:
                  advertise_as_vpn: "true"
            maximum:
              prefix: 500
# Task Output:
# ------------
#
# before:
# - name: VRF7
#   address_families:
#     - afi: "ipv4"
#       safi: "unicast"
#       export:
#         route_target: "192.0.2.2:400"
#         route_policy: "rm-policy"
#         to:
#           default_vrf:
#             route_policy: "rm-policy"
#           vrf:
#             allow_imported_vpn: true
#       import_config:
#         route_target: "192.0.2.4:400"
#         route_policy: "test-policy"
#         from_config:
#           bridge_domain:
#             advertise_as_vpn: true
#           default_vrf:
#             route_policy: "test-policy"
#           vrf:
#             advertise_as_vpn: true
#       maximum:
#         prefix: 200
#
# commands:
# - vrf VRF7
# - address-family ipv4 unicast
# - no import route-policy test-policy
# - no import from bridge-domain advertise-as-vpn
# - no import from default-vrf route-policy test-policy
# - no import from vrf advertise-as-vpn
# - no import route-target 192.0.2.4:400
# - no export route-policy rm-policy
# - no export route-target 192.0.2.2:400
# - no export to default-vrf route-policy rm-policy
# - no export to vrf allow-imported-vpn
# - no maximum prefix 200
# - vrf VRF6
# - address-family ipv4 unicast
# - export route-policy rm-policy1
# - export route-target 192.0.2.8:200
# - export to default-vrf route-policy rm-policy
# - export to vrf allow-imported-vpn
# - import route-target 192.0.2.2:200
# - import route-policy test-policy
# - import from bridge-domain advertise-as-vpn
# - import from default-vrf route-policy test-policy
# - import from vrf advertise-as-vpn
# - maximum prefix 500
#
# after:
# - name: VRF4
# - name: VRF6
#   address_families:
#     - afi: "ipv4"
#       safi: "unicast"
#       export:
#         route_target: "192.0.2.8:200"
#         route_policy: "rm-policy1"
#         to:
#           default_vrf:
#             route_policy: "rm-policy"
#           vrf:
#             allow_imported_vpn: "true"
#       import_config:
#         route_target: "192.0.2.2:200"
#         route_policy: "test-policy"
#         from_config:
#           bridge_domain:
#             advertise_as_vpn: "true"
#           default_vrf:
#             route_policy: "test-policy"
#           vrf:
#             advertise_as_vpn: "true"
#       maximum:
#         prefix: 500
# - name: VRF7
#
# After state:
# -------------
# RP/0/RP0/CPU0:iosxr(config)#show running-config vrf
# vrf VRF4
# vrf VRF6
#  address-family ipv4 unicast
#   import route-policy test-policy
#   import from bridge-domain advertise-as-vpn
#   import from default-vrf route-policy test-policy
#   import from vrf advertise-as-vpn
#   import route-target
#    192.0.2.2:200
#   export route-policy rm-policy1
#   export to vrf allow-imported-vpn
#   export to default-vrf route-policy rm-policy
#   export route-target
#    192.0.2.8:200
#   maximum prefix 500
# vrf VRF7

# Using deleted
#
# Before state:
# -------------
#
# RP/0/RP0/CPU0:iosxr(config)#show running-config vrf
# vrf VRF4
# vrf VRF6
#  address-family ipv4 unicast
#   import route-policy test-policy
#   import from bridge-domain advertise-as-vpn
#   import from default-vrf route-policy test-policy
#   import from vrf advertise-as-vpn
#   import route-target
#    192.0.2.2:200
#   export route-policy rm-policy1
#   export to vrf allow-imported-vpn
#   export to default-vrf route-policy rm-policy
#   export route-target
#    192.0.2.8:200
#   maximum prefix 500
# vrf VRF7

- name: Delete the provided configuration
  cisco.iosxr.iosxr_vrf_address_family:
    config:
    state: deleted

# Task Output:
# ------------
#
# before:
# - name: VRF4
# - name: VRF6
#   address_families:
#     - afi: "ipv4"
#       safi: "unicast"
#       export:
#         route_target: "192.0.2.8:200"
#         route_policy: "rm-policy1"
#         to:
#           default_vrf:
#             route_policy: "rm-policy"
#           vrf:
#             allow_imported_vpn: "true"
#       import_config:
#         route_target: "192.0.2.2:200"
#         route_policy: "test-policy"
#         from_config:
#           bridge_domain:
#             advertise_as_vpn: "true"
#           default_vrf:
#             route_policy: "test-policy"
#           vrf:
#             advertise_as_vpn: "true"
#       maximum:
#         prefix: 500
# - name: VRF7

# commands:
# - vrf VRF4
# - vrf VRF6
# - no address-family ipv4 unicast
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
# RP/0/RP0/CPU0:iosxr(config)#show running-config vrf
# vrf VRF4
# vrf VRF6
# vrf VRF7

# Using rendered
#
- name: Render provided configuration with device configuration
  cisco.iosxr.iosxr_vrf_address_family:
    config:
      - name: VRF4
        address_families:
          - afi: "ipv4"
            safi: "unicast"
            export:
              route_target: "192.0.2.1:400"
              route_policy: "rm-policy"
              to:
                default_vrf:
                  route_policy: "rm-policy"
                vrf:
                  allow_imported_vpn: true
            import_config:
              route_target: "192.0.2.6:200"
              route_policy: "test-policy"
              from_config:
                bridge_domain:
                  advertise_as_vpn: true
                default_vrf:
                  route_policy: "test-policy"
                vrf:
                  advertise_as_vpn: true
            maximum:
              prefix: 100
    state: rendered

# Task Output:
# ------------
#
# rendered:
# - vrf VRF4
# - address-family ipv4 unicast
# - export route-policy rm-policy
# - export route-target 192.0.2.1:400
# - export to default-vrf route-policy rm-policy
# - export to vrf allow-imported-vpn
# - import route-target 192.0.2.6:200
# - import route-policy test-policy
# - import from bridge-domain advertise-as-vpn
# - import from default-vrf route-policy test-policy
# - import from vrf advertise-as-vpn
# - maximum prefix 100

# Using gathered
#
# Before state:
# -------------
#
# RP/0/RP0/CPU0:iosxr(config)#show running-config vrf
# vrf VRF4
#  address-family ipv4 unicast
#   export route-policy rm-policy
#   export route-target 192.0.2.1:400
#   export to default-vrf route-policy rm-policy
#   export to vrf allow-imported-vpn
#   import route-target 192.0.2.6:200
#   import route-policy test-policy
#   import from bridge-domain advertise-as-vpn
#   import from default-vrf route-policy test-policy
#   import from vrf advertise-as-vpn
#   maximum prefix 100

- name: Gather existing running configuration
  cisco.iosxr.iosxr_vrf_address_family:
    state: gathered

# Task Output:
# ------------
#
# gathered:
# - name: VRF4
#   address_families:
#     - afi: "ipv4"
#       safi: "unicast"
#       export:
#         route_target: "192.0.2.1:400"
#         route_policy: "rm-policy"
#         to:
#           default_vrf:
#             route_policy: "rm-policy"
#           vrf:
#             allow_imported_vpn: true
#       import_config:
#         route_target: "192.0.2.6:200"
#         route_policy: "test-policy"
#         from_config:
#           bridge_domain:
#             advertise_as_vpn: true
#           default_vrf:
#             route_policy: "test-policy"
#           vrf:
#             advertise_as_vpn: true
#       maximum:
#         prefix: 100

# Using parsed
#
# File: parsed.cfg
# ----------------
#
# vrf test
#  address-family ipv4 unicast
#   export to default-vrf route-policy "rm-policy"
#   export to vrf allow-imported-vpn
#   export route-policy "export-policy"
#   export route-target
#    192.0.2.1:400
#   import route-target
#    192.0.2.2:200
#   import route-policy "test-policy"
#   import from bridge-domain advertise-as-vpn
#   import from default-vrf route-policy "new-policy"
#   import from vrf advertise-as-vpn
#   maximum prefix 23

- name: Parse the provided configuration
  cisco.iosxr.iosxr_vrf_address_family:
    running_config: "{{ lookup('file', 'parsed.cfg') }}"
    state: parsed

# Task Output:
# ------------
#
# parsed:
#   - address_families:
#     - afi: ipv4
#       export:
#         route_policy: export-policy
#         route_target: 192.0.2.1:400
#         to:
#           default_vrf:
#             route_policy: rm-policy
#           vrf:
#             allow_imported_vpn: true
#       import_config:
#         from_config:
#           bridge_domain:
#             advertise_as_vpn: true
#           default_vrf:
#             route_policy: new-policy
#           vrf:
#             advertise_as_vpn: true
#         route_policy: test-policy
#         route_target: 192.0.2.2:200
#       maximum:
#         prefix: 23
#       safi: unicast
#     name: test
"""

RETURN = """
before:
  description: The configuration prior to the model invocation.
  returned: always
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
after:
  description: The resulting configuration model invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample:
  - vrf VRF7
  - address-family ipv4 unicast
  - export route-policy rm-policy
  - import route-policy test-policy
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
  - vrf VRF4
  - address-family ipv4 unicast
  - export route-policy rm-policy
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

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.vrf_address_family.vrf_address_family import (
    Vrf_address_familyArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.config.vrf_address_family.vrf_address_family import (
    Vrf_address_family,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=Vrf_address_familyArgs.argument_spec,
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

    result = Vrf_address_family(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
