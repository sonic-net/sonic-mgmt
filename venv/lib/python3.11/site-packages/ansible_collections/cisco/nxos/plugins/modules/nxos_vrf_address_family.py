#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for nxos_vrf_address_family
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: nxos_vrf_address_family
short_description: Resource module to configure VRF address family definitions.
description: This module provides declarative management of VRF definitions on Cisco NXOS.
version_added: 9.3.0
author: Vinay Mulugund (@roverflow)
notes:
  - Tested against NX-OS 9.3.6.
  - This module works with connection C(network_cli) and C(httpapi).
    See U(https://docs.ansible.com/ansible/latest/network/user_guide/platform_nxos.html)
options:
  config:
    description: A list of device configurations for VRF address family.
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
            choices: ["ipv4", "ipv6"]
          safi:
            description: Address Family modifier
            type: str
            choices: ["multicast", "unicast"]
          maximum:
            description: Set a limit of routes
            type: dict
            suboptions:
              max_routes:
                description: Maximum number of routes allowed
                type: int
              max_route_options:
                description: Configure the options for maximum routes
                type: dict
                suboptions:
                  warning_only:
                    description: Configure only give a warning message if limit is exceeded
                    type: bool
                  threshold:
                    description: Configure threshold & its options
                    type: dict
                    suboptions:
                      threshold_value:
                        description: Threshold value (%) at which to generate a warning msg
                        type: int
                      reinstall_threshold:
                        description: Threshold value (%) at which to reinstall routes back to VRF
                        type: int
          route_target:
            description: Specify Target VPN Extended Communities
            type: list
            elements: dict
            suboptions:
              import:
                description: Import Target-VPN community
                type: str
              export:
                description: Export Target-VPN community
                type: str
          export:
            description: VRF export
            type: list
            elements: dict
            suboptions:
              map:
                description: Route-map based VRF export
                type: str
              vrf:
                description: Virtual Router Context
                type: dict
                suboptions:
                  max_prefix:
                    description: Maximum prefix limit
                    type: int
                  map_import:
                    description: Route-map based VRF import
                    type: str
                  allow_vpn:
                    description: Allow re-importation of VPN imported routes
                    type: bool
          import:
            description: VRF import
            type: list
            elements: dict
            suboptions:
              map:
                description: Route-map based VRF export
                type: str
              vrf:
                description: Virtual Router Context
                type: dict
                suboptions:
                  max_prefix:
                    description: Maximum prefix limit
                    type: int
                  map_import:
                    description: Route-map based VRF import
                    type: str
                  advertise_vpn:
                    description: Allow leaked routes to be advertised to VPN
                    type: bool
  running_config:
    description:
      - This option is used only with state I(parsed).
      - The value of this option should be the output received from the NX-OS device by
        executing the command B(show running-config | section ^vrf).
      - The state I(parsed) reads the configuration from C(running_config) option and
        transforms it into Ansible structured data as per the resource module's argspec
        and the value is then returned in the I(parsed) key within the result.
    type: str
  state:
    choices: [parsed, gathered, deleted, purged, merged, replaced, rendered, overridden]
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
        option should be the same format as the output of command I(show running-config | section ^vrf).
        connection to remote host is not required.
    type: str
"""

EXAMPLES = """
# Using merged

# Before state:
# -------------
#
# nxos#show running-config | section ^vrf

- name: Merge provided configuration with device configuration
  register: result
  cisco.nxos.nxos_vrf_address_family:
    config:
      - name: VRF1
        address_families:
          - afi: ipv4
            safi: unicast
            route_target:
              - export: "65512:200"
            maximum:
              max_routes: 500
              max_route_options:
                threshold:
                  threshold_value: 60
                  reinstall_threshold: 80
            export:
              - map: "22"
              - vrf:
                  allow_vpn: true
                  map_import: "44"
              - vrf:
                  allow_vpn: true
          - afi: ipv6
            safi: unicast
            maximum:
              max_routes: 1000
            route_target:
              - import: "65512:200"
            import:
              - map: "22"
              - vrf:
                  advertise_vpn: true
                  map_import: "44"
              - vrf:
                  advertise_vpn: true
    state: merged

# Task Output:
# ------------

# before: {}
# commands:
#   - vrf context VRF1
#   - address-family ipv4 unicast
#   - maximum routes 500 60 reinstall 80
#   - route-target export 65512:200
#   - export map 22
#   - export vrf default map 44 allow-vpn
#   - export vrf allow-vpn
#   - address-family ipv6 unicast
#   - maximum routes 1000
#   - route-target import 65512:200
#   - import map 22
#   - import vrf default map 44 advertise-vpn
#   - import vrf advertise-vpn
# after:
#   - address_families:
#       - afi: ipv4
#         export:
#           - map: "22"
#           - vrf:
#               allow_vpn: true
#               map_import: "44"
#           - vrf:
#               allow_vpn: true
#         maximum:
#           max_route_options:
#             threshold:
#               reinstall_threshold: 80
#               threshold_value: 60
#           max_routes: 500
#         route_target:
#           - export: 65512:200
#         safi: unicast
#       - afi: ipv6
#         import:
#           - map: "22"
#           - vrf:
#               advertise_vpn: true
#               map_import: "44"
#           - vrf:
#               advertise_vpn: true
#         maximum:
#           max_routes: 1000
#         route_target:
#           - import: 65512:200
#         safi: unicast
#     name: VRF1

# After state:
# ------------
#
# nxos#show running-config | section ^vrf
# vrf context VRF1
#   address-family ipv4 unicast
#     route-target export 65512:200
#     export map 22
#     export vrf default map 44 allow-vpn
#     export vrf allow-vpn
#     maximum routes 500 60 reinstall 80
#   address-family ipv6 unicast
#     route-target import 65512:200
#     import map 22
#     import vrf default map 44 advertise-vpn
#     import vrf advertise-vpn
#     maximum routes 1000

# Using deleted

# Before state:
# -------------
#
# nxos#show running-config | section ^vrf
# vrf context VRF1
#   address-family ipv4 unicast
#      route-target import 64512:200
#      route-target export 64512:200
#      export map 22
#      export vrf default map 44 allow-vpn
#      export vrf allow-vpn
#      maximum routes 900 22 reinstall 44

- name: Delete given vrf address family configuration
  register: result
  cisco.nxos.nxos_vrf_address_family:
    config:
      - name: VRF1
        address_families:
          - afi: ipv4
            safi: unicast
            route_target:
              - import: 64512:200
            export:
              - map: "22"
            maximum:
              max_routes: 900
              max_route_options:
                threshold:
                  threshold_value: 22
                  reinstall_threshold: 44
    state: deleted

# Task Output:
# ------------
#
# before:
#  - address_families:
#      - afi: ipv4
#        export:
#          - map: "22"
#          - vrf:
#              allow_vpn: true
#              map_import: "44"
#          - vrf:
#              allow_vpn: true
#        maximum:
#          max_route_options:
#            threshold:
#              reinstall_threshold: 44
#              threshold_value: 22
#          max_routes: 900
#        route_target:
#          - import: "64512:200"
#          - export: "64512:200"
#        safi: unicast
#    name: VRF1

# commands:
#   - vrf context VRF1
#   - address-family ipv4 unicast
#   - no maximum routes 900 22 reinstall 44
#   - no route-target import 64512:200
#   - no export map 22
# after:
#   - address_families:
#       - afi: ipv4
#         export:
#           - vrf:
#               allow_vpn: true
#               map_import: "44"
#           - vrf:
#               allow_vpn: true
#         route_target:
#           - export: "64512:200"
#         safi: unicast
#     name: VRF1

# Using purged

# Before state:
# -------------
#
# nxos#show running-config | section ^vrf
# vrf context VRF1
#   address-family ipv4 unicast
#     route-target export 65512:200
#     export map 22
#     export vrf default map 44 allow-vpn
#     export vrf allow-vpn
#     maximum routes 500 60 reinstall 80
#   address-family ipv6 unicast
#     route-target import 65512:200
#     import map 22
#     import vrf default map 44 advertise-vpn
#     import vrf advertise-vpn
#     maximum routes 1000

- name: Purge the configuration of VRF address family
  register: result
  cisco.nxos.nxos_vrf_address_family:
    config:
      - name: VRF1
        address_families:
          - afi: ipv4
            safi: unicast
          - afi: ipv6
            safi: unicast
    state: purged

# Task Output:
# ------------
#
# before:
#     - address_families:
#           - afi: ipv4
#             export:
#                 - map: "22"
#                 - vrf:
#                       allow_vpn: true
#                       map_import: "44"
#                 - vrf:
#                       allow_vpn: true
#             maximum:
#                 max_route_options:
#                     threshold:
#                         reinstall_threshold: 80
#                         threshold_value: 60
#                 max_routes: 500
#             route_target:
#                 - export: 65512:200
#             safi: unicast
#           - afi: ipv6
#             import:
#                 - map: "22"
#                 - vrf:
#                       advertise_vpn: true
#                       map_import: "44"
#                 - vrf:
#                       advertise_vpn: true
#             maximum:
#                 max_routes: 1000
#             route_target:
#                 - import: 65512:200
#             safi: unicast
#       name: VRF1
# commands:
#   - vrf context VRF1
#   - no address-family ipv4 unicast
#   - no address-family ipv6 unicast
# after: {}


# Using overridden

# Before state:
# -------------
#
# nxos#show running-config | section ^vrf
# vrf context VRF1
#   address-family ipv4 unicast
#     route-target import 64512:200
#   address-family ipv6 unicast
#     route-target import 554832:500

- name: Override the provided configuration with the existing running configuration
  cisco.nxos.nxos_vrf_address_family:
    config:
      - name: VRF1
        address_families:
          - afi: ipv6
            safi: unicast
            route_target:
              - export: 65512:200
            maximum:
              max_routes: 500
              max_route_options:
                threshold:
                  threshold_value: 60
                  reinstall_threshold: 80
            export:
              - map: "22"
              - vrf:
                  allow_vpn: true
                  map_import: "44"
              - vrf:
                  allow_vpn: true
      - name: temp
        address_families:
          - afi: ipv4
            safi: unicast
            route_target:
              - import: 65512:200
            maximum:
              max_routes: 1000
            export:
              - map: "26"
              - vrf:
                  allow_vpn: true
                  map_import: "46"
    state: overridden

# Task Output:
# ------------
#
# before:
#  - address_families:
#      - afi: ipv4
#        route_target:
#          - import: 64512:200
#        safi: unicast
#      - afi: ipv6
#        route_target:
#          - import: 554832:500
#        safi: unicast
#    name: VRF1
#
# commands:
#  - vrf context VRF1
#  - address-family ipv4 unicast
#  - no route-target import 64512:200
#  - address-family ipv6 unicast
#  - maximum routes 500 60 reinstall 80
#  - no route-target import 554832:500
#  - route-target export 65512:200
#  - export map 22
#  - export vrf default map 44 allow-vpn
#  - export vrf allow-vpn
#  - vrf context temp
#  - address-family ipv4 unicast
#  - maximum routes 1000
#  - route-target import 65512:200
#  - export map 26
#  - export vrf default map 46 allow-vpn
# after:
#  - address_families:
#      - afi: ipv4
#        safi: unicast
#      - afi: ipv6
#        export:
#          - map: "22"
#          - vrf:
#              allow_vpn: true
#              map_import: "44"
#          - vrf:
#              allow_vpn: true
#        maximum:
#          max_route_options:
#            threshold:
#              reinstall_threshold: 80
#              threshold_value: 60
#          max_routes: 500
#        route_target:
#          - export: 65512:200
#        safi: unicast
#    name: VRF1
#  - address_families:
#      - afi: ipv4
#        export:
#          - map: "26"
#          - vrf:
#              allow_vpn: true
#              map_import: "46"
#        maximum:
#          max_routes: 1000
#        route_target:
#          - import: 65512:200
#        safi: unicast
#    name: temp

# Using replaced

# Before state:
# -------------
#
# nxos# show running-config | section ^vrf
# vrf context VRF1
#   address-family ipv4 unicast
#     route-target import 64512:200
#   address-family ipv6 unicast
#     route-target import 554832:500

- name: Replaced state for VRF configuration
  cisco.nxos.nxos_vrf_global:
    config:
      vrfs:
        - ip:
            name_server:
              address_list:
                - 192.168.255.1
            route:
              - destination: 192.168.255.1
                source: 0.0.0.0/0
          name: management
        - name: temp
          description: Test
          ip:
            auto_discard: true
            domain_list:
              - invalid.com
              - example.com
            domain_name: test.org
    state: replaced

# Task Output:
# ------------
#
# before:
#  - address_families:
#      - afi: ipv4
#        route_target:
#          - import: 64512:200
#        safi: unicast
#      - afi: ipv6
#        route_target:
#          - import: 554832:500
#        safi: unicast
#    name: VRF1
# commands:
#  - vrf context VRF1
#  - address-family ipv4 unicast
#  - no route-target import 64512:200
#  - address-family ipv6 unicast
#  - maximum routes 500 60 reinstall 80
#  - no route-target import 554832:500
#  - route-target export 65512:200
#  - export map 22
#  - export vrf default map 44 allow-vpn
#  - export vrf allow-vpn
#  - vrf context temp
#  - address-family ipv4 unicast
#  - maximum routes 1000
#  - route-target import 65512:200
#  - export map 26
#  - export vrf default map 46 allow-vpn
# after:
#  - address_families:
#      - afi: ipv4
#        safi: unicast
#      - afi: ipv6
#        export:
#          - map: "22"
#          - vrf:
#              allow_vpn: true
#              map_import: "44"
#          - vrf:
#              allow_vpn: true
#        maximum:
#          max_route_options:
#            threshold:
#              reinstall_threshold: 80
#              threshold_value: 60
#          max_routes: 500
#        route_target:
#          - export: 65512:200
#        safi: unicast
#    name: VRF1
#  - address_families:
#      - afi: ipv4
#        export:
#          - map: "26"
#          - vrf:
#              allow_vpn: true
#              map_import: "46"
#        maximum:
#          max_routes: 1000
#        route_target:
#          - import: 65512:200
#        safi: unicast
#    name: temp
#
# After state:
# ------------
# router-ios#show running-config | section ^vrf
# vrf context VRF1
#   address-family ipv6 unicast
#     route-target export 65512:200
#     export map 22
#     export vrf default map 44 allow-vpn
#     export vrf allow-vpn
# vrf context temp
#   address-family ipv4 unicast
#     route-target import 65512:200
#     export map 26
#     export vrf default map 46 allow-vpn
#     maximum routes 1000

# Using gathered

# Before state:
# -------------
#
# nxos#show running-config | section ^vrf
# vrf context VRF1
#   address-family ipv4 unicast
#     route-target export 65512:200
#     export map 22
#     export vrf default map 44 allow-vpn
#     export vrf allow-vpn
#     maximum routes 500 60 reinstall 80
#   address-family ipv6 unicast
#     route-target import 65512:200
#     import map 22
#     import vrf default map 44 advertise-vpn
#     import vrf advertise-vpn
#     maximum routes 1000

- name: Gathered state for VRF configuration
  cisco.nxos.nxos_vrf_global:
    config:
    state: gathered

# Task Output:
# ------------
#
# gathered:
#     - address_families:
#           - afi: ipv4
#             export:
#                 - map: "22"
#                 - vrf:
#                       allow_vpn: true
#                       map_import: "44"
#                 - vrf:
#                       allow_vpn: true
#             maximum:
#                 max_route_options:
#                     threshold:
#                         reinstall_threshold: 80
#                         threshold_value: 60
#                 max_routes: 500
#             route_target:
#                 - export: 65512:200
#             safi: unicast
#           - afi: ipv6
#             import:
#                 - map: "22"
#                 - vrf:
#                       advertise_vpn: true
#                       map_import: "44"
#                 - vrf:
#                       advertise_vpn: true
#             maximum:
#                 max_routes: 1000
#             route_target:
#                 - import: 65512:200
#             safi: unicast
#       name: VRF1

# Using rendered

- name: Render provided configuration with device configuration
  register: result
  cisco.nxos.nxos_vrf_address_family:
    config:
      - name: VRF1
        address_families:
          - afi: ipv6
            safi: unicast
            route_target:
              - export: 65512:200
            maximum:
              max_routes: 500
              max_route_options:
                threshold:
                  threshold_value: 60
                  reinstall_threshold: 80
            export:
              - map: "22"
              - vrf:
                  allow_vpn: true
                  map_import: "44"
              - vrf:
                  allow_vpn: true
      - name: temp
        address_families:
          - afi: ipv4
            safi: unicast
            route_target:
              - import: 65512:200
            maximum:
              max_routes: 1000
            export:
              - map: "26"
              - vrf:
                  allow_vpn: true
                  map_import: "46"
    state: rendered

# Task Output:
# ------------
#
# commands:
#   - vrf context VRF1
#   - address-family ipv6 unicast
#   - maximum routes 500 60 reinstall 80
#   - route-target export 65512:200
#   - export map 22
#   - export vrf default map 44 allow-vpn
#   - export vrf allow-vpn
#   - vrf context temp
#   - address-family ipv4 unicast
#   - maximum routes 1000
#   - route-target import 65512:200
#   - export map 26
#   - export vrf default map 46 allow-vpn

# Using Parsed

# Parsed Config:
# -------------
# vrf context VRF1
#   address-family ipv4 unicast
#     route-target import 64512:200
#     route-target export 64512:200
#     export map 22
#     export vrf default map 44 allow-vpn
#     export vrf allow-vpn
#     maximum routes 900 22 reinstall 44
#   address-family ipv6 unicast
#     route-target import 554832:500

- name: Parse the commands for provided configuration
  register: result
  cisco.nxos.nxos_vrf_address_family:
    running_config: "{{ lookup('file', '_parsed.cfg') }}"
    state: parsed

# Task Output:
# ------------
# parsed:
#   - name: VRF1
#     address_families:
#       - afi: ipv4
#         safi: unicast
#         route_target:
#           - import: 64512:200
#           - export: 64512:200
#         export:
#           - map: "22"
#           - vrf:
#               allow_vpn: true
#               map_import: "44"
#           - vrf:
#               allow_vpn: true
#         maximum:
#           max_routes: 900
#           max_route_options:
#             threshold:
#               threshold_value: 22
#               reinstall_threshold: 44
#       - afi: ipv6
#         safi: unicast
#         route_target:
#           - import: 554832:500
"""

RETURN = """
before:
  description: The configuration prior to the module execution.
  returned: when I(state) is C(merged), C(replaced), C(overridden), C(deleted) or C(purged)
  type: list
  sample: >
    This output will always be in the same format as the
    module argspec.
after:
  description: The resulting configuration after module execution.
  returned: when changed
  type: list
  sample: >
    This output will always be in the same format as the
    module argspec.
commands:
  description: The set of commands pushed to the remote device.
  returned: when I(state) is C(merged), C(replaced), C(overridden), C(deleted) or C(purged)
  type: list
  sample:
    - vrf context management
    - address-family ipv4 unicast
    - maximum routes 500 60 reinstall 80
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - vrf context test1
    - address-family ipv6 unicast
    - route-target export 65512:200
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

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.vrf_address_family.vrf_address_family import (
    Vrf_address_familyArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.config.vrf_address_family.vrf_address_family import (
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
