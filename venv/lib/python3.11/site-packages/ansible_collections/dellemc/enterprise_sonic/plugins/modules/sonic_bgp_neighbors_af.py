#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_bgp_neighbors_af
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_bgp_neighbors_af
version_added: 1.0.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
author: Niraimadaiselvam M (@niraimadaiselvamm)
short_description: Manage the BGP neighbor address-family and its parameters
description:
  - This module provides configuration management of BGP neighbors address-family parameters on devices running Enterprise SONiC.
  - bgp_as, vrf_name and neighbors need be created in advance on the device.
options:
  config:
    description:
      - Specifies the BGP neighbors address-family related configuration.
    type: list
    elements: dict
    suboptions:
      bgp_as:
        description:
          - Specifies the BGP autonomous system (AS) number which is already configured on the device.
        type: str
        required: true
      vrf_name:
        description:
          - Specifies the VRF name which is already configured on the device.
        type: str
        default: 'default'
      neighbors:
        description:
          - Specifies BGP neighbor related configurations in address-family configuration mode.
        type: list
        elements: dict
        suboptions:
          neighbor:
            description:
              - Neighbor router address which is already configured on the device.
            type: str
            required: True
          address_family:
            description:
              - Specifies BGP address-family related configurations.
              - afi and safi are required together.
            type: list
            elements: dict
            suboptions:
              afi:
                description:
                  - Type of address-family to configure.
                type: str
                choices:
                  - ipv4
                  - ipv6
                  - l2vpn
                required: True
              safi:
                description:
                  - Specifies the type of cast for the address-family.
                type: str
                choices:
                  - unicast
                  - evpn
                default: unicast
              activate:
                description:
                  - Enables the address-family for this neighbor.
                type: bool
              allowas_in:
                description:
                  - Criterion for accepting received advertisements containing the AS number
                  - of this BGP router intance in the AS PATH of received advertisements.
                  - The 'origin' option can not be set to true when a 'value' is set.
                type: dict
                suboptions:
                  origin:
                    description:
                      - Accept this BGP router instance's set AS as the origin.
                    type: bool
                  value:
                    description:
                      - Accept up to this number of occurrences of this BGP router's
                      - set AS in the AS-PATH of received advertisements.
                      - (Specify a number in the range 1-10.)
                    type: int
              fabric_external:
                description:
                  - Configure a neighbor as fabric-external.
                  - Fabric external is supported only for l2vpn address family.
                type: bool
              ip_afi:
                description:
                  - Common configuration attributes for IPv4 and IPv6 unicast address families.
                type: dict
                suboptions:
                  default_policy_name:
                    description:
                      - Specifies routing policy definition.
                    type: str
                  send_default_route:
                    description:
                      - Enable or disable sending of default-route to the neighbor.
                    type: bool
                    default: False
              prefix_limit:
                description:
                  - Specifies prefix limit attributes for ipv4-unicast and ipv6-unicast.
                type: dict
                suboptions:
                  max_prefixes:
                    description:
                      - Maximum number of prefixes that will be accepted from the neighbor.
                    type: int
                  prevent_teardown:
                    description:
                      - Enable or disable teardown of BGP session when maximum prefix limit is exceeded.
                    type: bool
                    default: False
                  warning_threshold:
                    description:
                      - Threshold on number of prefixes that can be received from a neighbor before generation of warning messages.
                      - Expressed as a percentage of max-prefixes.
                    type: int
                  restart_timer:
                    description:
                      - Time interval in seconds after which the BGP session is re-established after being torn down.
                    type: int
                  discard_extra:
                    description:
                      - Enable or disable discard extra of BGP session when maximum prefix limit is exceeded.
                    type: bool
                    default: False
              prefix_list_in:
                description:
                  - Inbound route filtering policy for a neighbor.
                type: str
              prefix_list_out:
                description:
                  - Outbound route filtering policy for a neighbor.
                type: str
              route_map:
                description:
                  - Specifies the route-map.
                type: list
                elements: dict
                suboptions:
                  name:
                    description:
                      - Specifies the name of the route-map.
                    type: str
                  direction:
                    description:
                      - Specifies the direction of the route-map.
                    type: str
              route_reflector_client:
                description:
                  - Specifies a neighbor as a route-reflector client.
                type: bool
              route_server_client:
                description:
                  - Specifies a neighbor as a route-server client.
                type: bool
  state:
    description:
      - Specifies the operation to be performed on the BGP process that is configured on the device.
      - In case of merged, the input configuration is merged with the existing BGP configuration on the device.
      - In case of deleted, the existing BGP configuration is removed from the device.
    default: merged
    type: str
    choices: ['merged', 'deleted', 'replaced', 'overridden']
"""

EXAMPLES = """
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration bgp neighbor vrf default
# !
# neighbor interface Eth1/3
#  !
#  address-family ipv4 unicast
#   activate
#   allowas-in 4
#   route-map aa in
#   route-map aa out
#   route-reflector-client
#   route-server-client
#   send-community both
# !

- name: Delete specific BGP neighbors AF attributes
  dellemc.enterprise_sonic.sonic_bgp_neighbors_af:
     config:
        - bgp_as: 4
          neighbors:
             - neighbor: Eth1/3
               address_family:
                  - afi: ipv4
                    safi: unicast
                    allowas_in:
                       value: 4
                    route_map:
                       - name: aa
                         direction: in
                       - name: aa
                         direction: out
                    route_reflector_client: true
                    route_server_client: true
     state: deleted

# After state:
# ------------
#
# sonic# show running-configuration bgp neighbor vrf default
# !
# neighbor interface Eth1/3
#  !
#  address-family ipv4 unicast
#   send-community both
# !


# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration bgp neighbor vrf default 1.1.1.1
# (No bgp neighbor configuration present)
- name: "Configure BGP neighbor prefix-list attributes"
  dellemc.enterprise_sonic.sonic_bgp_neighbors_af:
     config:
        - bgp_as: 51
          neighbors:
             - neighbor: 1.1.1.1
               address_family:
                  - afi: ipv4
                    safi: unicast
                    ip_afi:
                       default_policy_name: rmap_reg1
                       send_default_route: true
                    prefix_limit:
                       max_prefixes: 2
                       discard_extra: true
                       warning_threshold: 60
                    prefix_list_in: p1
                    prefix_list_out: p2
     state: merged
# After state:
# ------------
#
# sonic# show running-configuration bgp neighbor vrf default 1.1.1.1
# !
# neighbor 1.1.1.1
#  !
#  address-family ipv4 unicast
#   default-originate route-map rmap_reg1
#   prefix-list p1 in
#   prefix-list p2 out
#   send-community both
#   maximum-prefix 2 60 discard-extra


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration bgp neighbor vrf default
# !
# neighbor 1.1.1.1
#  !
#  address-family ipv6 unicast
#   default-originate route-map rmap_reg2
#   prefix-list p1 in
#   prefix-list p2 out
#   send-community both
#   maximum-prefix 5 90 restart 2

- name: Delete BGP neighbors AF prefix-list attributes
  dellemc.enterprise_sonic.sonic_bgp_neighbors_af:
     config:
        - bgp_as: 51
          neighbors:
             - neighbor: 1.1.1.1
               address_family:
                  - afi: ipv6
                    safi: unicast
                    ip_afi:
                       default_policy_name: rmap_reg2
                       send_default_route: true
                    prefix_limit:
                       max_prefixes: 5
                       warning_threshold: 90
                       restart-timer: 2
                    prefix_list_in: p1
                    prefix_list_out: p2
     state: deleted

# After state:
# ------------
#
# sonic# show running-configuration bgp neighbor vrf default
# !
# neighbor 1.1.1.1
# !


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration bgp neighbor vrf default
# !
# neighbor interface Eth1/3
#  !
#  address-family ipv4 unicast
#   activate
#   allowas-in 4
#   route-map aa in
#   route-map aa out
#   route-reflector-client
#   route-server-client
#   send-community both
# !
# neighbor interface Eth1/5
#  !
#  address-family ipv4 unicast
#   activate
#   allowas-in origin
#   send-community both
# !

- name: Delete all BGP neighbors AF configuration
  dellemc.enterprise_sonic.sonic_bgp_neighbors_af:
     config:
     state: deleted

# After state:
# ------------
#
# sonic# show running-configuration bgp neighbor vrf default
# (No bgp neighbor configuration present)


# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration bgp neighbor vrf default
# !
# neighbor interface Eth1/3
# !

- name: Merge BGP neighbors AF configuration
  dellemc.enterprise_sonic.sonic_bgp_neighbors_af:
     config:
        - bgp_as: 4
          neighbors:
             - neighbor: Eth1/3
               address_family:
                  - afi: ipv4
                    safi: unicast
                    allowas_in:
                       value: 4
                    route_map:
                       - name: aa
                         direction: in
                       - name: aa
                         direction: out
                    route_reflector_client: true
                    route_server_client: true
     state: merged

# After state:
# ------------
#
# sonic# show running-configuration bgp neighbor vrf default
# !
# neighbor interface Eth1/3
#  !
#  address-family ipv4 unicast
#   activate
#   allowas-in 4
#   route-map aa in
#   route-map aa out
#   route-reflector-client
#   route-server-client
#   send-community both
# !


# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration bgp neighbor vrf default
# (No bgp neighbor configuration present)

- name: Configure BGP neighbors AF prefix-list attributes
  dellemc.enterprise_sonic.sonic_bgp_neighbors_af:
     config:
        - bgp_as: 51
          neighbors:
             - neighbor: 1.1.1.1
               address_family:
                  - afi: ipv4
                    safi: unicast
                    ip_afi:
                       default_policy_name: rmap_reg1
                       send_default_route: true
                    prefix_limit:
                       max_prefixes: 1
                       prevent_teardown: true
                       warning_threshold: 80
                    prefix_list_in: p1
                    prefix_list_out: p2
     state: merged

# After state:
# ------------
#
# sonic# show running-configuration bgp neighbor vrf default
# !
# neighbor 1.1.1.1
#  !
#  address-family ipv4 unicast
#   default-originate route-map rmap_reg1
#   prefix-list p1 in
#   prefix-list p2 out
#   send-community both
#   maximum-prefix 1 80 warning-only
# !


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration bgp neighbor vrf default
# !
# neighbor 1.1.1.1
#  !
#  address-family ipv6 unicast
#   default-originate route-map rmap_reg2
#   prefix-list p1 in
#   prefix-list p2 out
#   send-community both
#   maximum-prefix 5 90 restart 2
# !

- name: Replace BGP neighbors AF attributes
  dellemc.enterprise_sonic.sonic_bgp_neighbors_af:
     config:
        - bgp_as: 51
          neighbors:
             - neighbor: 1.1.1.1
               address_family:
                  - afi: ipv4
                    safi: unicast
                    ip_afi:
                       default_policy_name: rmap_reg1
                       send_default_route: true
                    prefix_limit:
                       max_prefixes: 1
                       prevent_teardown: true
                       warning_threshold: 80
                    prefix_list_in: p1
                    prefix_list_out: p2
     state: replaced

# After state:
# ------------
#
# sonic# show running-configuration bgp neighbor vrf default
# !
# neighbor 1.1.1.1
#  !
#  address-family ipv4 unicast
#   default-originate route-map rmap_reg1
#   prefix-list p1 in
#   prefix-list p2 out
#   send-community both
#   maximum-prefix 1 80 warning-only
# !


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show running-configuration bgp neighbor vrf default
# !
# neighbor 1.1.1.1
#  !
#  address-family ipv6 unicast
#   default-originate route-map rmap_reg2
#   prefix-list p1 in
#   prefix-list p2 out
#   send-community both
#   maximum-prefix 5 90 restart 2
# !

- name: Override BGP neighbors AF configuration
  dellemc.enterprise_sonic.sonic_bgp_neighbors_af:
     config:
        - bgp_as: 51
          neighbors:
             - neighbor: 2.2.2.2
               address_family:
                  - afi: ipv4
                    safi: unicast
                    ip_afi:
                       default_policy_name: rmap_reg1
                       send_default_route: true
                    prefix_limit:
                       max_prefixes: 1
                       prevent_teardown: true
                       warning_threshold: 80
                    prefix_list_in: p1
                    prefix_list_out: p2
     state: overridden

# After state:
# ------------
#
# sonic# show running-configuration bgp neighbor vrf default
# !
# neighbor 2.2.2.2
#  !
#  address-family ipv4 unicast
#   default-originate route-map rmap_reg1
#   prefix-list p1 in
#   prefix-list p2 out
#   send-community both
#   maximum-prefix 1 80 warning-only
# !
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: list
  sample: >
    The configuration returned is always in the same format
    as the parameters above.
after:
  description: The resulting configuration module invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned is always in the same format
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.bgp_neighbors_af.bgp_neighbors_af import Bgp_neighbors_afArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.bgp_neighbors_af.bgp_neighbors_af import Bgp_neighbors_af


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Bgp_neighbors_afArgs.argument_spec,
                           supports_check_mode=True)

    result = Bgp_neighbors_af(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
