#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_ospfv3
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_ospfv3
version_added: '3.1.0'
notes:
  - Supports C(check_mode).
  - Tested against Enterprise SONiC Distribution by Dell Technologies.
short_description: Configure global OSPFv3 protocol settings on SONiC.
description:
  - This module provides configuration management of global OSPFv3 parameters on devices running SONiC.
  - Configure VRF instance before configuring OSPFv3 in a VRF.
author: "Thenmozhi Gopal (@thenmozhi-gopal), Naresh Sasivarnan (@NareshSasivarnan)"

options:
  config:
    description:
      - Specifies the OSPFv3 related configuration.
    type: list
    elements: dict
    suboptions:
      auto_cost_reference_bandwidth:
        description:
          - Configure interface auto cost reference bandwidth (1 to 4294967).
        type: int
      distance:
        description:
          - Configure route administrative distance.
        type: dict
        suboptions:
          all:
            description:
              - Distance value for all type of routes (1 to 255).
            type: int
          external:
            description:
              - External routes (1 to 255).
            type: int
          inter_area:
            description:
              - Inter area routes (1 to 255).
            type: int
          intra_area:
            description:
              - Intra area routes (1 to 255).
            type: int
      graceful_restart:
        description:
          - OSPFv3 non stop forwarding (NSF) also known as OSPFv3 Graceful Restart.
        type: dict
        suboptions:
          enable:
            description:
              - Enable graceful restart.
            type: bool
          grace_period:
            description:
              - Maximum length of the grace period (1 to 1800).
            type: int
          helper:
            description:
              - OSPFv3 GR Helper.
            type: dict
            suboptions:
              enable:
                description:
                  - Enable Helper support.
                type: bool
              advertise_router_id:
                description:
                  - Advertising Router ID.
                type: list
                elements: str
              planned_only:
                description:
                  - Supported only planned restart.
                type: bool
              strict_lsa_checking:
                description:
                  - Enable strict LSA check.
                type: bool
              supported_grace_time:
                description:
                  - Supported grace interval (10 to 1800).
                type: int
      log_adjacency_changes:
        description:
          - Enable OSPFv3 adjacency state logs.
        type: str
        choices:
          - brief
          - detail
      maximum_paths:
        description:
          - Configure maximum number of multiple paths for ECMP support (1 to 256).
        type: int
      redistribute:
        description:
          - Configure route redistribution into OSPFv3 router.
        type: list
        elements: dict
        suboptions:
          always:
            description:
              - Enable default route redistribution into OSPFv3 always.
              - Only available for I(protocol=default_route).
            type: bool
          metric:
            description:
              - Metric value for redistributed routes (0 to 16777214).
            type: int
          metric_type:
            description:
              - Metric type for redistributed routes.
            type: int
            choices:
              - 1
              - 2
          protocol:
            description:
              - Configure the type of protocol to redistribute into OSPFv3.
              - Deleting I(protocol) alone will also delete all the other configuration under I(redistribute).
              - C(bgp) - Border Gateway Protocol.
              - C(connected) - Directly connected or attached subnets and hosts.
              - C(default_route) - Default routes.
              - C(kernel) - Kernel routes other than FRR installed routes.
              - C(static) - Statically configured routes.
            type: str
            choices:
              - bgp
              - connected
              - default_route
              - kernel
              - static
            required: true
          route_map:
            description:
              - Route map to filter redistributed routes.
              - Configure route map before.
            type: str
      router_id:
        description:
          - Configure OSPFv3 router identifier (A.B.C.D).
        type: str
      timers:
        description:
          - Configures router timers.
        type: dict
        suboptions:
          lsa_min_arrival:
            description:
              - LSA minimum arrival timer (0 to 600000).
            type: int
          throttle_spf:
            description:
              - OSPFv3 SPF timers.
              - I(delay_time), I(initial_hold_time) and I(maximum_hold_time) are required together.
            type: dict
            suboptions:
              delay_time:
                description:
                  - SPF delay time in milliseconds (0 to 600000).
                type: int
              initial_hold_time:
                description:
                  - SPF initial hold time in milliseconds (0 to 600000).
                type: int
              maximum_hold_time:
                description:
                  - SPF maximum hold time in milliseconds (0 to 600000).
                type: int
      write_multiplier:
        description:
          - Configure write multiplier (1 to 100).
          - Maximum number of interfaces serviced per write.
        type: int
      vrf_name:
        description:
          - Specifies the vrf name.
        type: str
        default: 'default'
  state:
    description:
      - Specifies the operation to be performed on the OSPFv3 process configured on the device.
      - In case of merged, the input configuration will be merged with the existing OSPFv3 configuration on the device.
      - In case of deleted, the specified existing OSPFv3 configuration will be removed from the device.
      - In case of overridden, all the existing OSPFv3 configuration will be deleted and the specified input configuration will be installed.
      - In case of replaced, the existing OSPFv3 configuration on the device will be replaced by the configuration
        in the playbook for each VRF group configured by the playbook.
    type: str
    default: merged
    choices: ['merged', 'deleted', 'replaced', 'overridden']
"""

EXAMPLES = """
# Using deleted

# Before state:
# -------------
#
# sonic# show running-configuration ospfv3
# router ospfv3 vrf Vrf_1
# timers throttle spf 50 20 1000
# redistribute bgp metric 15 metric-type 2 route-map RMAP
# !
# router ospfv3
# ospfv3 router-id 20.20.20.20
# distance 30
# distance ospfv3 external 20
# write-multiplier 20
# !
# sonic#
# sonic# show running-configuration vrf Vrf_1
# !
# ip vrf Vrf_1
# sonic# show running-configuration ipv6 prefix-list
# !
# ipv6 prefix-list PRF_LIST seq 1 permit 1::1/64
# ipv6 prefix-list PRF_LIST2 seq 1 permit 2::1/64
# sonic# show running-configuration route-map
# !
# route-map RMAP permit 1
# sonic#

- name: Delete the OSPFv3 configurations
  sonic_ospfv3:
    config:
      - vrf_name: 'default'
        router_id: "20.20.20.20"
        distance:
          external: 20
      - vrf_name: "Vrf_1"
        timers:
          throttle_spf:
          delay_time: 50
          initial_hold_time: 20
          maximum_hold_time: 1000
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration ospfv3
# router ospfv3 vrf Vrf_1
# redistribute bgp metric 15 metric-type 2 route-map RMAP
# !
# router ospfv3
# distance 30
# write-multiplier 20
# !
# sonic#


# Using deleted

# Before state:
# -------------
#
# sonic# show running-configuration ospfv3
# router ospfv3 vrf Vrf_1
# timers throttle spf 50 20 1000
# redistribute bgp metric 15 metric-type 2 route-map RMAP
# !
# router ospfv3
# distance 30
# write-multiplier 20
# !
# sonic#
# sonic# show running-configuration vrf Vrf_1
# !
# ip vrf Vrf_1
# sonic# show running-configuration ipv6 prefix-list
# !
# ipv6 prefix-list PRF_LIST seq 1 permit 1::1/24
# ipv6 prefix-list PRF_LIST2 seq 1 permit 2::1/24
# sonic# show running-configuration route-map
# !
# route-map RMAP permit 1
# sonic#

- name: Delete the OSPFv3 configurations
  sonic_ospfv3:
    config:
      - vrf_name: "Vrf_1"
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration ospfv3
# router ospfv3
# distance 30
# write-multiplier 20
# !
# sonic#


# Using merged

# Before state:
# -------------
#
# sonic# show running-configuration ospfv3
# (No ospfv3 configuration present)
# sonic# show running-configuration vrf Vrf_1
# !
# ip vrf Vrf_1
# sonic# show running-configuration ipv6 prefix-list
# !
# ipv6 prefix-list PRF_LIST seq 1 permit 1::1/24
# ipv6 prefix-list PRF_LIST2 seq 1 permit 2::1/24
# sonic# show running-configuration route-map
# !
# route-map RMAP permit 1
# sonic#

- name: Add the OSPFv3 configurations
  sonic_ospfv3:
    config:
      - vrf_name: 'default'
        router_id: "10.10.10.10"
        distance:
          external: 20
      - vrf_name: "Vrf_1"
        timers:
          throttle_spf:
          delay_time: 10
          initial_hold_time: 20
          maximum_hold_time: 50
        redistribute:
          - protocol: "bgp"
            metric: 15
            metric_type: 2
            route_map: "RMAP"
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration ospfv3
# router ospfv3 vrf Vrf_1
# timers throttle spf 10 20 50
# redistribute bgp metric 15 metric-type 2 route-map RMAP
# !
# router ospfv3
# ospfv3 router-id 10.10.10.10
# distance ospfv3 external 20
# !
# sonic#


# Using merged

# Before state:
# -------------
#
# sonic# show running-configuration ospfv3
# router ospfv3 vrf Vrf_1
# timers throttle spf 10 20 50
# redistribute bgp metric 15 metric-type 2 route-map RMAP
# !
# router ospfv3
# ospfv3 router-id 10.10.10.10
# distance ospfv3 external 20
# !
# sonic#
# sonic# show running-configuration vrf Vrf_1
# !
# ip vrf Vrf_1
# sonic# show running-configuration ipv6 prefix-list
# !
# ipv6 prefix-list PRF_LIST seq 1 permit 1::1/24
# ipv6 prefix-list PRF_LIST2 seq 1 permit 2::1/24
# sonic# show running-configuration route-map
# !
# route-map RMAP permit 1
# sonic#

- name: Add the OSPFv3 configurations
  sonic_ospfv3:
    config:
      - vrf_name: 'default'
        write_multiplier: 20
        router_id: "20.20.20.20"
        distance:
          all: 30
      - vrf_name: "Vrf_1"
        timers:
          throttle_spf:
            delay_time: 50
            initial_hold_time: 20
            maximum_hold_time: 100
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration ospfv3
# router ospfv3 vrf Vrf_1
# timers throttle spf 50 20 100
# redistribute bgp metric 15 metric-type 2 route-map RMAP
# !
# router ospfv3
# ospfv3 router-id 20.20.20.20
# distance 30
# distance ospfv3 external 20
# write-multiplier 20
# !
# sonic#


# Using replaced

# Before state:
# -------------
#
# sonic# show running-configuration ospfv3
# router ospfv3 vrf Vrf_1
# timers throttle spf 50 20 10
# redistribute bgp metric 15 metric-type 2 route-map RMAP
# !
# router ospfv3
# ospfv3 router-id 20.20.20.20
# distance 30
# distance ospfv3 external 20
# write-multiplier 20
# !
# sonic#
# sonic# show running-configuration vrf Vrf_1
# !
# ip vrf Vrf_1
# sonic# show running-configuration ipv6 prefix-list
# !
# ipv6 prefix-list PRF_LIST seq 1 permit 1::1/24
# ipv6 prefix-list PRF_LIST2 seq 1 permit 2::1/24
# sonic# show running-configuration route-map
# !
# route-map RMAP permit 1
# route-map RMAP2 permit 2
# sonic#

- name: Replace the OSPFv3 vrf default configurations
  sonic_ospfv3:
    config:
      - vrf_name: 'default'
        router_id: "20.20.20.20"
        redistribute:
          - protocol: "connected"
            metric: 15
            metric_type: 2
            route_map: "RMAP2"
        distance:
          all: 20
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration ospfv3
# router ospfv3 vrf Vrf_1
# timers throttle spf 50 20 10
# redistribute bgp metric 15 metric-type 2 route-map RMAP
# !
# router ospfv3
# ospfv3 router-id 20.20.20.20
# distance 20
# redistribute connected metric 15 metric-type 2 route-map RMAP2
# !


# Using overridden

# Before state:
# -------------
#
# sonic# show running-configuration ospfv3
# router ospfv3 vrf Vrf_1
# timers throttle spf 50 20 10
# redistribute bgp metric 15 metric-type 2 route-map RMAP
# !
# router ospfv3
# ospfv3 router-id 20.20.20.20
# distance 30
# distance ospfv3 external 20
# write-multiplier 20
# !
# sonic#
# sonic# show running-configuration vrf Vrf_1
# !
# ip vrf Vrf_1
# sonic# show running-configuration ipv6 prefix-list
# !
# ipv6 prefix-list PRF_LIST seq 1 permit 1::1/24
# ipv6 prefix-list PRF_LIST2 seq 1 permit 2::1/24
# sonic# show running-configuration route-map
# !
# route-map RMAP permit 1
# route-map RMAP2 permit 2
# sonic#

- name: Override the OSPFv3 configurations
  sonic_ospfv3:
    config:
      - vrf_name: 'default'
        router_id: "20.20.20.20"
        redistribute:
          - protocol: "connected"
            metric: 15
            metric_type: 2
            route_map: "RMAP2"
        distance:
          all: 20
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration ospfv3
# router ospfv3
# ospfv3 router-id 20.20.20.20
# distance 20
# redistribute connected metric 15 metric-type 2 route-map RMAP2
# !
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
  description: The configuration resulting from module invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
     as the parameters above.
after(generated):
  description: The generated (calculated) configuration that would be applied by module invocation.
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ospfv3.ospfv3 import Ospfv3Args
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.ospfv3.ospfv3 import Ospfv3


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Ospfv3Args.argument_spec,
                           supports_check_mode=True)

    result = Ospfv3(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
