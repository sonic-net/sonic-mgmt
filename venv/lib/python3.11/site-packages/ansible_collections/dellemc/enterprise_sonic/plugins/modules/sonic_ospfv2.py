#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_ospfv2
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_ospfv2
version_added: '2.5.0'
notes:
- Supports C(check_mode).
short_description: Configure global OSPFv2 protocol settings on SONiC.
description:
  - This module provides configuration management of global OSPFv2 parameters on devices running SONiC.
  - Configure VRF instance before configuring OSPF in a VRF.
author: "Santhosh kumar T (@santhosh-kt)"
options:
  config:
    description:
      - Specifies the OSPFv2 related configuration.
      - I(non_passive_interfaces) and I(passive_interfaces) are mutually exclusive.
      - When I(default_passive=True), I(passive_interfaces) cannot be configured.
      - When I(default_passive=False), I(non_passive_interfaces) cannot be configured.
    type: list
    elements: dict
    suboptions:
      abr_type:
        description:
          - Configure router ABR type.
          - C(cisco) - Cisco implementation type ABR.
          - C(ibm) - IBM implementation type ABR.
          - C(shortcut) - Shortcut ABR.
          - C(standard) - RFC2328 Standard implementation ABR.
        type: str
        choices:
          - cisco
          - ibm
          - shortcut
          - standard
      auto_cost_reference_bandwidth:
        description:
          - Configure interface auto cost reference bandwidth (1 to 4294967).
        type: int
      default_metric:
        description:
          - Configure metric for redistributed routes (0 to 16777214).
        type: int
      default_passive:
        description:
          - Suppresses OSPFv2 routing updates on all interfaces.
        type: bool
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
              - Distance value for external routes (1 to 255).
            type: int
          inter_area:
            description:
              - Distance value for inter-area routes (1 to 255).
            type: int
          intra_area:
            description:
              - Distance value for intra-area routes (1 to 255).
            type: int
      graceful_restart:
        description:
          - OSPF non stop forwarding (NSF) also known as OSPF Graceful Restart.
        type: dict
        suboptions:
          enable:
            description:
              - Enable graceful restart.
            type: bool
          grace_period:
            description:
              - Maximum length of the grace period in seconds (1 to 1800).
            type: int
          helper:
            description:
              - OSPF GR Helper.
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
                  - Supported grace interval in seconds (10 to 1800).
                type: int
      log_adjacency_changes:
        description:
          - Enable OSPFv2 adjacency state logs.
        type: str
        choices:
          - brief
          - detail
      max_metric:
        description:
          - Enables infinite metric advertising in OSPFv2 LSAs.
        type: dict
        suboptions:
          administrative:
            description:
              - Enables administrative type infinite metric advertising.
            type: bool
          external_lsa_all:
            description:
              - Configure external LSA all prefix max metric advertising.
              - Configure the maximum metric value (1 to 16777215).
            type: int
          external_lsa_connected:
            description:
              - Configure external LSA connected prefix max metric advertising.
              - Configure the maximum metric value (1 to 16777215).
            type: int
          on_startup:
            description:
              - Enables infinite metric advertising at OSPFv2 router startup (5 to 86400).
            type: int
          router_lsa_all:
            description:
              - Configure router LSA all link max metric advertising.
              - Configure the maximum metric value (1 to 16777215).
            type: int
          router_lsa_stub:
            description:
              - Configure router LSA stub link max metric advertising.
              - Configure the maximum metric value (1 to 16777215).
            type: int
      maximum_paths:
        description:
          - Configure maximum number of multiple paths for ECMP support (1 to 256).
        type: int
      non_passive_interfaces:
        description:
          - Configure non passive interface types.
        type: list
        elements: dict
        suboptions:
          addresses:
            description:
              - Configure Interface IPv4 addresses.
            type: list
            elements: str
          interface:
            description:
              - Full name of the Layer 3 interface, i.e. Eth1/1.
            type: str
            required: true
      opaque_lsa_capability:
        description:
          - Enables opaque LSA capability.
        type: bool
      passive_interfaces:
        description:
          - Configure passive interface types.
        type: list
        elements: dict
        suboptions:
          addresses:
            description:
              - Configure Interface IPv4 addresses.
            type: list
            elements: str
          interface:
            description:
              - Full name of the Layer 3 interface, i.e. Eth1/1.
            type: str
            required: true
      redistribute:
        description:
          - Configure route redistribution into OSPFv2 router.
        type: list
        elements: dict
        suboptions:
          always:
            description:
              - Enable default route redistribution into OSPF always.
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
              - Configure the type of protocol to redistribute into OSPF.
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
      refresh_timer:
        description:
          - Configures LSA refresh interval in seconds (10 to 1800).
        type: int
      rfc1583_compatible:
        description:
          - Enable OSPFv2 RFC compatibility.
        type: bool
      router_id:
        description:
          - Configure OSPFv2 router identifier (A.B.C.D).
        type: str
      timers:
        description:
          - Configures router timers.
        type: dict
        suboptions:
          lsa_min_arrival:
            description:
              - LSA minimum arrival timer in milliseconds (0 to 600000).
            type: int
          throttle_lsa_all:
            description:
              - LSA delay between transmissions in milliseconds (0 to 5000).
            type: int
          throttle_spf:
            description:
              - OSPFv2 SPF timers.
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
          - Specifies the maximum number of interfaces serviced per write (1 to 100)
        type: int
      vrf_name:
        description:
          - Specifies the vrf name.
        type: str
        default: 'default'
  state:
    description:
      - Specifies the operation to be performed on the OSPFv2 process configured on the device.
      - In case of merged, the input configuration will be merged with the existing OSPFv2 configuration on the device.
      - In case of deleted, the existing OSPFv2 configuration will be removed from the device.
      - In case of overridden, all the existing OSPFv2 configuration will be deleted and the specified input configuration will be installed.
      - In case of replaced, the existing OSPFv2 configuration on the device will be replaced by the configuration
        in the playbook for each VRF group configured by the playbook.
    type: str
    default: merged
    choices: ['merged', 'deleted', 'replaced', 'overridden']
"""

EXAMPLES = """
# Using "deleted" state

# Before state:
# -------------
#
# sonic# show running-configuration ospf
# router ospf vrf Vrf_1
# default-metric 100
# max-metric router-lsa external-lsa all 2
# passive-interface default
# timers throttle spf 50 20 10
# timers throttle lsa all 300
# redistribute bgp metric 15 metric-type 2 route-map RMAP
# no passive-interface Eth1/1 2.2.2.2
# no passive-interface Eth1/2 2.2.2.2
# !
# router ospf
# ospf router-id 20.20.20.20
# distance 30
# distance ospf external 20
# refresh timer 300
# write-multiplier 20
# maximum-paths 200
# passive-interface Eth1/2 3.3.3.3
# passive-interface Eth1/3
# !
# sonic#
# sonic# show running-configuration vrf Vrf_1
# !
# ip vrf Vrf_1
# sonic# show running-configuration ip prefix-list
# !
# ip prefix-list PRF_LIST seq 1 permit 1.1.1.1/24
# ip prefix-list PRF_LIST2 seq 1 permit 1.1.1.1/24
# sonic# show running-configuration route-map
# !
# route-map RMAP permit 1
# sonic#

- name: Delete the OSPFv2 configurations
  sonic_ospf:
    config:
      - vrf_name: 'default'
        router_id: "20.20.20.20"
        distance:
          external: 20
        default_passive: false
        maximum_paths: 200
        passive_interfaces:
          interfaces:
            - interface: 'Eth1/3'
        redistribute:
          - protocol: "bgp"
            metric: 15
            metric_type: 2
            route_map: "RMAP"
        refresh_timer: 300
      - vrf_name: "Vrf_1"
        timers:
          throttle_spf:
            delay_time: 50
            initial_hold_time: 20
            maximum_hold_time: 10
        default_metric: 100
        max_metric:
          external_lsa_all: 2
        non_passive_interfaces:
          interfaces:
            - interface: "Eth1/2"
              addresses:
                - "2.2.2.2"
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration ospf
# router ospf vrf Vrf_1
# passive-interface default
# timers throttle lsa all 300
# no passive-interface Eth1/1 2.2.2.2
# no passive-interface Eth1/2 2.2.2.2
# !
# router ospf
# distance 30
# write-multiplier 20
# passive-interface Eth1/2 3.3.3.3
# !
# sonic#


# Using "deleted" state

# Before state:
# -------------
#
# sonic# show running-configuration ospf
# router ospf vrf Vrf_1
# passive-interface default
# timers throttle lsa all 300
# no passive-interface Eth1/1 2.2.2.2
# no passive-interface Eth1/2 2.2.2.2
# !
# router ospf
# distance 30
# write-multiplier 20
# passive-interface Eth1/2 3.3.3.3
# !
# sonic#
# sonic# show running-configuration vrf Vrf_1
# !
# ip vrf Vrf_1
# sonic# show running-configuration ip prefix-list
# !
# ip prefix-list PRF_LIST seq 1 permit 1.1.1.1/24
# ip prefix-list PRF_LIST2 seq 1 permit 1.1.1.1/24
# sonic# show running-configuration route-map
# !
# route-map RMAP permit 1
# sonic#

- name: Delete the OSPFv2 configurations
  sonic_ospf:
    config:
      - vrf_name: "Vrf_1"
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration ospf
# router ospf
# distance 30
# write-multiplier 20
# passive-interface Eth1/2 3.3.3.3
# !
# sonic#


# Using "merged" state

# Before state:
# -------------
#
# sonic# show running-configuration ospf
# (No ospf configuration present)
# sonic# show running-configuration vrf Vrf_1
# !
# ip vrf Vrf_1
# sonic# show running-configuration ip prefix-list
# !
# ip prefix-list PRF_LIST seq 1 permit 1.1.1.1/24
# ip prefix-list PRF_LIST2 seq 1 permit 1.1.1.1/24
# sonic# show running-configuration route-map
# !
# route-map RMAP permit 1
# sonic#

- name: Add the OSPFv2 configurations
  sonic_ospf:
    config:
      - vrf_name: 'default'
        router_id: "10.10.10.10"
        distance:
          external: 20
        auto_cost_reference_bandwidth: 100
      - vrf_name: "Vrf_1"
        timers:
          throttle_lsa_all: 300
          throttle_spf:
            delay_time: 10
            initial_hold_time: 20
            maximum_hold_time: 50
        redistribute:
          - protocol: "bgp"
            metric: 15
            metric_type: 2
            route_map: "RMAP"
        default_passive: true
        non_passive_interfaces:
          interfaces:
            - interface: "Eth1/1"
              addresses:
                - "2.2.2.2"
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration ospf
# router ospf vrf Vrf_1
# passive-interface default
# timers throttle spf 10 20 50
# timers throttle lsa all 300
# redistribute bgp metric 15 metric-type 2 route-map RMAP
# no passive-interface Eth1/1 2.2.2.2
# !
# router ospf
# auto-cost reference-bandwidth 100
# ospf router-id 10.10.10.10
# distance ospf external 20
# !
# sonic#


# Using "merged" state

# Before state:
# -------------
#
# sonic# show running-configuration ospf
# router ospf vrf Vrf_1
# passive-interface default
# timers throttle spf 10 20 50
# timers throttle lsa all 300
# redistribute bgp metric 15 metric-type 2 route-map RMAP
# no passive-interface Eth1/1 2.2.2.2
# !
# router ospf
# ospf router-id 10.10.10.10
# distance ospf external 20
# !
# sonic#
# sonic# show running-configuration vrf Vrf_1
# !
# ip vrf Vrf_1
# sonic# show running-configuration ip prefix-list
# !
# ip prefix-list PRF_LIST seq 1 permit 1.1.1.1/24
# ip prefix-list PRF_LIST2 seq 1 permit 1.1.1.1/24
# sonic# show running-configuration route-map
# !
# route-map RMAP permit 1
# sonic#

- name: Add the OSPFv2 configurations
  sonic_ospf:
    config:
      - vrf_name: 'default'
        write_multiplier: 20
        router_id: "20.20.20.20"
        distance:
          all: 30
        default_passive: false
        graceful_restart:
          enable: true
          grace_period: 100
          helper:
            enable: true
            planned_only: true
            advertise_router_id:
              - '1.1.1.1'
              - '2.2.2.2'
        passive_interfaces:
          interfaces:
            - interface: 'Eth1/2'
              addresses:
                - '3.3.3.3'
            - interface: 'Eth1/3'
        log_adjacency_changes: 'detail'
      - vrf_name: "Vrf_1"
        timers:
          throttle_spf:
            delay_time: 50
            initial_hold_time: 20
            maximum_hold_time: 10
        max_metric:
          external_lsa_all: 30
        log_adjacency_changes: 'brief'
        default_passive: true
        non_passive_interfaces:
          interfaces:
            - interface: "Eth1/2"
              addresses:
                - "2.2.2.2"
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration ospf
# router ospf vrf Vrf_1
# log-adjacency-changes
# max-metric router-lsa external-lsa all 30
# passive-interface default
# timers throttle spf 50 20 10
# timers throttle lsa all 300
# redistribute bgp metric 15 metric-type 2 route-map RMAP
# no passive-interface Eth1/1 2.2.2.2
# no passive-interface Eth1/2 2.2.2.2
# !
# router ospf
# ospf router-id 20.20.20.20
# distance 30
# distance ospf external 20
# log-adjacency-changes detail
# graceful-restart grace-period 100
# graceful-restart helper enable
# graceful-restart helper planned-only
# graceful-restart helper enable 1.1.1.1
# graceful-restart helper enable 2.2.2.2
# write-multiplier 20
# passive-interface Eth1/2 3.3.3.3
# passive-interface Eth1/3
# !
# sonic#


# Using "replaced" state

# Before state:
# -------------
#
# sonic# show running-configuration ospf
# router ospf vrf Vrf_1
# max-metric router-lsa external-lsa all 2
# passive-interface default
# timers throttle spf 50 20 10
# timers throttle lsa all 300
# redistribute bgp metric 15 metric-type 2 route-map RMAP
# no passive-interface Eth1/1 2.2.2.2
# no passive-interface Eth1/2 2.2.2.2
# !
# router ospf
# ospf router-id 20.20.20.20
# distance 30
# distance ospf external 20
# write-multiplier 20
# passive-interface Eth1/2 3.3.3.3
# passive-interface Eth1/3
# !
# sonic#
# sonic# show running-configuration vrf Vrf_1
# !
# ip vrf Vrf_1
# sonic# show running-configuration ip prefix-list
# !
# ip prefix-list PRF_LIST seq 1 permit 1.1.1.1/24
# ip prefix-list PRF_LIST2 seq 1 permit 1.1.1.1/24
# sonic# show running-configuration route-map
# !
# route-map RMAP permit 1
# route-map RMAP2 permit 2
# sonic#

- name: Replace the OSPFv2 vrf default configurations
  sonic_ospf:
    config:
      - vrf_name: 'default'
        router_id: "20.20.20.20"
        redistribute:
          - protocol: "connected"
            metric: 15
            metric_type: 2
            route_map: "RMAP2"
          - protocol: "default_route"
            always: true
            route_map: "RMAP"
        distance:
          all: 20
        abr_type: cisco
        opaque_lsa_capability: true
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration ospf
# router ospf vrf Vrf_1
# max-metric router-lsa external-lsa all 2
# passive-interface default
# timers throttle spf 50 20 10
# timers throttle lsa all 300
# redistribute bgp metric 15 metric-type 2 route-map RMAP
# no passive-interface Eth1/1 2.2.2.2
# no passive-interface Eth1/2 2.2.2.2
# !
# router ospf
# capability opaque
# ospf router-id 20.20.20.20
# default-information originate always route-map RMAP
# distance 20
# ospf abr-type cisco
# redistribute connected metric 15 metric-type 2 route-map RMAP2
# !


# Using "overridden" state

# Before state:
# -------------
#
# sonic# show running-configuration ospf
# router ospf vrf Vrf_1
# max-metric router-lsa external-lsa all 2
# passive-interface default
# timers throttle spf 50 20 10
# timers throttle lsa all 300
# redistribute bgp metric 15 metric-type 2 route-map RMAP
# no passive-interface Eth1/1 2.2.2.2
# no passive-interface Eth1/2 2.2.2.2
# !
# router ospf
# ospf router-id 20.20.20.20
# distance 30
# distance ospf external 20
# write-multiplier 20
# passive-interface Eth1/2 3.3.3.3
# passive-interface Eth1/3
# !
# sonic#
# sonic# show running-configuration vrf Vrf_1
# !
# ip vrf Vrf_1
# sonic# show running-configuration ip prefix-list
# !
# ip prefix-list PRF_LIST seq 1 permit 1.1.1.1/24
# ip prefix-list PRF_LIST2 seq 1 permit 1.1.1.1/24
# sonic# show running-configuration route-map
# !
# route-map RMAP permit 1
# route-map RMAP2 permit 2
# sonic#

- name: Override the OSPFv2 configurations
  sonic_ospf:
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
        rfc1583_compatible: true
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration ospf
# router ospf
# compatible rfc1583
# ospf router-id 20.20.20.20
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ospfv2.ospfv2 import Ospfv2Args
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.ospfv2.ospfv2 import Ospfv2


def main():
    """
    Main entry point for module execution

    :returns: the result from module invocation
    """
    module = AnsibleModule(argument_spec=Ospfv2Args.argument_spec,
                           supports_check_mode=True)

    result = Ospfv2(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
