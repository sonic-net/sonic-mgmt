#!/usr/bin/python
# -*- coding: utf-8 -*-
# © Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_bgp
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_bgp
version_added: 1.0.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
author: Dhivya P (@dhivayp)
short_description: Manage global BGP and its parameters
description:
  - This module provides configuration management of global BGP parameters on devices running Enterprise SONiC Distribution by Dell Technologies.
options:
  config:
    description:
      - Specifies the BGP-related configuration.
    type: list
    elements: dict
    suboptions:
      bgp_as:
        description:
          - Specifies the BGP autonomous system (AS) number to configure on the device.
        type: str
        required: true
      vrf_name:
        description:
          - Specifies the VRF name.
        type: str
        default: 'default'
      router_id:
        description:
          - Configures the BGP routing process router-id value.
        type: str
      log_neighbor_changes:
        description:
          - Enables/disables logging neighbor up/down and reset reason.
        type: bool
      as_notation:
        description:
          - Specify the AS number notation format
          - Option supported on Enterprise-Sonic releases 4.4.0 and higher.
        choices: ['asdot', 'asdot+']
        type: str
      max_med:
        description:
          - Configure max med and its parameters
        type: dict
        suboptions:
          on_startup:
            description:
              - On startup time and max-med value
            type: dict
            suboptions:
              timer:
                description:
                  - Configures on startup time
                type: int
              med_val:
                description:
                  - on startup med value
                type: int
      timers:
        description:
          - Adjust routing timers
        type: dict
        suboptions:
          holdtime:
            description:
              - Configures hold-time
            type: int
          keepalive_interval:
            description:
              - Configures keepalive-interval
            type: int
      graceful_restart:
        version_added: 3.1.0
        description:
          - Configure graceful restart
        type: dict
        suboptions:
          enabled:
            description:
              - Enable graceful restart
            type: bool
          restart_time:
            description:
              - Configures restart-time.
              - The range is from 1 to 3600.
            type: int
          stale_routes_time:
            description:
              - Configures stale-routes-time.
              - The range is from 1 to 3600.
            type: int
          preserve_fw_state:
            description:
              - Configures preserve-fw-state
            type: bool
      bestpath:
        description:
          - Configures the BGP best-path.
        type: dict
        suboptions:
          as_path:
            description:
              - Configures the as-path values.
            type: dict
            suboptions:
              confed:
                description:
                  - Configures the confed values of as-path.
                type: bool
              ignore:
                description:
                  - Configures the ignore values of as-path.
                type: bool
              multipath_relax:
                description:
                  - Configures the multipath_relax values of as-path.
                type: bool
              multipath_relax_as_set:
                description:
                  - Configures the multipath_relax_as_set values of as-path.
                type: bool
          bandwidth:
            version_added: 3.1.0
            description:
              - Link Bandwidth attribute for the bestpath selection process
              - Options are as follows
              - default_weight - Assign a low default weight (value 1) to paths not having link bandwidth
              - ignore_weight - Ignore link bandwidth (i.e., do regular ECMP, not weighted)
              - skip_missing - Ignore paths without link bandwidth for ECMP (if other paths have it)
            choices: ['default_weight', 'ignore_weight', 'skip_missing']
            type: str
          compare_routerid:
            description:
              - Configures the compare_routerid.
            type: bool
          med:
            description:
              - Configures the med values.
            type: dict
            suboptions:
              confed:
                description:
                  - Configures the confed values of med.
                type: bool
              missing_as_worst:
                description:
                  - Configures the missing_as_worst values of as-path.
                type: bool
              always_compare_med:
                description:
                  - Allows comparing meds from different neighbors if set to true
                type: bool
      rt_delay:
        description:
          - Time in seconds to wait before processing route-map changes.
          - Range is 0-600. 0 disables the timer and changes to route-map will not be updated.
        type: int
  state:
    description:
      - Specifies the operation to be performed on the BGP process that is configured on the device.
      - In case of merged, the input configuration is merged with the existing BGP configuration on the device.
      - In case of deleted, the existing BGP configuration is removed from the device.
      - In case of replaced, the existing configuration of the specified BGP AS will be replaced with provided configuration.
      - In case of overridden, the existing BGP configuration will be overridden with the provided configuration.
    default: merged
    choices: ['merged', 'deleted', 'replaced', 'overridden']
    type: str
"""

EXAMPLES = """
# Using "deleted" state
#
# Before state:
# -------------
#
# !
# router bgp 10 vrf VrfCheck1
#  router-id 10.2.2.32
#  route-map delay-timer 20
#  log-neighbor-changes
# !
# router bgp 11 vrf VrfCheck2
#  log-neighbor-changes
#  bestpath as-path ignore
#  bestpath med missing-as-worst confed
#  bestpath compare-routerid
# !
# router bgp 4
#  router-id 10.2.2.4
#  graceful-restart enable
#  graceful-restart restart-time 1
#  graceful-restart stalepath-time 500
#  route-map delay-timer 10
#  bestpath as-path ignore
#  bestpath as-path confed
#  bestpath med missing-as-worst confed
#  bestpath compare-routerid
#  bestpath bandwidth default-weight
# !
#
- name: Delete BGP Global attributes
  dellemc.enterprise_sonic.sonic_bgp:
    config:
      - bgp_as: 4
        router_id: 10.2.2.4
        rt_delay: 10
        log_neighbor_changes: false
        graceful_restart:
          stale_routes_time: 500
          restart_time: 1
        bestpath:
          as_path:
            confed: true
            ignore: true
            multipath_relax: false
            multipath_relax_as_set: true
          bandwidth: default_weight
          compare_routerid: true
          med:
            confed: true
            missing_as_worst: true
      - bgp_as: 10
        router_id: 10.2.2.32
        rt_delay: 20
        log_neighbor_changes: true
        vrf_name: 'VrfCheck1'
      - bgp_as: 11
        log_neighbor_changes: true
        vrf_name: 'VrfCheck2'
        bestpath:
          as_path:
            confed: false
            ignore: true
            multipath_relax_as_set: true
          compare_routerid: true
          med:
            confed: true
            missing_as_worst: true
    state: deleted


# After state:
# ------------
#
# !
# router bgp 10 vrf VrfCheck1
#  log-neighbor-changes
# !
# router bgp 11 vrf VrfCheck2
#  log-neighbor-changes
#  bestpath compare-routerid
# !
# router bgp 4
#  graceful-restart enable
#  log-neighbor-changes
#  bestpath compare-routerid
# !


# Using "deleted" state
#
# Before state:
# -------------
#
# !
# router bgp 10 vrf VrfCheck1
#  router-id 10.2.2.32
#  route-map delay-timer 20
#  log-neighbor-changes
# !
# router bgp 11 vrf VrfCheck2
#  graceful-restart enable
#  log-neighbor-changes
#  bestpath as-path ignore
#  bestpath med missing-as-worst confed
#  bestpath compare-routerid
#  bestpath bandwidth ignore-weight
# !
# router bgp 4
#  router-id 10.2.2.4
#  route-map delay-timer 10
#  bestpath as-path ignore
#  bestpath as-path confed
#  bestpath med missing-as-worst confed
#  bestpath compare-routerid
# !

- name: Deletes all the bgp global configurations
  dellemc.enterprise_sonic.sonic_bgp:
    config:
    state: deleted

# After state:
# ------------
#
# !
# !


# Using "merged" state
#
# Before state:
# -------------
#
# !
# router bgp 4
#  router-id 10.1.1.4
# !
#
- name: Merges provided configuration with device configuration
  dellemc.enterprise_sonic.sonic_bgp:
    config:
      - bgp_as: 4
        router_id: 10.2.2.4
        rt_delay: 10
        log_neighbor_changes: false
        graceful_restart:
          enabled: true
          preserve_fw_state: true
        timers:
          holdtime: 20
          keepalive_interval: 30
        bestpath:
          as_path:
            confed: true
            ignore: true
            multipath_relax: false
            multipath_relax_as_set: true
          bandwidth: ignore-weight
          compare_routerid: true
          med:
            confed: true
            missing_as_worst: true
            always_compare_med: true
        max_med:
          on_startup:
            timer: 667
            med_val: 7878
      - bgp_as: 10
        router_id: 10.2.2.32
        rt_delay: 20
        log_neighbor_changes: true
        vrf_name: 'VrfCheck1'
      - bgp_as: 11
        log_neighbor_changes: true
        vrf_name: 'VrfCheck2'
        bestpath:
          as_path:
            confed: false
            ignore: true
            multipath_relax_as_set: true
          compare_routerid: true
          med:
            confed: true
            missing_as_worst: true
    state: merged

#
# After state:
# ------------
#
# !
# router bgp 10 vrf VrfCheck1
#  router-id 10.2.2.32
#  route-map delay-timer 20
#  log-neighbor-changes
# !
# router bgp 11 vrf VrfCheck2
#  log-neighbor-changes
#  bestpath as-path ignore
#  bestpath med missing-as-worst confed
#  bestpath compare-routerid
# !
# router bgp 4
#  router-id 10.2.2.4
#  graceful-restart enable
#  graceful-restart preserve-fw-state
#  route-map delay-timer 10
#  bestpath as-path ignore
#  bestpath as-path confed
#  bestpath med missing-as-worst confed
#  bestpath compare-routerid
#  bestpath bandwidth ignore-weight
#  always-compare-med
#  max-med on-startup 667 7878
#  timers 20 30
#
# !


# Using "replaced" state
#
# Before state:
# -------------
#
# !
# router bgp 10 vrf VrfCheck1
#  router-id 10.2.2.32
#  log-neighbor-changes
#  timers 60 180
# !
# router bgp 4
#  router-id 10.2.2.4
#  max-med on-startup 667 7878
#  bestpath as-path ignore
#  bestpath as-path confed
#  bestpath med missing-as-worst confed
#  bestpath compare-routerid
#  bestpath bandwidth default-weight
#  timers 20 30
# !
#

- name: Replace device configuration of specified BGP AS with provided
  dellemc.enterprise_sonic.sonic_bgp:
    config:
      - bgp_as: 4
        router_id: 10.2.2.44
        log_neighbor_changes: true
        bestpath:
          as_path:
            confed: true
          bandwidth: skip_missing
          compare_routerid: true
      - bgp_as: 11
        vrf_name: 'VrfCheck2'
        router_id: 10.2.2.33
        log_neighbor_changes: true
        bestpath:
          as_path:
            confed: true
            ignore: true
          compare_routerid: true
          med:
            confed: true
            missing_as_worst: true
    state: replaced

#
# After state:
# ------------
#
# !
# router bgp 10 vrf VrfCheck1
#  router-id 10.2.2.32
#  log-neighbor-changes
#  timers 60 180
# !
# router bgp 11 vrf VrfCheck2
#  router-id 10.2.2.33
#  log-neighbor-changes
#  bestpath as-path ignore
#  bestpath as-path confed
#  bestpath med missing-as-worst confed
#  bestpath compare-routerid
#  timers 60 180
# !
# router bgp 4
#  router-id 10.2.2.44
#  log-neighbor-changes
#  bestpath as-path confed
#  bestpath compare-routerid
#  bestpath bandwidth skip_missing
#  timers 60 180
# !


# Using "overridden" state
#
# Before state:
# -------------
#
# !
# router bgp 10 vrf VrfCheck1
#  router-id 10.2.2.32
#  log-neighbor-changes
#  timers 60 180
# !
# router bgp 4
#  router-id 10.2.2.4
#  max-med on-startup 667 7878
#  bestpath as-path ignore
#  bestpath as-path confed
#  bestpath med missing-as-worst confed
#  bestpath compare-routerid
#  bestpath bandwidth default-weight
#  timers 20 30
# !
#

- name: Override device configuration of global BGP with provided configuration
  dellemc.enterprise_sonic.sonic_bgp:
    config:
      - bgp_as: 4
        router_id: 10.2.2.44
        log_neighbor_changes: true
        bestpath:
          as_path:
            confed: true
          compare_routerid: true
      - bgp_as: 11
        vrf_name: 'VrfCheck2'
        router_id: 10.2.2.33
        log_neighbor_changes: true
        bestpath:
          as_path:
            confed: true
            ignore: true
          compare_routerid: true
        timers:
          holdtime: 90
          keepalive_interval: 30
    state: overridden

#
# After state:
# ------------
#
# !
# router bgp 11 vrf VrfCheck2
#  router-id 10.2.2.33
#  log-neighbor-changes
#  bestpath as-path ignore
#  bestpath as-path confed
#  bestpath compare-routerid
#  timers 30 90
# !
# router bgp 4
#  router-id 10.2.2.44
#  log-neighbor-changes
#  bestpath as-path confed
#  bestpath compare-routerid
#  timers 60 180
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
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.bgp.bgp import BgpArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.bgp.bgp import Bgp


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=BgpArgs.argument_spec,
                           supports_check_mode=True)

    result = Bgp(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
