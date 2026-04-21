#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_ospfv3_area
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_ospfv3_area
version_added: "3.1.0"
notes:
  - Supports C(check_mode).
  - Tested against Enterprise SONiC Distribution by Dell Technologies.
short_description: Configure OSPFv3 area settings on SONiC.
description:
  - This module provides configuration for the area settings of OSPFv3 running on SONiC switches.
  - Configure global/VRF OSPFv3 instance before configuring OSPFv3 areas.
  - Configure OSPFv3 instance before configuring OSPFv3 areas.
author: "Santhosh kumar T (@santhosh-kt)"
options:
  config:
    description:
      - Specifies configuration for OSPFv3 areas.
      - I(stub) and I(nssa) are mutually exclusive.
      - If I(area_id=0 or 0.0.0.0), I(stub/nssa) should not be specified.
    type: list
    elements: dict
    suboptions:
      area_id:
        type: str
        required: true
        description:
          - Area ID of the network (A.B.C.D or 0 to 4294967295).
      filter_list_in:
        type: str
        description:
          - Inter-area prefix filter list.
          - Filter incoming prefixes into the area.
          - Expects name of a prefix list.
      filter_list_out:
        type: str
        description:
          - Inter-area prefix filter list.
          - Filter outgoing prefixes from the area.
          - Expects name of a prefix list.
      nssa:
        type: dict
        description:
          - Configuration for NSSA type area.
          - I(default_originate) and I(no_summary) are mutually exclusive.
        suboptions:
          default_originate:
            type: dict
            description:
              - Advertise default route for the NSSA area.
            suboptions:
              enabled:
                type: bool
                description:
                  - Enable to advertise the default route for the NSSA area.
                required: true
              metric:
                type: int
                description:
                  - Configure metric for the redistributed route (0 to 16777214).
              metric_type:
                type: int
                description:
                  - Configure metric type for the redistributed route.
                choices: [1, 2]
          enabled:
            type: bool
            description:
              - Configure area as NSSA type area.
            required: true
          no_summary:
            type: bool
            description:
              - Disable inter-area route injection into the NSSA.
          ranges:
            type: list
            elements: dict
            description:
              - Configure address range summarization on border routers.
            suboptions:
              prefix:
                type: str
                required: true
                description:
                  - Configure address range prefix.
              advertise:
                type: bool
                description:
                  - Enable address range advertising.
                  - Default value while creating a new range is True.
                  - If the I(cost) is specified, I(advertise) is unconditionally set to True during playbook execution.
              cost:
                type: int
                description:
                  - Configure cost of address range (0 to 16777215).
      ranges:
        type: list
        elements: dict
        description:
          - Configure address range summarization on border routers.
        suboptions:
          prefix:
            type: str
            required: true
            description:
              - Configure address range prefix.
          advertise:
            type: bool
            description:
              - Enable address range advertising.
              - Default value while creating a new range is True.
              - If the I(cost) is specified, I(advertise) is unconditionally set to True during playbook execution.
          cost:
            type: int
            description:
              - Configure cost of address range (0 to 16777215).
      stub:
        type: dict
        description:
          - Configuration for STUB type area.
        suboptions:
          enabled:
            type: bool
            description:
              - Configure area as STUB type area.
            required: true
          no_summary:
            type: bool
            description:
              - Disable inter-area route injection into the STUB.
      vrf_name:
        type: str
        required: true
        description:
          - Name of the VRF this area belongs to.
  state:
    description:
      - Specifies the type of configuration update to be performed on the device.
    type: str
    choices:
      - merged
      - replaced
      - overridden
      - deleted
    default: merged
"""

EXAMPLES = """
# Using "deleted" state
#
# Before state:
# -------------
# sonic(config-router-ospfv3)# show configuration
# !
# router ospfv3 vrf Vrf1
#  area 0.0.0.1 stub no-summary
#  area 0.0.0.1 filter-list prefix pf1 in
#  area 0.0.0.1 filter-list prefix pf2 out
#  area 0.0.0.2 stub no-summary
#  area 0.0.0.1 range 1::1/64 not-advertise
#  area 0.0.0.1 range 1::2/64
#  area 0.0.0.2 range 1::1/64
#  area 0.0.0.3 range 1::3/24 cost 14
# sonic(config-router-ospfv3)#

- name: "test delete all settings for areas"
  dellemc.enterprise_sonic.sonic_ospfv3_area:
    state: deleted
    config:
      - area_id: 0.0.0.1
        vrf_name: Vrf1
      - area_id: 0.0.0.2
        vrf_name: Vrf1
        ranges:
          - prefix: 1::1/64
            advertise: true
        stub:
          enabled: true
          no_summary: true

# After state
# -------------
# sonic(config-router-ospfv3)# show configuration
# !
# router ospfv3 vrf Vrf1
#  area 0.0.0.3 range 1::3/24 cost 14
# sonic(config-router-ospfv3)#


# Using "deleted" state
# Before state:
# -------------
# sonic(config-router-ospfv3)# show configuration
# !
# router ospfv3 vrf Vrf1
#  area 0.0.0.1 nssa no-summary
#  area 0.0.0.3 filter-list prefix pf1 in
#  area 0.0.0.1 nssa
#  area 0.0.0.4 stub no-summary
#  area 0.0.0.1 nssa range 1::1/64
#  area 0.0.0.1 nssa range 1::2/64 cost 20
#  area 0.0.0.2 range 1::1/64 not-advertise
#  area 0.0.0.2 range 1::2/64 advertise cost 4
#  area 0.0.0.2 range 1::3/24 not-advertise
# sonic(config-router-ospfv3)#

- name: "test clear subsections"
  dellemc.enterprise_sonic.sonic_ospfv3_area:
    state: deleted
    config:
      - area_id: 0.0.0.1
        vrf_name: Vrf1
        nssa:
          enabled: true
          ranges: []
      - area_id: 0.0.0.2
        vrf_name: Vrf1
        ranges: []
      - area_id: 4
        vrf_name: Vrf1

# After state
# -------------
# sonic(config-router-ospfv3)# show configuration
# !
# router ospfv3 vrf Vrf1
#  area 0.0.0.1 nssa no-summary
#  area 0.0.0.3 filter-list prefix pf1 in
#  area 0.0.0.1 nssa
# sonic(config-router-ospfv3)#


# Using "deleted" state
# Before state:
# -------------
# sonic# show running-configuration ospfv3
# !
# router ospfv3 vrf Vrf1
#  area 0.0.0.1 nssa no-summary
#  area 0.0.0.1 filter-list prefix pf1 in
#  area 0.0.0.1 filter-list prefix pf2 out
#  area 0.0.0.3 filter-list prefix pf1 in
#  area 0.0.0.1 nssa
#  area 0.0.0.4 stub no-summary
#  area 0.0.0.1 nssa range 1::1/64
#  area 0.0.0.1 nssa range 1::2/64 cost 20
#  area 0.0.0.2 range 1::1/64 not-advertise
#  area 0.0.0.2 range 1::2/64 advertise cost 4
#  area 0.0.0.2 range 1::3/24 not-advertise
# router ospfv3
#  area 0.0.0.1 nssa no-summary
#  area 0.0.0.1 filter-list prefix pf1 in
#  area 0.0.0.1 filter-list prefix pf2 out
#  area 0.0.0.3 filter-list prefix pf1 in
#  area 0.0.0.1 nssa
#  area 0.0.0.4 stub no-summary
#  area 0.0.0.1 nssa range 1::1/64
#  area 0.0.0.1 nssa range 1::2/64 cost 20
#  area 0.0.0.2 range 1::1/64 not-advertise
#  area 0.0.0.2 range 1::2/64 advertise cost 4
#  area 0.0.0.2 range 1::3/24 not-advertise
# sonic#

- name: "test clear subsections"
  dellemc.enterprise_sonic.sonic_ospfv3_area:
    state: deleted
    config:
      - area_id: 0.0.0.1
        vrf_name: Vrf1
        filter_list_in: pf1
        filter_list_out: pf2
        nssa:
          enabled: true
          range:
            - prefix: 1::2/64
              advertise: true
              cost: 20
      - area_id: 0.0.0.2
        vrf_name: Vrf1
        range:
          - prefix: 1::2/64
      - area_id: 3
        vrf_name: default
      - area_id: 4
        vrf_name: default
        stub:
          enabled: true
          no_summary: true

# After state
# -------------
# sonic# show running-configuration ospfv3
# !
# router ospfv3 vrf Vrf1
#  area 0.0.0.1 nssa no-summary
#  area 0.0.0.3 filter-list prefix pf1 in
#  area 0.0.0.1 nssa
#  area 0.0.0.4 stub no-summary
#  area 0.0.0.1 nssa range 1::1/64
#  area 0.0.0.2 range 1::1/64 not-advertise
#  area 0.0.0.2 range 1::3/24 not-advertise
# router ospfv3
#  area 0.0.0.1 nssa no-summary
#  area 0.0.0.1 filter-list prefix pf1 in
#  area 0.0.0.1 filter-list prefix pf2 out
#  area 0.0.0.1 nssa
#  area 0.0.0.4
#  area 0.0.0.1 nssa range 1::1/64
#  area 0.0.0.1 nssa range 1::2/64 cost 20
#  area 0.0.0.2 range 1::1/64 not-advertise
#  area 0.0.0.2 range 1::2/64 advertise cost 4
#  area 0.0.0.2 range 1::3/24 not-advertise
# sonic#


# Using "merged" state
# Before state:
# -------------
# sonic# show running-configuration ospfv3
# !
# router ospfv3 vrf Vrf2
# !
# router ospfv3 vrf Vrf1
# sonic#

- name: merge examples of all settings
  dellemc.enterprise_sonic.sonic_ospfv3_area:
    state: merged
    config:
      - area_id: 1
        vrf_name: Vrf1
      - area_id: 2
        vrf_name: Vrf1
        stub:
          enabled: true
          no_summary: true
      - area_id: 3
        vrf_name: Vrf1
        filter_list_in: pf1
        filter_list_out: pf2
        ranges:
          - prefix: 1::1/64
          - prefix: 1::2/64
            advertise: true
            cost: 4
          - prefix: 1::3/24
            advertise: false
          - prefix: 1::4/24
            advertise: true
            cost: 10
      - area_id: 4
        vrf_name: Vrf1
      - area_id: 5
        vrf_name: Vrf2

# After state
# -------------
# sonic# show running-configuration ospfv3
#
# outer ospfv3 vrf Vrf1
# area 0.0.0.1
# area 0.0.0.2 stub no-summary
# area 0.0.0.3 filter-list prefix pf1 in
# area 0.0.0.3 filter-list prefix pf2 out
# area 0.0.0.4
# area 0.0.0.3 range 1::1/64
# area 0.0.0.3 range 1::2/64 advertise cost 4
# area 0.0.0.3 range 1::3/24 not-advertise
# area 0.0.0.3 range 1::4/24 advertise cost 10
# !
# router ospfv3 vrf Vrf2
#  area 0.0.0.5
# sonic#


# Using "merged" state
# Before state:
# -------------
# sonic(config-router-ospfv3)# show configuration
# !
# router ospfv3 vrf Vrf2
# sonic(config-router-ospfv3)# show configuration
# !
# router ospfv3 vrf Vrf1
# sonic(config-router-ospfv3)#

- name: merge smallest group of settings
  dellemc.enterprise_sonic.sonic_ospfv3_area:
    state: merged
    config:
      - area_id: 0.0.0.1
        vrf_name: Vrf1
      - area_id: 0.0.0.2
        vrf_name: Vrf1
        nssa:
          enabled: true
          no_summary: true
      - area_id: 0.0.0.3
        vrf_name: Vrf1
        ranges:
          - prefix: 1::1/64
        nssa:
          enabled: true
          default_originate:
            enabled: true
      - area_id: 0.0.0.4
        vrf_name: Vrf2
        stub:
          enabled: true
      - area_id: 0.0.0.5
        vrf_name: Vrf2
        filter_list_in: pf1
        filter_list_out: pf2

# After state
# -------------
# sonic(config-router-ospfv3)# show configuration
# !
# router ospfv3 vrf Vrf1
#  area 0.0.0.1
#  area 0.0.0.2 nssa no-summary
#  area 0.0.0.3 range 1::1/64
#  area 0.0.0.3 nssa default-information-originate
# sonic(config-router-ospfv3)# router ospfv3 vrf Vrf2
# sonic(config-router-ospfv3)# show configuration
# !
# router ospfv3 vrf Vrf2
#  area 0.0.0.4 stub
#  area 0.0.0.5 filter-list prefix pf1 in
#  area 0.0.0.5 filter-list prefix pf2 out
# sonic(config-router-ospfv3)#


# Using "merged" state
# Before state:
# -------------
# sonic(config-router-ospfv3)# show configuration
# !
# router ospfv3 vrf Vrf1
#  area 0.0.0.1 stub no-summary
#  area 0.0.0.1 filter-list prefix pf1 in
#  area 0.0.0.1 filter-list prefix pf2 out
#  area 0.0.0.1 range 1::1/64 not-advertise
#  area 0.0.0.1 range 1::2/64 advertise
# sonic(config-router-ospfv3)#

- name: "test merge all settings"
  dellemc.enterprise_sonic.sonic_ospfv3_area:
    state: merged
    config:
      - area_id: 0.0.0.1
        vrf_name: Vrf1
        filter_list_in: pf2
        filter_list_out: pf1
        ranges:
          - prefix: 1::1/64
            advertise: true
            cost: 12
          - prefix: 1::2/64
            advertise: false
        stub:
          enabled: true
          no_summary: false

# After state
# -------------
# sonic(config-router-ospfv3)# show configuration
# !
# router ospfv3 vrf Vrf1
#  area 0.0.0.1 stub
#  area 0.0.0.1 filter-list prefix pf2 in
#  area 0.0.0.1 filter-list prefix pf1 out
#  area 0.0.0.1 range 1::1/64 advertise cost 12
#  area 0.0.0.1 range 1::2/64 not-advertise
# sonic(config-router-ospfv3)#


# Using "replaced" state
# Before state:
# -------------
# sonic# show running-configuration ospfv3
# !
# router ospfv3 vrf Vrf1
#  area 0.0.0.1 nssa no-summary
#  area 0.0.0.1 filter-list prefix pf1 in
#  area 0.0.0.1 filter-list prefix pf2 out
#  area 0.0.0.3 filter-list prefix pf1 in
#  area 0.0.0.1 nssa
#  area 0.0.0.4 stub no-summary
#  area 0.0.0.1 nssa range 1::1/64
#  area 0.0.0.1 nssa range 1::2/64 cost 20
#  area 0.0.0.2 range 1::1/64 not-advertise
#  area 0.0.0.2 range 1::2/64 advertise cost 4
#  area 0.0.0.2 range 1::3/24 not-advertise
# router ospfv3
#  area 0.0.0.1 nssa no-summary
#  area 0.0.0.1 filter-list prefix pf1 in
#  area 0.0.0.1 filter-list prefix pf2 out
#  area 0.0.0.3 filter-list prefix pf1 in
#  area 0.0.0.1 nssa
#  area 0.0.0.4 stub no-summary
#  area 0.0.0.1 nssa range 1::1/64
#  area 0.0.0.1 nssa range 1::2/64 cost 20
#  area 0.0.0.2 range 1::1/64 not-advertise
#  area 0.0.0.2 range 1::2/64 advertise cost 4
#  area 0.0.0.2 range 1::3/24 not-advertise
# sonic#

- name: "replace areas"
  dellemc.enterprise_sonic.sonic_ospfv3_area:
    state: replaced
    config:
      - area_id: 0.0.0.1
        vrf_name: Vrf1
      - area_id: 0.0.0.5
        vrf_name: Vrf1
        nssa:
          enabled: true
          default_originate:
            enabled: true
            metric: 10
            metric_type: 1
          ranges:
            - prefix: "1::1/64"
              cost: 15
      - area_id: 0.0.0.4
        vrf_name: Vrf1
        stub:
          no_summary: true
          enabled: true

# After state
# -------------
# sonic# show running-configuration ospfv3
# !
# router ospfv3 vrf Vrf1
#  area 0.0.0.1
#  area 0.0.0.4 stub no-summary
#  area 0.0.0.5 nssa nssa default-information-originate metric 10 metric-type 1
#  area 0.0.0.5 nssa range 1::1/64 cost 15
# router ospfv3
#  area 0.0.0.1 nssa no-summary
#  area 0.0.0.1 filter-list prefix pf1 in
#  area 0.0.0.1 filter-list prefix pf2 out
#  area 0.0.0.3 filter-list prefix pf1 in
#  area 0.0.0.1 nssa
#  area 0.0.0.4 stub no-summary
#  area 0.0.0.1 nssa range 1::1/64
#  area 0.0.0.1 nssa range 1::2/64 cost 20
#  area 0.0.0.2 range 1::1/64 not-advertise
#  area 0.0.0.2 range 1::2/64 advertise cost 4
#  area 0.0.0.2 range 1::3/24 not-advertise
# sonic#


# Using "overridden" state
# Before state:
# -------------
# sonic# show running-configuration ospfv3
# !
# router ospfv3 vrf Vrf1
#  area 0.0.0.1 nssa no-summary
#  area 0.0.0.1 filter-list prefix pf1 in
#  area 0.0.0.1 filter-list prefix pf2 out
#  area 0.0.0.3 filter-list prefix pf1 in
#  area 0.0.0.1 nssa
#  area 0.0.0.4 stub no-summary
#  area 0.0.0.1 nssa range 1::1/64
#  area 0.0.0.1 nssa range 1::2/64 cost 20
#  area 0.0.0.2 range 1::1/64 not-advertise
#  area 0.0.0.2 range 1::2/64 advertise cost 4
#  area 0.0.0.2 range 1::3/24 not-advertise
# router ospfv3
#  area 0.0.0.1 nssa no-summary
#  area 0.0.0.1 filter-list prefix pf1 in
#  area 0.0.0.1 filter-list prefix pf2 out
#  area 0.0.0.3 filter-list prefix pf1 in
#  area 0.0.0.1 nssa
#  area 0.0.0.4 stub no-summary
#  area 0.0.0.1 nssa range 1::1/64
#  area 0.0.0.1 nssa range 1::2/64 cost 20
#  area 0.0.0.2 range 1::1/64 not-advertise
#  area 0.0.0.2 range 1::2/64 advertise cost 4
#  area 0.0.0.2 range 1::3/24 not-advertise
# sonic#

- name: "override areas"
  dellemc.enterprise_sonic.sonic_ospfv3_area:
    state: overridden
    config:
      - area_id: 0.0.0.1
        vrf_name: Vrf1
      - area_id: 0.0.0.5
        vrf_name: Vrf1
        nssa:
          enabled: true
          default_originate:
            enabled: true
            metric: 10
            metric_type: 1
          ranges:
            - prefix: "1::1/64"
              cost: 15
      - area_id: 0.0.0.4
        vrf_name: Vrf1
        stub:
          no_summary: true
          enabled: true

# After state
# -------------
# sonic# show running-configuration ospfv3
# !
# router ospfv3 vrf Vrf1
#  area 0.0.0.1
#  area 0.0.0.4 stub no-summary
#  area 0.0.0.5 nssa nssa default-information-originate metric 10 metric-type 1
#  area 0.0.0.5 nssa range 1::1/64 cost 15
# router ospfv3
# sonic#
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
after:
  description: The configuration resulting from model invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
after(generated):
  description: The generated (calculated) configuration that would be applied by module invocation.
  returned: when C(check_mode)
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: [{"config": ..., "state": ...}, {"config": ..., "state": ...}]
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ospfv3_area.ospfv3_area import Ospfv3_areaArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.ospfv3_area.ospfv3_area import Ospfv3_area


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Ospfv3_areaArgs.argument_spec,
                           supports_check_mode=True)

    result = Ospfv3_area(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
