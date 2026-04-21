#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The module file for sonic_facts
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_facts
version_added: 1.0.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
short_description: Collects facts on devices running Enterprise SONiC
description:
  - Collects facts from devices running Enterprise SONiC Distribution by
    Dell Technologies. This module places the facts gathered in the fact tree
    keyed by the respective resource name. The facts module always collects
    a base set of facts from the device and can enable or disable collection
    of additional facts.
author:
- Mohamed Javeed (@javeedf)
- Abirami N (@abirami-n)
options:
  gather_subset:
    description:
      - When supplied, this argument restricts the facts collected
        to a given subset. Possible values for this argument include
        all, min, hardware, config, legacy, and interfaces. Can specify a
        list of values to include a larger subset. Values can also be used
        with an initial '!' to specify that a specific subset should
        not be collected.
    required: false
    type: list
    elements: str
    default: '!config'
  gather_network_resources:
    description:
      - When supplied, this argument restricts the facts collected
        to a given subset. Possible values for this argument include
        all and the resources like 'all', 'interfaces', 'vlans', 'lag_interfaces', 'l2_interfaces', 'l3_interfaces'.
        Can specify a list of values to include a larger subset. Values
        can also be used with an initial '!' to specify that a
        specific subset should not be collected.
    required: false
    type: list
    elements: str
    choices:
      - all
      - vlans
      - interfaces
      - l2_interfaces
      - l3_interfaces
      - ipv6_router_advertisement
      - lag_interfaces
      - bgp
      - bgp_af
      - bgp_neighbors
      - bgp_neighbors_af
      - bgp_as_paths
      - bgp_communities
      - bgp_ext_communities
      - ospfv2_interfaces
      - ospfv2
      - ospfv3
      - ospfv3_area
      - ospfv3_interfaces
      - mclag
      - prefix_lists
      - vlan_mapping
      - vrfs
      - vrrp
      - vxlans
      - users
      - system
      - port_breakout
      - pms
      - aaa
      - ldap
      - tacacs_server
      - radius_server
      - static_routes
      - ntp
      - logging
      - pki
      - ip_neighbor
      - ip_neighbor_interfaces
      - port_group
      - dhcp_relay
      - acl_interfaces
      - l2_acls
      - l3_acls
      - lldp_global
      - ptp_default_ds
      - mac
      - bfd
      - copp
      - route_maps
      - lldp_interfaces
      - stp
      - poe
      - dhcp_snooping
      - sflow
      - fips
      - roce
      - qos_buffer
      - qos_pfc
      - qos_maps
      - qos_scheduler
      - qos_wred
      - qos_interfaces
      - pim_global
      - pim_interfaces
      - login_lockout
      - mgmt_servers
      - ospf_area
      - ssh
      - lst
      - ptp_port_ds
      - fbs_classifiers
      - fbs_groups
      - fbs_policies
      - ars
      - network_policy
      - br_l2pt
      - dcbx
      - mirroring
      - drop_counter
      - evpn_esi_multihome
      - ssh_server
      - ecmp_load_share
"""

EXAMPLES = """
- name: Gather all facts
  dellemc.enterprise_sonic.sonic_facts:
    gather_subset: all
    gather_network_resources: all
- name: Collects VLAN and interfaces facts
  dellemc.enterprise_sonic.sonic_facts:
    gather_subset:
      - min
    gather_network_resources:
      - vlans
      - interfaces
- name: Do not collects VLAN and interfaces facts
  dellemc.enterprise_sonic.sonic_facts:
    gather_network_resources:
      - "!vlans"
      - "!interfaces"
- name: Collects VLAN and minimal default facts
  dellemc.enterprise_sonic.sonic_facts:
    gather_subset: min
    gather_network_resources: vlans
- name: Collect lag_interfaces and minimal default facts
  dellemc.enterprise_sonic.sonic_facts:
    gather_subset: min
    gather_network_resources: lag_interfaces
"""

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.facts.facts import FactsArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts


def main():
    """
    Main entry point for module execution
    :returns: ansible_facts
    """
    module = AnsibleModule(argument_spec=FactsArgs.argument_spec,
                           supports_check_mode=True)
    warnings = ['default value for `gather_subset` '
                'will be changed to `min` from `!config` v2.11 onwards']

    result = Facts(module).get_facts()

    ansible_facts, additional_warnings = result
    warnings.extend(additional_warnings)

    module.exit_json(ansible_facts=ansible_facts, warnings=warnings)


if __name__ == '__main__':
    main()
