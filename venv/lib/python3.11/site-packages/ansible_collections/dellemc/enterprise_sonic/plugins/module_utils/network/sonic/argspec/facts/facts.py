#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The arg spec for the sonic facts module.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class FactsArgs(object):  # pylint: disable=R0903

    """ The arg spec for the sonic facts module
    """

    def __init__(self, **kwargs):
        pass

    choices = [
        'all',
        'vlans',
        'interfaces',
        'l2_interfaces',
        'l3_interfaces',
        'lag_interfaces',
        'bgp',
        'bgp_af',
        'bgp_neighbors',
        'bgp_neighbors_af',
        'bgp_as_paths',
        'bgp_communities',
        'bgp_ext_communities',
        'dcbx',
        'ospfv2_interfaces',
        'ospfv2',
        'ospfv3',
        'ospfv3_area',
        'ospfv3_interfaces',
        'mclag',
        'prefix_lists',
        'vlan_mapping',
        'vrfs',
        'vrrp',
        'vxlans',
        'users',
        'system',
        'port_breakout',
        'pms',
        'aaa',
        'ldap',
        'tacacs_server',
        'radius_server',
        'static_routes',
        'ntp',
        'logging',
        'pki',
        'ip_neighbor',
        'ip_neighbor_interfaces',
        'ipv6_router_advertisement',
        'port_group',
        'dhcp_relay',
        'dhcp_snooping',
        'acl_interfaces',
        'l2_acls',
        'l3_acls',
        'lldp_global',
        'mac',
        'bfd',
        'copp',
        'route_maps',
        'lldp_interfaces',
        'stp',
        'sflow',
        'fips',
        'roce',
        'qos_buffer',
        'qos_pfc',
        'qos_maps',
        'qos_scheduler',
        'qos_wred',
        'qos_interfaces',
        'pim_global',
        'ptp_default_ds',
        'pim_interfaces',
        'ptp_port_ds',
        'login_lockout',
        'poe',
        'mgmt_servers',
        'ospf_area',
        'ssh',
        'lst',
        'fbs_classifiers',
        'fbs_groups',
        'fbs_policies',
        'ars',
        'mirroring',
        'network_policy',
        'drop_counter',
        'br_l2pt',
        'evpn_esi_multihome',
        'ssh_server',
        'ecmp_load_share'
    ]

    argument_spec = {
        'gather_subset': dict(default=['!config'], type='list', elements='str'),
        'gather_network_resources': dict(choices=choices, type='list', elements='str'),
    }
