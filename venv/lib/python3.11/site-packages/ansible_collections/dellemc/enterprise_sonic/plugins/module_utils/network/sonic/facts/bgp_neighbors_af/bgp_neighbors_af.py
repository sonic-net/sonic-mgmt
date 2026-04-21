#
# -*- coding: utf-8 -*-
# © Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic bgp_neighbors_af fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.bgp_neighbors_af.bgp_neighbors_af import Bgp_neighbors_afArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.bgp_utils import (
    get_all_bgp_neighbors,
    get_from_params_map,
    update_bgp_nbr_pg_ip_afi_dict,
    update_bgp_nbr_pg_prefix_limit_dict
)


class Bgp_neighbors_afFacts(object):
    """ The sonic bgp_neighbors_af fact class
    """

    neighbor_af_params_map = {
        'afi': 'afi-safi-name',
        'route_reflector_client': 'route-reflector-client',
        'route_server_client': 'route-server-client',
        'allowas_in_origin': ['allow-own-as', 'origin'],
        'allowas_in_value': ['allow-own-as', 'as-count'],
        'in_route_name': ['apply-policy', 'import-policy'],
        'out_route_name': ['apply-policy', 'export-policy'],
        'activate': 'enabled',
        'fabric_external': 'fabric-external',
        'prefix_list_in': ['prefix-list', 'import-policy'],
        'prefix_list_out': ['prefix-list', 'export-policy'],
        'ipv4_unicast': 'ipv4-unicast',
        'ipv6_unicast': 'ipv6-unicast',
        'discard-extra': 'openconfig-bgp-ext:discard-extra',
        'l2vpn_evpn': ['l2vpn-evpn', 'prefix-limit']
    }

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Bgp_neighbors_afArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def fill_route_map(self, data):
        for route_map_key in ['out_route_name', 'in_route_name']:
            if route_map_key in data:
                route_map = data['route_map']
                for e_route in data[route_map_key]:
                    direction = route_map_key.split('_', maxsplit=1)[0]
                    route_map.append({'name': e_route, 'direction': direction})
                data.pop(route_map_key)

    def normalize_neighbors_af_data(self, neighbors):
        norm_neighbors = []

        for nei_data in neighbors:
            norm_neighbor = {}

            neighbor = nei_data.get('neighbor-address', None)
            if not neighbor:
                continue
            norm_neighbor['neighbor'] = neighbor
            norm_neighbor['address_family'] = []
            nei_afs = nei_data.get('afi-safis', None)
            if not nei_afs:
                if norm_neighbor:
                    norm_neighbors.append(norm_neighbor)
                continue
            nei_afs = nei_afs.get('afi-safi', None)
            if not nei_afs:
                if norm_neighbor:
                    norm_neighbors.append(norm_neighbor)
                continue
            norm_neighbor_afs = []
            for nei_af in nei_afs:
                norm_nei_af = get_from_params_map(self.neighbor_af_params_map, nei_af)
                if norm_nei_af:
                    if 'activate' not in norm_nei_af:
                        norm_nei_af['activate'] = False
                    if 'fabric_external' not in norm_nei_af:
                        norm_nei_af['fabric_external'] = False
                    if 'route_server_client' not in norm_nei_af:
                        norm_nei_af['route_server_client'] = False
                    norm_nei_af['route_map'] = []
                    self.fill_route_map(norm_nei_af)

                    allowas_in = {}
                    allowas_in_origin = norm_nei_af.get('allowas_in_origin', None)
                    if allowas_in_origin is not None:
                        allowas_in['origin'] = allowas_in_origin
                        norm_nei_af.pop('allowas_in_origin')

                    allowas_in_value = norm_nei_af.get('allowas_in_value', None)
                    if allowas_in_value is not None:
                        allowas_in['value'] = allowas_in_value
                        norm_nei_af.pop('allowas_in_value')
                    if allowas_in:
                        norm_nei_af['allowas_in'] = allowas_in

                    ipv4_unicast = norm_nei_af.get('ipv4_unicast', None)
                    ipv6_unicast = norm_nei_af.get('ipv6_unicast', None)
                    if ipv4_unicast:
                        if 'config' in ipv4_unicast:
                            ip_afi = update_bgp_nbr_pg_ip_afi_dict(ipv4_unicast['config'])
                            if ip_afi:
                                norm_nei_af['ip_afi'] = ip_afi
                        if 'prefix-limit' in ipv4_unicast and 'config' in ipv4_unicast['prefix-limit']:
                            prefix_limit = update_bgp_nbr_pg_prefix_limit_dict(ipv4_unicast['prefix-limit']['config'])
                            if prefix_limit:
                                norm_nei_af['prefix_limit'] = prefix_limit
                        norm_nei_af.pop('ipv4_unicast')
                    elif ipv6_unicast:
                        if 'config' in ipv6_unicast:
                            ip_afi = update_bgp_nbr_pg_ip_afi_dict(ipv6_unicast['config'])
                            if ip_afi:
                                norm_nei_af['ip_afi'] = ip_afi
                        if 'prefix-limit' in ipv6_unicast and 'config' in ipv6_unicast['prefix-limit']:
                            prefix_limit = update_bgp_nbr_pg_prefix_limit_dict(ipv6_unicast['prefix-limit']['config'])
                            if prefix_limit:
                                norm_nei_af['prefix_limit'] = prefix_limit
                        norm_nei_af.pop('ipv6_unicast')

                    norm_neighbor_afs.append(norm_nei_af)
            if norm_neighbor_afs:
                norm_neighbor['address_family'] = norm_neighbor_afs
            if norm_neighbor:
                norm_neighbors.append(norm_neighbor)
        return norm_neighbors

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for BGP
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = list()
        if connection:  # just for linting purposes, remove
            pass

        if not data:
            data = get_all_bgp_neighbors(self._module)

        new_data = []
        for conf in data:
            if not conf:
                continue
            new_item = {}
            new_item['bgp_as'] = conf['bgp_as']
            new_item['vrf_name'] = conf['vrf_name']
            neighbors = conf.get('neighbors', None)
            if not neighbors:
                new_data.append(new_item)
                continue
            neighbors = neighbors.get('neighbor', None)
            if not neighbors:
                new_data.append(new_item)
                continue

            new_neighbors = self.normalize_neighbors_af_data(neighbors)
            if new_neighbors:
                new_item['neighbors'] = new_neighbors
            if new_item:
                new_data.append(new_item)

        # operate on a collection of resource x
        for conf in new_data:
            if conf:
                obj = self.render_config(self.generated_spec, conf)
        # split the config into instances of the resource
                if obj:
                    objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('bgp_neighbors_af', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': remove_empties_from_list(objs)})
            facts['bgp_neighbors_af'] = params['config']
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def render_config(self, spec, conf):
        """
        Render config as dictionary structure and delete keys
          from spec for null values

        :param spec: The facts tree, generated from the argspec
        :param conf: The configuration
        :rtype: dictionary
        :returns: The generated config
        """
        return conf
