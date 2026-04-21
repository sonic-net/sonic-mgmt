#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic static_routes fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy

from ansible.module_utils.connection import ConnectionError
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.static_routes.static_routes import Static_routesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.bgp_utils import (
    get_all_vrfs,
)

network_instance_path = '/data/openconfig-network-instance:network-instances/network-instance'
protocol_static_routes_path = 'protocols/protocol=STATIC,static/static-routes'


class Static_routesFacts(object):
    """ The sonic static_routes fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Static_routesArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for static_routes
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []

        if not data:
            static_routes_config = self.get_static_routes(self._module)
            data = self.update_static_routes(static_routes_config)
        objs = data
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['static_routes'] = remove_empties_from_list(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_static_routes(self, module):
        all_static_routes = []
        vrfs = get_all_vrfs(module)
        for vrf_name in vrfs:
            get_path = '%s=%s/%s' % (network_instance_path, vrf_name, protocol_static_routes_path)
            request = {'path': get_path, 'method': 'get'}
            try:
                response = edit_config(module, to_request(module, request))
            except ConnectionError as exc:
                module.fail_json(msg=str(exc), code=exc.code)
            for resp in response:
                if 'openconfig-network-instance:static-routes' in resp[1]:
                    static_routes_dict = resp[1].get('openconfig-network-instance:static-routes', {})
                    static_routes_dict['vrf'] = vrf_name
                    all_static_routes.append(static_routes_dict)
        return all_static_routes

    def update_static_routes(self, data):
        static_vrf_list = []
        for static_route in data:
            static_vrf_dict = {}
            static_route_list = static_route.get('static', [])
            vrf_name = static_route.get('vrf', None)
            static_list = []
            for static in static_route_list:
                static_dict = {}
                prefix = static.get('prefix', None)
                next_hops = static.get('next-hops', None)
                next_hop_list = next_hops.get('next-hop', [])
                next_hop_dict_list = []
                for next_hop in next_hop_list:
                    next_hop_dict = {}
                    index_dict = {}
                    inf_ref = next_hop.get('interface-ref', {})
                    inf_ref_cfg = inf_ref.get('config', {})
                    interface = inf_ref_cfg.get('interface', None)
                    config = next_hop.get('config', {})
                    next_hop_attr = config.get('next-hop', None)
                    metric = config.get('metric', None)
                    nexthop_vrf = config.get('network-instance', None)
                    blackhole = config.get('blackhole', None)
                    track = config.get('track', None)
                    tag = config.get('tag', None)
                    if blackhole is not None:
                        index_dict['blackhole'] = blackhole
                    if interface:
                        index_dict['interface'] = interface
                    if nexthop_vrf:
                        index_dict['nexthop_vrf'] = nexthop_vrf
                    if next_hop_attr:
                        index_dict['next_hop'] = next_hop_attr
                    if index_dict:
                        next_hop_dict['index'] = index_dict
                    if metric:
                        next_hop_dict['metric'] = metric
                    if track:
                        next_hop_dict['track'] = track
                    if tag:
                        next_hop_dict['tag'] = tag
                    if next_hop_dict:
                        next_hop_dict_list.append(next_hop_dict)
                if prefix:
                    static_dict['prefix'] = prefix
                if next_hop_dict_list:
                    static_dict['next_hops'] = next_hop_dict_list
                if static_dict:
                    static_list.append(static_dict)
            if static_list:
                static_vrf_dict['static_list'] = static_list
            if vrf_name:
                static_vrf_dict['vrf_name'] = vrf_name
            if static_vrf_dict:
                static_vrf_list.append(static_vrf_dict)

        return static_vrf_list
