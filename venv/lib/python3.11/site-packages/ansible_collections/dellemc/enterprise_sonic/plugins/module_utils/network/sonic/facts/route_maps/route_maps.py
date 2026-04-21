#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic route_maps fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re
from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible.module_utils.connection import ConnectionError
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.route_maps.route_maps import Route_mapsArgs

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import remove_empties_from_list

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic \
    import to_request, edit_config


class Route_mapsFacts(object):
    """ The sonic route_maps fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Route_mapsArgs.argument_spec
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
        """ Populate the facts for route_maps
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if not data:
            # Fetch data from the current device configuration
            # (Skip if operating on previously fetched configuration.)
            data = self.get_all_route_maps()

        # split the unparsed route map configuration list into a list
        # of parsed route map statement "instances" (dictonary "objects").
        route_maps = []
        for route_map_cfg in data:
            route_map_stmts = self.route_map_cfg_parse(route_map_cfg)
            if route_map_stmts:
                route_maps.extend(route_map_stmts)

        ansible_facts['ansible_network_resources'].pop('route_maps', None)
        facts = {}
        if route_maps:
            params = utils.validate_config(self.argument_spec,
                                           {'config': route_maps})
            params_cleaned = {'config': remove_empties_from_list(params['config'])}
            facts['route_maps'] = params_cleaned['config']
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_all_route_maps(self):
        '''Execute a REST "GET" API to fetch all of the current route map configuration
        from the target device.'''

        route_map_fetch_spec = \
            "openconfig-routing-policy:routing-policy/policy-definitions"
        route_map_resp_key = "openconfig-routing-policy:policy-definitions"
        route_map_key = "policy-definition"
        url = "data/%s" % route_map_fetch_spec
        method = "GET"
        request = [{"path": url, "method": method}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc))

        route_maps_unparsed = []
        resp_route_map_envelope = response[0][1].get(route_map_resp_key, None)
        if resp_route_map_envelope:
            route_maps_unparsed = resp_route_map_envelope.get(route_map_key, None)
        return route_maps_unparsed

    def route_map_cfg_parse(self, unparsed_route_map):
        '''Parse the raw input configuration JSON representation for the route map specified
        by the "unparsed_route_map" input parameter. Parse the information to
        convert it to a dictionary matching the "argspec" for the "route_maps" resource
        module.'''

        parsed_route_map_stmts = []

        if not unparsed_route_map.get("config"):
            return parsed_route_map_stmts
        route_map_name = unparsed_route_map.get('name')
        if not route_map_name:
            return parsed_route_map_stmts
        route_map_statements = unparsed_route_map.get('statements')
        if not route_map_statements:
            return parsed_route_map_stmts
        route_map_stmts_list = route_map_statements.get('statement')
        if not route_map_stmts_list:
            return parsed_route_map_stmts

        for route_map_stmt in route_map_stmts_list:
            parsed_route_map_stmt = {}
            parsed_seq_num = route_map_stmt.get('name')
            if not parsed_seq_num:
                continue
            parsed_route_map_stmt['map_name'] = route_map_name
            parsed_route_map_stmt['sequence_num'] = parsed_seq_num
            self.get_route_map_stmt_set_attr(route_map_stmt, parsed_route_map_stmt)
            self.get_route_map_stmt_match_attr(route_map_stmt, parsed_route_map_stmt)
            self.get_route_map_call_attr(route_map_stmt, parsed_route_map_stmt)
            parsed_route_map_stmts.append(parsed_route_map_stmt)

        return parsed_route_map_stmts

    def get_route_map_stmt_set_attr(self, route_map_stmt, parsed_route_map_stmt):
        '''Parse the "set" attribute portion of the raw input configuration JSON
        representation for the route map "statement" specified
        by the "route_map_stmt," input parameter. Parse the information to
        convert it to a dictionary matching the "argspec" for the "route_maps" resource
        module.'''

        stmt_actions = route_map_stmt.get('actions')
        if not stmt_actions:
            return

        # Fetch the permit/deny action for the route map statement
        actions_config = stmt_actions.get('config')
        if not actions_config:
            return
        permit_deny_config = actions_config.get('policy-result')
        if not permit_deny_config:
            return
        if permit_deny_config == "ACCEPT_ROUTE":
            parsed_route_map_stmt['action'] = "permit"
        elif permit_deny_config == "REJECT_ROUTE":
            parsed_route_map_stmt['action'] = "deny"
        else:
            return

        # Create a dict object to hold "set" attributes.
        parsed_route_map_stmt['set'] = {}
        parsed_route_map_stmt_set = parsed_route_map_stmt['set']

        # Fetch non-required top level set attributes
        set_metric_action = stmt_actions.get('metric-action')
        if set_metric_action:
            set_metric_action_cfg = set_metric_action.get('config')
            if set_metric_action_cfg:
                metric_action = set_metric_action_cfg.get('action')
                if metric_action:
                    parsed_route_map_stmt_set['metric'] = {}
                    if metric_action == 'openconfig-routing-policy:METRIC_SET_VALUE':
                        value = set_metric_action_cfg.get('metric')
                        if value:
                            parsed_route_map_stmt_set['metric']['value'] = value
                    elif metric_action == 'openconfig-routing-policy:METRIC_SET_RTT':
                        parsed_route_map_stmt_set['metric']['rtt_action'] = 'set'
                    elif metric_action == 'openconfig-routing-policy:METRIC_ADD_RTT':
                        parsed_route_map_stmt_set['metric']['rtt_action'] = 'add'
                    elif metric_action == 'openconfig-routing-policy:METRIC_SUBTRACT_RTT':
                        parsed_route_map_stmt_set['metric']['rtt_action'] = 'subtract'

                    # Possible anomalous state due to partial deletion of metric config via REST
                    if parsed_route_map_stmt_set['metric'] == {}:
                        parsed_route_map_stmt_set.pop('metric')

        # Fetch BGP policy action attributes
        set_bgp_policy = stmt_actions.get('openconfig-bgp-policy:bgp-actions')
        if set_bgp_policy:
            self.get_route_map_set_bgp_policy_attr(set_bgp_policy, parsed_route_map_stmt_set)

    def get_route_map_set_bgp_policy_attr(self, set_bgp_policy, parsed_route_map_stmt_set):
        '''Parse the BGP policy "set" attribute portion of the raw input
        configuration JSON representation within the route map "statement"
        that is currently being parsed. The configuration section to be parsed
        is specified by the "set_bgp_policy" input parameter. Parse the
        information to convert it to a dictionary matching the "argspec" for
        the "route_maps" resource module.'''

        # Fetch ars_object config
        set_ars_obj_top = set_bgp_policy.get('openconfig-routing-policy-ext:ars-object')
        if set_ars_obj_top and set_ars_obj_top.get('config'):
            ars_object = \
                set_ars_obj_top['config'].get(
                    'set-ars-object')
            if ars_object:
                parsed_route_map_stmt_set['ars_object'] = \
                    ars_object

        # Fetch as_path_prepend config
        set_as_path_top = set_bgp_policy.get('set-as-path-prepend')
        if set_as_path_top and set_as_path_top.get('config'):
            as_path_prepend = \
                set_as_path_top['config'].get(
                    'openconfig-routing-policy-ext:asn-list')
            if as_path_prepend:
                parsed_route_map_stmt_set['as_path_prepend'] = \
                    as_path_prepend

        # Fetch community list "delete" config
        set_comm_list_delete_top = set_bgp_policy.get('set-community-delete')
        if set_comm_list_delete_top:
            set_comm_list_delete_config = set_comm_list_delete_top.get('config')
            if set_comm_list_delete_config:
                comm_list_delete = \
                    set_comm_list_delete_config.get('community-set-delete')
                if comm_list_delete:
                    parsed_route_map_stmt_set['comm_list_delete'] = \
                        comm_list_delete

        # Fetch community attributes.
        self.get_rmap_set_community(set_bgp_policy, parsed_route_map_stmt_set)

        # Fetch extended community attributes.
        self.get_rmap_set_extcommunity(set_bgp_policy, parsed_route_map_stmt_set)

        # Fetch other BGP policy "set" attributes
        set_bgp_policy_cfg = set_bgp_policy.get('config')
        if set_bgp_policy_cfg:

            ip_next_hop_address = set_bgp_policy_cfg.get('set-next-hop')
            ip_next_hop_native = set_bgp_policy_cfg.get('openconfig-bgp-policy-ext:set-next-hop-native')
            if ip_next_hop_address or (ip_next_hop_native is not None):
                parsed_route_map_stmt_set['ip_next_hop'] = {}
                set_ip_nexthop = parsed_route_map_stmt_set['ip_next_hop']
                if ip_next_hop_address:
                    set_ip_nexthop['address'] = ip_next_hop_address
                if ip_next_hop_native is not None:
                    set_ip_nexthop['native'] = ip_next_hop_native

            ipv6_next_hop_global_addr = set_bgp_policy_cfg.get('set-ipv6-next-hop-global')
            ipv6_prefer_global = set_bgp_policy_cfg.get('set-ipv6-next-hop-prefer-global')
            ipv6_native = set_bgp_policy_cfg.get('openconfig-bgp-policy-ext:set-ipv6-next-hop-native')
            if ipv6_next_hop_global_addr or (ipv6_prefer_global is not None) or (ipv6_native is not None):
                parsed_route_map_stmt_set['ipv6_next_hop'] = {}
                set_ipv6_nexthop = parsed_route_map_stmt_set['ipv6_next_hop']
                if ipv6_next_hop_global_addr:
                    set_ipv6_nexthop['global_addr'] = ipv6_next_hop_global_addr
                if ipv6_prefer_global is not None:
                    set_ipv6_nexthop['prefer_global'] = ipv6_prefer_global
                if ipv6_native is not None:
                    set_ipv6_nexthop['native'] = ipv6_native

            local_preference = set_bgp_policy_cfg.get('set-local-pref')
            if local_preference:
                parsed_route_map_stmt_set['local_preference'] = local_preference

            set_origin = set_bgp_policy_cfg.get('set-route-origin')
            if set_origin:
                if set_origin == 'EGP':
                    parsed_route_map_stmt_set['origin'] = 'egp'
                elif set_origin == 'IGP':
                    parsed_route_map_stmt_set['origin'] = 'igp'
                elif set_origin == 'INCOMPLETE':
                    parsed_route_map_stmt_set['origin'] = 'incomplete'

            weight = set_bgp_policy_cfg.get('set-weight')
            if weight:
                parsed_route_map_stmt_set['weight'] = weight

            tag = set_bgp_policy_cfg.get('set-tag')
            if tag:
                parsed_route_map_stmt_set['tag'] = tag

    @staticmethod
    def get_rmap_set_community(set_bgp_policy, parsed_route_map_stmt_set):
        '''Parse the "community" sub-section of the BGP policy "set" attribute
        portion of the raw input configuration JSON representation.
        The BGP policy "set" configuration section to be parsed is specified
        by the "set_bgp_policy" input parameter. Parse the information
        to convert it to a dictionary matching the "argspec" for the "route_maps"
        resource module.'''

        set_community_top = set_bgp_policy.get('set-community')
        if (set_community_top and set_community_top.get('inline') and
                set_community_top['inline'].get('config') and
                set_community_top['inline']['config'].get('communities')):

            set_community_config_list = \
                set_community_top['inline']['config']['communities']
            parsed_route_map_stmt_set['community'] = {}
            parsed_rmap_stmt_set_comm = parsed_route_map_stmt_set['community']
            for set_community_config_item in set_community_config_list:
                if (set_community_config_item.split(':')[0] in
                        ('openconfig-bgp-types', 'openconfig-routing-policy-ext')):
                    set_community_attr = set_community_config_item.split(':')[1]
                    if not parsed_rmap_stmt_set_comm.get('community_attributes'):
                        parsed_rmap_stmt_set_comm['community_attributes'] = []
                        parsed_comm_attr_list = \
                            parsed_rmap_stmt_set_comm['community_attributes']
                    comm_attr_rest_to_argspec = {
                        'NO_EXPORT_SUBCONFED': 'local_as',
                        'NO_ADVERTISE': 'no_advertise',
                        'NO_EXPORT': 'no_export',
                        'NOPEER': 'no_peer',
                        'NONE': 'none',
                        'ADDITIVE': 'additive'
                    }
                    if set_community_attr in comm_attr_rest_to_argspec:
                        parsed_comm_attr_list.append(
                            comm_attr_rest_to_argspec[set_community_attr])
                else:
                    if not parsed_rmap_stmt_set_comm.get('community_number'):
                        parsed_rmap_stmt_set_comm['community_number'] = []
                        parsed_comm_num_list = \
                            parsed_rmap_stmt_set_comm['community_number']
                    set_community_num_val_match = \
                        re.match(r'\d+:\d+$', set_community_config_item)
                    if set_community_num_val_match:
                        parsed_comm_num_list.append(set_community_config_item)

    @staticmethod
    def get_rmap_set_extcommunity(set_bgp_policy, parsed_route_map_stmt_set):
        '''Parse the "extcommunity" sub-section of the BGP policy "set"
        attribute portion of the raw input configuration JSON representation.
        The BGP policy "set" configuration section to be parsed is specified
        by the "set_bgp_policy" input parameter. Parse the information
        to convert it to a dictionary matching the "argspec" for the "route_maps"
        resource module.'''
        set_extcommunity_top = set_bgp_policy.get('set-ext-community')
        if (set_extcommunity_top and set_extcommunity_top.get('inline') and
                set_extcommunity_top['inline'].get('config') and
                set_extcommunity_top['inline']['config'].get('communities')):
            set_extcommunity_config_list = \
                set_extcommunity_top['inline']['config']['communities']
            if set_extcommunity_config_list:
                parsed_route_map_stmt_set['extcommunity'] = {}
                parsed_rmap_stmt_set_extcomm = parsed_route_map_stmt_set['extcommunity']
                for set_extcommunity_config_item in set_extcommunity_config_list:
                    if 'route-target:' in set_extcommunity_config_item:
                        rt_val = set_extcommunity_config_item.replace('route-target:', '')
                        if parsed_rmap_stmt_set_extcomm.get('rt'):
                            parsed_rmap_stmt_set_extcomm['rt'].append(rt_val)
                        else:
                            parsed_rmap_stmt_set_extcomm['rt'] = [rt_val]
                    elif 'route-origin:' in set_extcommunity_config_item:
                        soo_val = set_extcommunity_config_item.replace('route-origin:', '')
                        if parsed_rmap_stmt_set_extcomm.get('soo'):
                            parsed_rmap_stmt_set_extcomm['soo'].append(soo_val)
                        else:
                            parsed_rmap_stmt_set_extcomm['soo'] = [soo_val]
                    elif 'link-bandwidth:' in set_extcommunity_config_item:
                        if not parsed_rmap_stmt_set_extcomm.get('bandwidth'):
                            parsed_rmap_stmt_set_extcomm['bandwidth'] = {}
                        bandwidth_val = set_extcommunity_config_item.split(":")[1]
                        parsed_rmap_stmt_set_extcomm['bandwidth']['bandwidth_value'] = bandwidth_val
                        bandwidth_transitive_val = ("transitive" == set_extcommunity_config_item.split(":")[2])
                        parsed_rmap_stmt_set_extcomm['bandwidth']['transitive_value'] = bandwidth_transitive_val

    @staticmethod
    def get_route_map_call_attr(route_map_stmt, parsed_route_map_stmt):
        '''Parse the "call" attribute portion of the raw input configuration JSON
        representation for the route map "statement" specified
        by the "route_map_stmt," input parameter. Parse the information to
        convert it to a dictionary matching the "argspec" for the "route_maps" resource
        module.'''

        stmt_conditions = route_map_stmt.get('conditions')
        if not stmt_conditions:
            return

        # Fetch the "call" policy configuration for the route map statement
        conditions_config = stmt_conditions.get('config')
        if not conditions_config:
            return
        call_str = conditions_config.get('call-policy')
        if not call_str:
            return
        parsed_route_map_stmt['call'] = call_str

    def get_route_map_stmt_match_attr(self, route_map_stmt, parsed_route_map_stmt):
        '''Parse the "match" attributes in the raw input configuration JSON
        representation for the route map "statement" specified
        by the "route_map_stmt," input parameter. Parse the information to
        convert it to a dictionary matching the "argspec" for the "route_maps" resource
        module.'''

        # Create a dict object to hold "match" attributes.
        parsed_route_map_stmt['match'] = {}
        parsed_rmap_match = parsed_route_map_stmt['match']

        stmt_conditions = route_map_stmt.get('conditions')
        if not stmt_conditions:
            return

        # Fetch match as-path configuration
        if (stmt_conditions.get('match-as-path-set') and
                stmt_conditions['match-as-path-set'].get('config')):
            as_path = \
                stmt_conditions['match-as-path-set']['config'].get('as-path-set')
            if as_path:
                parsed_rmap_match['as_path'] = as_path

        # Fetch BGP policy match attributes.
        rmap_bgp_policy_match = stmt_conditions.get('openconfig-bgp-policy:bgp-conditions')
        if rmap_bgp_policy_match:
            self.get_rmap_match_bgp_policy_attr(rmap_bgp_policy_match, parsed_rmap_match)

        # Fetch other match attributes
        if (stmt_conditions.get('match-interface') and
                stmt_conditions['match-interface'].get('config')):
            match_interface = stmt_conditions['match-interface']['config'].get('interface')
            if match_interface:
                parsed_rmap_match['interface'] = match_interface

        if (stmt_conditions.get('match-prefix-set') and
                stmt_conditions['match-prefix-set']['config']):
            match_prefix_set = \
                stmt_conditions['match-prefix-set']['config']
            if match_prefix_set and match_prefix_set.get('prefix-set'):
                if not parsed_rmap_match.get('ip'):
                    parsed_rmap_match['ip'] = {}
                parsed_rmap_match['ip']['address'] = \
                    match_prefix_set['prefix-set']
            if (match_prefix_set and
                    match_prefix_set.get('openconfig-routing-policy-ext:ipv6-prefix-set')):
                parsed_rmap_match['ipv6'] = {}
                parsed_rmap_match['ipv6']['address'] = \
                    match_prefix_set['openconfig-routing-policy-ext:ipv6-prefix-set']

            if (stmt_conditions.get('match-neighbor-set') and
                    stmt_conditions['match-neighbor-set'].get('config') and
                    stmt_conditions['match-neighbor-set']['config'].get(
                        'openconfig-routing-policy-ext:address')):
                parsed_rmap_match_peer = stmt_conditions[
                    'match-neighbor-set']['config']['openconfig-routing-policy-ext:address'][0]
                parsed_rmap_match['peer'] = {}
                if ':' in parsed_rmap_match_peer:
                    parsed_rmap_match['peer']['ipv6'] = parsed_rmap_match_peer
                elif '.' in parsed_rmap_match_peer:
                    parsed_rmap_match['peer']['ip'] = parsed_rmap_match_peer
                else:
                    parsed_rmap_match['peer']['interface'] = parsed_rmap_match_peer

        if (stmt_conditions.get('config') and
                stmt_conditions['config'].get('install-protocol-eq')):
            parsed_rmap_match_source_protocol = \
                stmt_conditions['config']['install-protocol-eq']
            if parsed_rmap_match_source_protocol == "openconfig-policy-types:BGP":
                parsed_rmap_match['source_protocol'] = "bgp"
            elif parsed_rmap_match_source_protocol == "openconfig-policy-types:OSPF":
                parsed_rmap_match['source_protocol'] = "ospf"
            elif parsed_rmap_match_source_protocol == "openconfig-policy-types:STATIC":
                parsed_rmap_match['source_protocol'] = "static"
            elif parsed_rmap_match_source_protocol == \
                    "openconfig-policy-types:DIRECTLY_CONNECTED":
                parsed_rmap_match['source_protocol'] = "connected"

        if stmt_conditions.get(
                'openconfig-routing-policy-ext:match-src-network-instance'):
            match_src_vrf = \
                stmt_conditions[
                    'openconfig-routing-policy-ext:match-src-network-instance'].get('config')
            if match_src_vrf and match_src_vrf.get('name'):
                parsed_rmap_match['source_vrf'] = match_src_vrf['name']

        if (stmt_conditions.get('match-tag-set') and
                stmt_conditions['match-tag-set'].get('config')):
            match_tag = \
                stmt_conditions['match-tag-set']['config'].get(
                    'openconfig-routing-policy-ext:tag-value')
            if match_tag:
                parsed_rmap_match['tag'] = match_tag[0]

    @staticmethod
    def get_rmap_match_bgp_policy_attr(rmap_bgp_policy_match, parsed_rmap_match):
        '''Parse the BGP policy "match" attribute portion of the raw input
        configuration JSON representation within the route map "statement"
        that is currently being parsed. The configuration section to be parsed
        is specified by the "rmap_bgp_match_cfg" input parameter. Parse the
        information to convert it to a dictionary matching the "argspec" for
        the "route_maps" resource module.'''

        if (rmap_bgp_policy_match.get('match-as-path-set') and
                rmap_bgp_policy_match['match-as-path-set'].get('config')):
            as_path = rmap_bgp_policy_match['match-as-path-set']['config'].get('as-path-set')
            if as_path:
                parsed_rmap_match['as_path'] = as_path

        # Fetch BGP policy match "config" attributes
        rmap_bgp_match_cfg = rmap_bgp_policy_match.get('config')
        if rmap_bgp_match_cfg:
            match_metric = rmap_bgp_match_cfg.get('med-eq')
            if match_metric:
                parsed_rmap_match['metric'] = match_metric

            match_origin = rmap_bgp_match_cfg.get('origin-eq')
            if match_origin:
                if match_origin == 'IGP':
                    parsed_rmap_match['origin'] = 'igp'
                elif match_origin == 'EGP':
                    parsed_rmap_match['origin'] = 'egp'
                elif match_origin == 'INCOMPLETE':
                    parsed_rmap_match['origin'] = 'incomplete'

            if rmap_bgp_match_cfg.get('local-pref-eq'):
                parsed_rmap_match['local_preference'] = rmap_bgp_match_cfg['local-pref-eq']

            if rmap_bgp_match_cfg.get('community-set'):
                parsed_rmap_match['community'] = rmap_bgp_match_cfg['community-set']

            if rmap_bgp_match_cfg.get('ext-community-set'):
                parsed_rmap_match['ext_comm'] = rmap_bgp_match_cfg['ext-community-set']

            if rmap_bgp_match_cfg.get('openconfig-bgp-policy-ext:next-hop-set'):
                parsed_rmap_match['ip'] = {}
                parsed_rmap_match['ip']['next_hop'] = \
                    rmap_bgp_match_cfg['openconfig-bgp-policy-ext:next-hop-set']

        # Fetch BGP policy match "evpn" attributes
        if rmap_bgp_policy_match.get('openconfig-bgp-policy-ext:match-evpn-set'):
            bgp_policy_match_evpn_cfg = \
                rmap_bgp_policy_match['openconfig-bgp-policy-ext:match-evpn-set'].get('config')
            if bgp_policy_match_evpn_cfg:
                parsed_rmap_match['evpn'] = {}
                if bgp_policy_match_evpn_cfg.get('vni-number'):
                    parsed_rmap_match['evpn']['vni'] = \
                        bgp_policy_match_evpn_cfg.get('vni-number')
                if bgp_policy_match_evpn_cfg.get('default-type5-route'):
                    parsed_rmap_match['evpn']['default_route'] = True
                evpn_route_type = bgp_policy_match_evpn_cfg.get('route-type')
                if evpn_route_type:
                    if evpn_route_type == "openconfig-bgp-policy-ext:MACIP":
                        parsed_rmap_match['evpn']['route_type'] = "macip"
                    elif evpn_route_type == "openconfig-bgp-policy-ext:MULTICAST":
                        parsed_rmap_match['evpn']['route_type'] = "multicast"
                    elif evpn_route_type == "openconfig-bgp-policy-ext:PREFIX":
                        parsed_rmap_match['evpn']['route_type'] = "prefix"
