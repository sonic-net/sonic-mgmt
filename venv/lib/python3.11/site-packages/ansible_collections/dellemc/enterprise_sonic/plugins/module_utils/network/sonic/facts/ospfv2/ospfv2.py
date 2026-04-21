#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic ospfv2 fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ospfv2.ospfv2 import Ospfv2Args
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.bgp_utils import (
    get_all_vrfs,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    remove_empties_from_list
)
from ansible.module_utils.connection import ConnectionError


network_instance_path = '/data/openconfig-network-instance:network-instances/network-instance'
protocol_ospf_path = 'protocols/protocol=OSPF,ospfv2/ospfv2'


class Ospfv2Facts(object):
    """ The sonic ospfv2 fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Ospfv2Args.argument_spec
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
        """ Populate the facts for ospfv2
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []

        all_ospfv2_configs = {}

        if not data:
            all_ospfv2_configs = self.get_ospfv2(self._module)

        for ospf_config in all_ospfv2_configs:
            if ospf_config:
                obj = self.render_config(self.generated_spec, ospf_config)
                if obj:
                    objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('ospfv2', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['ospfv2'] = remove_empties_from_list(params['config'])
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

    def get_ospfv2(self, module):
        """Get all OSPFv2 configurations available in chassis"""
        ospf_configs = []
        vrfs = get_all_vrfs(module)
        for vrf_name in vrfs:
            all_ospf_path = '%s=%s/%s' % (network_instance_path, vrf_name, protocol_ospf_path)
            request = [{"path": all_ospf_path, "method": "GET"}]

            try:
                response = edit_config(module, to_request(module, request))
            except ConnectionError as exc:
                module.fail_json(msg=str(exc), code=exc.code)

            if 'openconfig-network-instance:ospfv2' in response[0][1]:
                ospf_dict = {}
                ospf_global = response[0][1]['openconfig-network-instance:ospfv2'].get('global', {})
                ospf_passive_list = ospf_global.get('openconfig-ospfv2-ext:passive-interfaces', {})

                ospf_dict.update(self.get_ospf_globals(ospf_global))
                ospf_dict.update(self.get_ospf_timers_max_metric(ospf_global))
                ospf_dict.update(self.get_ospf_passive(ospf_passive_list))
                ospf_dict.update(self.get_ospf_redistribute(ospf_global.get("openconfig-ospfv2-ext:route-distribution-policies", {})))
                ospf_dict.update(self.get_ospf_graceful_restart(ospf_global.get("graceful-restart", {})))

                if ospf_dict:
                    ospf_dict['vrf_name'] = vrf_name
                    ospf_configs.append(ospf_dict)
        return ospf_configs

    def get_ospf_globals(self, ospf_global):
        ospf_dict = {}
        config = ospf_global.get("config")

        if config:
            self.update_dict(ospf_dict, "router_id", config.get("router-id"))
            abr_type = config.get('openconfig-ospfv2-ext:abr-type')
            if abr_type:
                abr_type = abr_type.split(':')[1]
                self.update_dict(ospf_dict, 'abr_type', abr_type.lower())
            self.update_dict(ospf_dict, 'auto_cost_reference_bandwidth', config.get('openconfig-ospfv2-ext:auto-cost-reference-bandwidth'))
            self.update_dict(ospf_dict, 'default_metric', config.get('openconfig-ospfv2-ext:default-metric'))
            self.update_dict(ospf_dict, 'default_passive', config.get('openconfig-ospfv2-ext:passive-interface-default', False))
            self.update_dict(ospf_dict, 'maximum_paths', config.get('openconfig-ospfv2-ext:maximum-paths'))
            self.update_dict(ospf_dict, 'opaque_lsa_capability', config.get('openconfig-ospfv2-ext:opaque-lsa-capability'))
            self.update_dict(ospf_dict, 'rfc1583_compatible', config.get('openconfig-ospfv2-ext:ospf-rfc1583-compatible'))
            self.update_dict(ospf_dict, 'write_multiplier', config.get('openconfig-ospfv2-ext:write-multiplier'))
            self.update_dict(ospf_dict, 'log_adjacency_changes', config.get('openconfig-ospfv2-ext:log-adjacency-state-changes'))
            if 'log_adjacency_changes' in ospf_dict:
                ospf_dict['log_adjacency_changes'] = 'brief' if 'BRIEF' in ospf_dict['log_adjacency_changes'] else 'detail'

        if ospf_global.get("openconfig-ospfv2-ext:distance"):
            distance_config = ospf_global.get("openconfig-ospfv2-ext:distance").get("config")
            self.update_dict(ospf_dict, "all", distance_config.get("all"), "distance")
            self.update_dict(ospf_dict, "external", distance_config.get("external"), "distance")
            self.update_dict(ospf_dict, "inter_area", distance_config.get("inter-area"), "distance")
            self.update_dict(ospf_dict, "intra_area", distance_config.get("intra-area"), "distance")

        return ospf_dict

    def get_ospf_timers_max_metric(self, ospf_global):
        timers_dict, refresh_timer, max_metric_dict = {}, {}, {}
        timers = ospf_global.get("timers", {})
        lsa_generation = timers.get("lsa-generation")
        spf = timers.get("spf")
        max_metric = timers.get("max-metric")

        if lsa_generation and lsa_generation.get("config"):
            lsa_config = lsa_generation.get("config")
            self.update_dict(timers_dict, "lsa_min_arrival", lsa_config.get("openconfig-ospfv2-ext:minimum-arrival"))
            self.update_dict(timers_dict, "throttle_lsa_all", lsa_config.get("openconfig-ospfv2-ext:minimum-interval"))
            self.update_dict(refresh_timer, "refresh_timer", lsa_config.get("openconfig-ospfv2-ext:refresh-timer"))

        if spf and spf.get("config"):
            throttle_spf = {}
            spf_config = spf.get("config")
            self.update_dict(throttle_spf, "initial_hold_time", spf_config.get("initial-delay"))
            self.update_dict(throttle_spf, "maximum_hold_time", spf_config.get("maximum-delay"))
            self.update_dict(throttle_spf, "delay_time", spf_config.get("openconfig-ospfv2-ext:throttle-delay"))

            self.update_dict(timers_dict, "throttle_spf", throttle_spf)

        if max_metric and max_metric.get("config"):
            max_metric_config = max_metric.get("config")
            self.update_dict(max_metric_dict, "administrative", max_metric_config.get("openconfig-ospfv2-ext:administrative"))
            self.update_dict(max_metric_dict, "external_lsa_all", max_metric_config.get("openconfig-ospfv2-ext:external-lsa-all"))
            self.update_dict(max_metric_dict, "external_lsa_connected", max_metric_config.get("openconfig-ospfv2-ext:external-lsa-connected"))
            self.update_dict(max_metric_dict, "on_startup", max_metric_config.get("openconfig-ospfv2-ext:on-startup"))
            self.update_dict(max_metric_dict, "router_lsa_all", max_metric_config.get("openconfig-ospfv2-ext:router-lsa-all"))
            self.update_dict(max_metric_dict, "router_lsa_stub", max_metric_config.get("openconfig-ospfv2-ext:router-lsa-stub"))

        return_dict = {}
        self.update_dict(return_dict, "refresh_timer", refresh_timer.get('refresh_timer'))
        self.update_dict(return_dict, "timers", timers_dict)
        self.update_dict(return_dict, "max_metric", max_metric_dict)

        return return_dict

    def get_ospf_passive(self, ospf_passive_list):
        return_dict = {}
        passive_list, non_passive_list = [], []
        passive_interfaces = ospf_passive_list.get("passive-interface", [])
        for passive_interface in passive_interfaces:
            passive_dict = {}
            non_passive_dict = {}
            config = passive_interface.get("config")
            if config:
                address = config.get("address")
                non_passive = config.get("non-passive")
                sub_interface = config.get("subinterface")
                intf_name = config.get("name")
                if sub_interface and sub_interface != 0:
                    intf_name = "%s.%s" % (intf_name, sub_interface)
                if non_passive is not None:
                    intf_exist = False
                    if non_passive:
                        for np_dict in non_passive_list:
                            if np_dict.get('interface') == intf_name:
                                np_dict.setdefault('addresses', [])
                                np_dict['addresses'].append(address)
                                intf_exist = True
                        if not intf_exist:
                            non_passive_dict['interface'] = intf_name
                            if address:
                                non_passive_dict.setdefault('addresses', [])
                                non_passive_dict['addresses'].append(address)
                    else:
                        for p_dict in passive_list:
                            if p_dict.get('interface') == intf_name:
                                p_dict.setdefault('addresses', [])
                                p_dict['addresses'].append(address)
                                intf_exist = True
                        if not intf_exist:
                            passive_dict['interface'] = intf_name
                            if address:
                                passive_dict.setdefault('addresses', [])
                                passive_dict['addresses'].append(address)
            if non_passive_dict:
                non_passive_list.append(non_passive_dict)
            if passive_dict:
                passive_list.append(passive_dict)

        self.update_dict(return_dict, 'passive_interfaces', passive_list)
        self.update_dict(return_dict, 'non_passive_interfaces', non_passive_list)

        return return_dict

    def get_ospf_redistribute(self, ospf_redistribute):
        return_dict = {}
        redistribute_list = []
        protocol_map = {
            "BGP": "bgp",
            "KERNEL": "kernel",
            "DIRECTLY_CONNECTED": "connected",
            "STATIC": "static",
            "DEFAULT_ROUTE": "default_route"
        }

        for redistribute in ospf_redistribute.get("distribute-list", []):
            redistribute_dict = {}
            config = redistribute.get("config")
            if config:
                protocol = config.get("protocol").split(":")[1]
                if protocol and protocol in protocol_map:
                    map_protocol = protocol_map[protocol]
                    if map_protocol == "default_route":
                        self.update_dict(redistribute_dict, 'always', config.get("always"))
                    self.update_dict(redistribute_dict, "metric", config.get("metric"))
                    self.update_dict(redistribute_dict, "route_map", config.get("route-map"))
                    self.update_dict(redistribute_dict, "metric_type", config.get("metric-type"))
                    if "metric_type" in redistribute_dict:
                        type_val = redistribute_dict['metric_type'].split(":")[1]
                        redistribute_dict['metric_type'] = 1 if type_val == 'TYPE_1' else 2
                    redistribute_dict['protocol'] = map_protocol
            if redistribute_dict:
                redistribute_list.append(redistribute_dict)
        self.update_dict(return_dict, 'redistribute', redistribute_list)

        return return_dict

    def get_ospf_graceful_restart(self, graceful_restart):
        return_dict, helper_dict = {}, {}
        advertise_router_id = []
        config = graceful_restart.get("config")
        helpers = graceful_restart.get('openconfig-ospfv2-ext:helpers', {})
        if config:
            self.update_dict(return_dict, 'enable', config.get("enabled"))
            self.update_dict(return_dict, 'grace_period', config.get("openconfig-ospfv2-ext:grace-period"))
            self.update_dict(helper_dict, 'enable', config.get("helper-only"))
            self.update_dict(helper_dict, 'planned_only', config.get("openconfig-ospfv2-ext:planned-only"))
            self.update_dict(helper_dict, 'strict_lsa_checking', config.get("openconfig-ospfv2-ext:strict-lsa-checking"))
            self.update_dict(helper_dict, 'supported_grace_time', config.get("openconfig-ospfv2-ext:supported-grace-time"))
        if helpers:
            for helper in helpers.get('helper', []):
                if helper.get('neighbour-id'):
                    advertise_router_id.append(helper.get('neighbour-id'))
            self.update_dict(helper_dict, 'advertise_router_id', advertise_router_id)
        self.update_dict(return_dict, 'helper', helper_dict)

        if return_dict:
            return_dict = {'graceful_restart': return_dict}

        return return_dict

    def update_dict(self, dict, key, value, parent_key=None):
        if value not in [None, {}, [], ()]:
            if parent_key:
                dict.setdefault(parent_key, {})
                dict[parent_key][key] = value
            else:
                dict[key] = value
