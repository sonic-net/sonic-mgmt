from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ospfv3.ospfv3 import Ospfv3Args
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
protocol_ospf_path = 'protocols/protocol=OSPF3,ospfv3/ospfv3'  # OSPFv3 path


class Ospfv3Facts(object):
    """ The sonic ospfv3 fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Ospfv3Args.argument_spec
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
        """ Populate the facts for ospfv3
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """

        objs = []

        all_ospfv3_configs = {}

        if not data:
            all_ospfv3_configs = self.get_ospfv3(self._module)

        for ospf_config in all_ospfv3_configs:
            if ospf_config:
                objs.append(ospf_config)

        ansible_facts['ansible_network_resources'].pop('ospfv3', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['ospfv3'] = remove_empties_from_list(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_ospfv3(self, module):
        """Get all OSPFv3 configurations available in chassis"""
        ospf_configs = []
        vrfs = get_all_vrfs(module)
        for vrf_name in vrfs:
            all_ospf_path = '%s=%s/%s' % (network_instance_path, vrf_name, protocol_ospf_path)
            request = [{"path": all_ospf_path, "method": "GET"}]

            try:
                response = edit_config(module, to_request(module, request))
            except ConnectionError as exc:
                module.fail_json(msg=str(exc), code=exc.code)

            if 'openconfig-network-instance:ospfv3' in response[0][1]:
                ospf_dict = {}
                ospf_global = response[0][1]['openconfig-network-instance:ospfv3'].get('global', {})
                ospf_dict.update(self.get_ospf_globals(ospf_global))
                ospf_dict.update(self.get_ospf_timers(ospf_global))
                ospf_dict.update(self.get_ospf_redistribute(ospf_global.get("openconfig-ospfv3-ext:route-distribution-policies", {})))
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
            self.update_dict(ospf_dict, 'auto_cost_reference_bandwidth', config.get('openconfig-ospfv3-ext:auto-cost-reference-bandwidth'))
            self.update_dict(ospf_dict, 'maximum_paths', config.get('openconfig-ospfv3-ext:maximum-paths'))
            self.update_dict(ospf_dict, 'write_multiplier', config.get('openconfig-ospfv3-ext:write-multiplier'))
            self.update_dict(ospf_dict, 'log_adjacency_changes', config.get('openconfig-ospfv3-ext:log-adjacency-state-changes'))
            if 'log_adjacency_changes' in ospf_dict:
                ospf_dict['log_adjacency_changes'] = 'brief' if 'BRIEF' in ospf_dict['log_adjacency_changes'] else 'detail'

        if ospf_global.get("openconfig-ospfv3-ext:distance"):
            distance_config = ospf_global.get("openconfig-ospfv3-ext:distance").get("config")
            self.update_dict(ospf_dict, "all", distance_config.get("all"), "distance")
            self.update_dict(ospf_dict, "external", distance_config.get("external"), "distance")
            self.update_dict(ospf_dict, "inter_area", distance_config.get("inter-area"), "distance")
            self.update_dict(ospf_dict, "intra_area", distance_config.get("intra-area"), "distance")

        return ospf_dict

    def get_ospf_timers(self, ospf_global):
        timers_dict = {}
        timers = ospf_global.get("openconfig-ospfv3-ext:timers", {})
        lsa_generation = timers.get("lsa-generation")
        spf = timers.get("spf")

        if lsa_generation and lsa_generation.get("config"):
            lsa_config = lsa_generation.get("config")
            self.update_dict(timers_dict, "lsa_min_arrival", lsa_config.get("minimum-arrival"))

        if spf and spf.get("config"):
            throttle_spf = {}
            spf_config = spf.get("config")
            self.update_dict(throttle_spf, "initial_hold_time", spf_config.get("initial-delay"))
            self.update_dict(throttle_spf, "maximum_hold_time", spf_config.get("maximum-delay"))
            self.update_dict(throttle_spf, "delay_time", spf_config.get("throttle-delay"))
            self.update_dict(timers_dict, "throttle_spf", throttle_spf)

        return {"timers": timers_dict}

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
        helpers = graceful_restart.get('openconfig-ospfv3-ext:helpers', {})
        if config:
            self.update_dict(return_dict, 'enable', config.get("enabled"))
            self.update_dict(return_dict, 'grace_period', config.get("openconfig-ospfv3-ext:grace-period"))
            self.update_dict(helper_dict, 'enable', config.get("helper-only"))
            self.update_dict(helper_dict, 'planned_only', config.get("openconfig-ospfv3-ext:planned-only"))
            self.update_dict(helper_dict, 'strict_lsa_checking', config.get("openconfig-ospfv3-ext:strict-lsa-checking"))
            self.update_dict(helper_dict, 'supported_grace_time', config.get("openconfig-ospfv3-ext:supported-grace-time"))
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
