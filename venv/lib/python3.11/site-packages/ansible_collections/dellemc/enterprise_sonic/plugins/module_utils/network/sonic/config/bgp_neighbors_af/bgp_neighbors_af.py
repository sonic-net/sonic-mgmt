#
# -*- coding: utf-8 -*-
# © Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_bgp_neighbors_af class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    update_states,
    get_diff,
    remove_empties_from_list,
    remove_matching_defaults
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF,
    __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF,
    get_new_config,
    get_formatted_config_diff
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.sort_config_util import (
    sort_config,
    remove_void_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.bgp_utils import (
    convert_bgp_asn,
    validate_bgps,
    normalize_neighbors_interface_name,
    get_ip_afi_cfg_payload,
    get_prefix_limit_payload
)
from ansible.module_utils.connection import ConnectionError

PATCH = 'patch'
DELETE = 'delete'
TEST_KEYS = [
    {'config': {'vrf_name': '', 'bgp_as': ''}},
    {'neighbors': {'neighbor': ''}},
    {'address_family': {'afi': '', 'safi': ''}},
    {'route_map': {'name': '', 'direction': ''}},
]

default_entries = [
    [
        {'name': 'neighbors'},
        {'name': 'address_family'},
        {'name': 'route_server_client', 'default': False}
    ],
    [
        {'name': 'neighbors'},
        {'name': 'address_family'},
        {'name': 'activate', 'default': False}
    ],
    [
        {'name': 'neighbors'},
        {'name': 'address_family'},
        {'name': 'fabric_external', 'default': False}
    ]
]

is_delete_all = False
TEST_KEYS_sort_config = [
    {'config': {'__test_keys': ('vrf_name', 'bgp_as')}},
    {'neighbors': {'__test_keys': ('neighbor',)}},
    {'address_family': {'__test_keys': ('afi', 'safi')}},
    {'route_map': {'__test_keys': ('name', 'direction')}},
]


def __derive_bgp_nbrs_af_delete_op(key_set, command, exist_conf):

    done, new_conf = __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, exist_conf)
    if done:
        return done, new_conf
    else:
        return __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, new_conf)


def __derive_bgp_neighbors_af_delete_op(key_set, command, exist_conf):

    if is_delete_all:
        new_conf = {'bgp_as': exist_conf['bgp_as'], 'vrf_name': exist_conf['vrf_name']}
        return True, new_conf

    done, new_conf = __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, exist_conf)
    if not new_conf:
        new_conf = {'bgp_as': command['bgp_as'], 'vrf_name': command['vrf_name']}

    return done, new_conf


TEST_KEYS_generate_config = [
    {'__default_ops': {'__delete_op': __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'config': {'vrf_name': '', 'bgp_as': '', '__delete_op': __derive_bgp_neighbors_af_delete_op}},
    {'neighbors': {'neighbor': '', '__delete_op': __derive_bgp_nbrs_af_delete_op}},
    {'address_family': {'afi': '', 'safi': '', '__delete_op': __derive_bgp_nbrs_af_delete_op}},
    {'route_map': {'name': '', 'direction': '', '__delete_op': __derive_bgp_nbrs_af_delete_op}},
]


class Bgp_neighbors_af(ConfigBase):
    """
    The sonic_bgp_neighbors_af class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'bgp_neighbors_af',
    ]

    network_instance_path = '/data/openconfig-network-instance:network-instances/network-instance'
    protocol_bgp_path = 'protocols/protocol=BGP,bgp/bgp'
    neighbor_path = 'neighbors/neighbor'
    afi_safi_path = 'afi-safis/afi-safi'
    activate_path = "/config/enabled"
    fabric_external_path = "/config/fabric-external"
    ref_client_path = "/config/route-reflector-client"
    serv_client_path = "/config/route-server-client"
    allowas_origin_path = "/allow-own-as/config/origin"
    allowas_value_path = "/allow-own-as/config/as-count"
    allowas_enabled_path = "/allow-own-as/config/enabled"
    prefix_list_in_path = "/prefix-list/config/import-policy"
    prefix_list_out_path = "/prefix-list/config/export-policy"
    def_policy_name_path = "/%s/config/default-policy-name"
    send_def_route_path = "/%s/config/send-default-route"
    max_prefixes_path = "/%s/prefix-limit/config/max-prefixes"
    prv_teardown_path = "/%s/prefix-limit/config/prevent-teardown"
    restart_timer_path = "/%s/prefix-limit/config/restart-timer"
    wrn_threshold_path = "/%s/prefix-limit/config/warning-threshold-pct"
    discard_extra_path = "/%s/prefix-limit/config/openconfig-bgp-ext:discard-extra"

    def __init__(self, module):
        super(Bgp_neighbors_af, self).__init__(module)

    def get_bgp_neighbors_af_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        bgp_neighbors_af_facts = facts['ansible_network_resources'].get('bgp_neighbors_af')
        if not bgp_neighbors_af_facts:
            bgp_neighbors_af_facts = []
        return bgp_neighbors_af_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        existing_bgp_neighbors_af_facts = self.get_bgp_neighbors_af_facts()
        commands, requests = self.set_config(existing_bgp_neighbors_af_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_bgp_neighbors_af_facts = self.get_bgp_neighbors_af_facts()

        result['before'] = existing_bgp_neighbors_af_facts
        if result['changed']:
            result['after'] = changed_bgp_neighbors_af_facts

        new_config = changed_bgp_neighbors_af_facts
        old_config = existing_bgp_neighbors_af_facts
        if self._module.check_mode:
            result.pop('after', None)

            new_config = get_new_config(commands, existing_bgp_neighbors_af_facts,
                                        TEST_KEYS_generate_config)
            new_config = self.post_process_generated_config(new_config)
            old_config = remove_empties_from_list(old_config)
            result['after(generated)'] = new_config

        if self._module._diff:
            new_config = sort_config(new_config, TEST_KEYS_sort_config)
            old_config = sort_config(old_config, TEST_KEYS_sort_config)
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)
        result['warnings'] = warnings
        return result

    def set_config(self, existing_bgp_neighbors_af_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        convert_bgp_asn(want)
        normalize_neighbors_interface_name(want, self._module)
        have = existing_bgp_neighbors_af_facts
        resp = self.set_state(want, have)
        return to_list(resp)

    def set_state(self, want, have):
        """ Select the appropriate function based on the state provided

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []
        state = self._module.params['state']

        diff = get_diff(want, have, TEST_KEYS)

        if state == 'overridden':
            commands, requests = self._state_overridden(want, have)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have, diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have)
        return commands, requests

    def _state_replaced(self, want, have):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, requests = [], []
        new_have = deepcopy(have)
        new_want = deepcopy(want)
        for default_entry in default_entries:
            remove_matching_defaults(new_have, default_entry)
            remove_matching_defaults(new_want, default_entry)
        new_have = remove_empties_from_list(new_have)
        new_want = remove_empties_from_list(new_want)
        self.sort_lists_in_config(new_have)
        self.sort_lists_in_config(new_want)
        add_config, del_config = self._get_replaced_config(new_want, new_have)
        self.sort_lists_in_config(del_config)
        self.sort_lists_in_config(add_config)
        if del_config:
            del_requests = self.get_delete_bgp_neighbors_af_requests(del_config, new_have, (del_config == new_have))
            if del_requests:
                requests.extend(del_requests)
                commands.extend(update_states(del_config, "deleted"))

        if add_config:
            mod_requests = self.get_modify_bgp_neighbors_af_requests(add_config, have, want)

            if len(mod_requests) > 0:
                requests.extend(mod_requests)
                commands.extend(update_states(add_config, "replaced"))
        return commands, requests

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, requests = [], []
        new_have = deepcopy(have)
        new_want = deepcopy(want)
        for default_entry in default_entries:
            remove_matching_defaults(new_have, default_entry)
            remove_matching_defaults(new_want, default_entry)
        new_have = remove_empties_from_list(new_have)
        new_want = remove_empties_from_list(new_want)
        new_have = self.remove_empty_neighbors(new_have)
        diff = get_diff(new_want, new_have, TEST_KEYS)
        diff2 = get_diff(new_have, new_want, TEST_KEYS)
        if diff or diff2:
            del_requests = self.get_delete_bgp_neighbors_af_requests(new_have, new_have, True)
            if len(del_requests) > 0:
                requests.extend(del_requests)
                commands.extend(update_states(have, "deleted"))
            mod_requests = self.get_modify_bgp_neighbors_af_requests(new_want, [], new_want)
            if len(mod_requests) > 0:
                requests.extend(mod_requests)
                commands.extend(update_states(want, "overridden"))

        return commands, requests

    def _state_merged(self, want, have, diff):
        """ The command generator when state is merged

        :param want: the additive configuration as a dictionary
        :param obj_in_have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        validate_bgps(self._module, want, have)
        requests = self.get_modify_bgp_neighbors_af_requests(commands, have, want)
        if commands and len(requests) > 0:
            commands = update_states(commands, "merged")
        else:
            commands = []

        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :param want: the objects from which the configuration should be removed
        :param obj_in_have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        # if want is none, then delete all the bgp_neighbors_afs
        global is_delete_all
        is_delete_all = False
        if not want:
            commands = have
            is_delete_all = True
        else:
            commands = want

        requests = self.get_delete_bgp_neighbors_af_requests(commands, have, is_delete_all)

        if commands and len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []

        return commands, requests

    def remove_empty_neighbors(self, have):
        new_conf = []
        for conf in have:
            temp_conf, temp_nbr = {}, []
            for nbr in conf.get('neighbors', []):
                if 'address_family' in nbr:
                    temp_nbr.append(nbr)
            if temp_nbr:
                temp_conf['bgp_as'] = conf['bgp_as']
                temp_conf['vrf_name'] = conf['vrf_name']
                temp_conf['neighbors'] = temp_nbr
                new_conf.append(temp_conf)
        return new_conf

    def set_val(self, cfg, var, src_key, des_key):
        value = var.get(src_key, None)
        if value is not None:
            cfg[des_key] = value

    def _get_replaced_config(self, want, have):
        add_config, del_config = [], []

        diff1 = get_diff(want, have, TEST_KEYS)
        diff2 = get_diff(have, want, TEST_KEYS)
        for cmd in diff1:
            del_cfg, add_cfg = {}, {}
            vrf_name = cmd.get('vrf_name')
            bgp_as = cmd.get('bgp_as')
            match = next((cfg for cfg in diff2 if (cfg['vrf_name'] == vrf_name and (cfg['bgp_as'] == bgp_as))), None)

            if match:
                neighbors = cmd.get('neighbors', [])
                match_neighbors = match.get('neighbors', [])
                for neigh in neighbors:
                    add_nbr, del_nbr = {}, {}
                    nbr = neigh.get('neighbor')
                    match_nbr = next((nei for nei in match_neighbors if nei['neighbor'] == nbr), None)
                    if match_nbr:
                        for af in neigh.get('address_family', []):
                            afi = af.get('afi')
                            if afi:
                                match_af = next((match_af for match_af in match_nbr.get('address_family', []) if match_af['afi'] == afi), None)
                                if match_af:
                                    add_nbr.setdefault("neighbor", nbr)
                                    add_nbr.setdefault("address_family", [])
                                    add_nbr['address_family'].append(af)
                                    del_nbr.setdefault("neighbor", nbr)
                                    del_nbr.setdefault("address_family", [])
                                    del_nbr['address_family'].append(match_af)
                                else:
                                    add_nbr.setdefault("neighbor", nbr)
                                    add_nbr.setdefault("address_family", [])
                                    add_nbr['address_family'].append(af)
                    else:
                        add_nbr = neigh

                    if add_nbr:
                        add_cfg.setdefault('neighbors', [])
                        add_cfg['neighbors'].append(add_nbr)
                    if del_nbr:
                        del_cfg.setdefault('neighbors', [])
                        del_cfg['neighbors'].append(del_nbr)
            else:
                add_cfg = cmd.get('neighbors', [])

            if add_cfg:
                add_cfg['bgp_as'] = bgp_as
                add_cfg['vrf_name'] = vrf_name
                add_config.append(add_cfg)
            if del_cfg:
                del_cfg['bgp_as'] = bgp_as
                del_cfg['vrf_name'] = vrf_name
                del_config.append(del_cfg)

        return add_config, del_config

    def get_allowas_in(self, match, conf_neighbor_val, conf_afi, conf_safi):
        mat_allowas_in = None
        if match:
            mat_neighbors = match.get('neighbors', None)
            if mat_neighbors:
                mat_neighbor = next((nei for nei in mat_neighbors if nei['neighbor'] == conf_neighbor_val), None)
                if mat_neighbor:
                    mat_nei_addr_fams = mat_neighbor.get('address_family', [])
                    if mat_nei_addr_fams:
                        mat_nei_addr_fam = next((af for af in mat_nei_addr_fams if (af['afi'] == conf_afi and af['safi'] == conf_safi)), None)
                        if mat_nei_addr_fam:
                            mat_allowas_in = mat_nei_addr_fam.get('allowas_in', None)
        return mat_allowas_in

    def get_single_neighbors_af_modify_request(self, match, vrf_name, as_val, conf_neighbor_val, conf_neighbor, want):
        requests = []
        conf_nei_addr_fams = conf_neighbor.get('address_family', [])
        conf_nbr_val = conf_neighbor_val.replace('/', '%2f')
        url = '%s=%s/%s/%s=%s/afi-safis' % (self.network_instance_path, vrf_name, self.protocol_bgp_path, self.neighbor_path, conf_nbr_val)
        payload = {}
        afi_safis = []
        if not conf_nei_addr_fams:
            return requests

        for conf_nei_addr_fam in conf_nei_addr_fams:
            afi_safi = {}
            conf_afi = conf_nei_addr_fam.get('afi', None)
            conf_safi = conf_nei_addr_fam.get('safi', None)
            afi_safi_val = ("{0}_{1}".format(conf_afi, conf_safi)).upper()
            conf_nbr_val = conf_neighbor_val.replace('/', '%2f')
            del_url = "{0}={1}/{2}/{3}={4}/".format(self.network_instance_path, vrf_name, self.protocol_bgp_path, self.neighbor_path, conf_nbr_val)
            del_url += "{0}=openconfig-bgp-types:{1}".format(self.afi_safi_path, afi_safi_val)

            afi_safi_cfg = {}
            if conf_afi and conf_safi:
                afi_safi_name = ("%s_%s" % (conf_afi, conf_safi)).upper()
                afi_safi['afi-safi-name'] = afi_safi_name
                afi_safi_cfg['afi-safi-name'] = afi_safi_name

                self.set_val(afi_safi_cfg, conf_nei_addr_fam, 'activate', 'enabled')
                self.set_val(afi_safi_cfg, conf_nei_addr_fam, 'fabric_external', 'fabric-external')
                self.set_val(afi_safi_cfg, conf_nei_addr_fam, 'route_reflector_client', 'route-reflector-client')
                self.set_val(afi_safi_cfg, conf_nei_addr_fam, 'route_server_client', 'route-server-client')

                if afi_safi_cfg:
                    afi_safi['config'] = afi_safi_cfg

                policy_cfg = {}
                conf_route_map = conf_nei_addr_fam.get('route_map', None)
                if conf_route_map:
                    for route in conf_route_map:
                        policy_key = "import-policy" if "in" == route['direction'] else "export-policy"
                        route_name = route['name']
                        policy_cfg[policy_key] = [route_name]
                if policy_cfg:
                    afi_safi['apply-policy'] = {'config': policy_cfg}

                pfx_lst_cfg = {}
                conf_prefix_list_in = conf_nei_addr_fam.get('prefix_list_in', None)
                conf_prefix_list_out = conf_nei_addr_fam.get('prefix_list_out', None)
                if conf_prefix_list_in:
                    pfx_lst_cfg['import-policy'] = conf_prefix_list_in
                if conf_prefix_list_out:
                    pfx_lst_cfg['export-policy'] = conf_prefix_list_out
                if pfx_lst_cfg:
                    afi_safi['prefix-list'] = {'config': pfx_lst_cfg}

                ip_dict = {}
                ip_afi_cfg = {}
                pfx_lmt_cfg = {}
                conf_ip_afi = conf_nei_addr_fam.get('ip_afi')
                conf_prefix_limit = conf_nei_addr_fam.get('prefix_limit')
                if conf_prefix_limit:
                    pfx_lmt_cfg = get_prefix_limit_payload(conf_prefix_limit)
                if pfx_lmt_cfg and afi_safi_val == 'L2VPN_EVPN':
                    self._module.fail_json('Prefix limit configuration not supported for l2vpn evpn')
                else:
                    if conf_ip_afi:
                        ip_afi_cfg = get_ip_afi_cfg_payload(conf_ip_afi)
                        if ip_afi_cfg:
                            ip_dict['config'] = ip_afi_cfg
                    if pfx_lmt_cfg:
                        ip_dict['prefix-limit'] = {'config': pfx_lmt_cfg}
                    if ip_dict and afi_safi_val == 'IPV4_UNICAST':
                        afi_safi['ipv4-unicast'] = ip_dict
                    elif ip_dict and afi_safi_val == 'IPV6_UNICAST':
                        afi_safi['ipv6-unicast'] = ip_dict

                allowas_in_cfg = {}
                conf_allowas_in = conf_nei_addr_fam.get('allowas_in', None)
                if conf_allowas_in:
                    origin = conf_allowas_in.get('origin', None)
                    value = conf_allowas_in.get('value', None)

                    # Check for a conflict between input allowas_in 'origin' configuration and input allowas_in 'value' configuration.
                    want_bgp_instance = next((cfg for cfg in want if (cfg['vrf_name'] == vrf_name and (cfg['bgp_as'] == as_val))), None)
                    want_allowas_in = self.get_allowas_in(want_bgp_instance, conf_neighbor_val, conf_afi, conf_safi)
                    want_origin = want_allowas_in.get('origin')
                    want_value = want_allowas_in.get('value')
                    if want_origin is True and want_value is not None:
                        self._module.fail_json(msg="No allowas_in 'value' can be configured when setting allowas_in 'origin' to 'true'.")

                    # Remove any existing configuration that conflicts with the input 'allowas_in' configuration before applying
                    # the new requested 'allowas_in' configuration.
                    mat_allowas_in = self.get_allowas_in(match, conf_neighbor_val, conf_afi, conf_safi)

                    if origin is not None:
                        if origin is True and mat_allowas_in:
                            mat_value = mat_allowas_in.get('value', None)
                            if mat_value:
                                self.append_delete_request(requests, mat_value, mat_allowas_in, 'value', del_url, self.allowas_value_path)

                        allowas_in_cfg['origin'] = origin

                    if value is not None:
                        if mat_allowas_in:
                            mat_origin = mat_allowas_in.get('origin', None)
                            if mat_origin:
                                self.append_delete_request(requests, mat_origin, mat_allowas_in, 'origin', del_url, self.allowas_origin_path)

                        allowas_in_cfg['as-count'] = value
                if allowas_in_cfg:
                    allowas_in_cfg['enabled'] = True
                    afi_safi['allow-own-as'] = {'config': allowas_in_cfg}

            if afi_safi:
                afi_safis.append(afi_safi)

        if afi_safis:
            payload = {"openconfig-network-instance:afi-safis": {"afi-safi": afi_safis}}
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        return requests

    def get_delete_neighbor_af_routemaps_requests(self, vrf_name, conf_neighbor_val, afi, safi, routes):
        requests = []
        for route in routes:
            afi_safi_name = ("{0}_{1}".format(afi, safi)).upper()
            policy_type = "import-policy" if "in" == route['direction'] else "export-policy"
            conf_nbr_val = conf_neighbor_val.replace('/', '%2f')
            url = "{0}={1}/{2}/{3}={4}/".format(self.network_instance_path, vrf_name, self.protocol_bgp_path, self.neighbor_path, conf_nbr_val)
            url += "{0}={1}/apply-policy/config/{2}".format(self.afi_safi_path, afi_safi_name, policy_type)
            requests.append({'path': url, 'method': DELETE})
        return requests

    def get_all_neighbors_af_modify_requests(self, match, conf_neighbors, vrf_name, as_val, want):
        requests = []
        for conf_neighbor in conf_neighbors:
            conf_neighbor_val = conf_neighbor.get('neighbor', None)
            if conf_neighbor_val:
                requests.extend(self.get_single_neighbors_af_modify_request(match, vrf_name, as_val, conf_neighbor_val, conf_neighbor, want))
        return requests

    def get_modify_requests(self, conf, match, vrf_name, as_val, want):
        requests = []
        conf_neighbors = conf.get('neighbors', [])
        mat_neighbors = []
        if match and match.get('neighbors', None):
            mat_neighbors = match.get('neighbors')

        if conf_neighbors:
            for conf_neighbor in conf_neighbors:
                conf_neighbor_val = conf_neighbor.get('neighbor', None)
                if conf_neighbor_val is None:
                    continue

                mat_neighbor = next((e_neighbor for e_neighbor in mat_neighbors if e_neighbor['neighbor'] == conf_neighbor_val), None)
                if mat_neighbor is None:
                    continue

                conf_nei_addr_fams = conf_neighbor.get('address_family', None)
                mat_nei_addr_fams = mat_neighbor.get('address_family', None)
                if conf_nei_addr_fams is None or mat_nei_addr_fams is None:
                    continue

                for conf_nei_addr_fam in conf_nei_addr_fams:
                    afi = conf_nei_addr_fam.get('afi', None)
                    safi = conf_nei_addr_fam.get('safi', None)
                    if afi is None or safi is None:
                        continue

                    mat_nei_addr_fam = next((addr_fam for addr_fam in mat_nei_addr_fams if (addr_fam['afi'] == afi and addr_fam['safi'] == safi)), None)
                    if mat_nei_addr_fam is None:
                        continue

                    conf_route_map = conf_nei_addr_fam.get('route_map', None)
                    mat_route_map = mat_nei_addr_fam.get('route_map', None)
                    if conf_route_map is None or mat_route_map is None:
                        continue

                    del_routes = []
                    for route in conf_route_map:
                        exist_route = next((e_route for e_route in mat_route_map if e_route['direction'] == route['direction']), None)
                        if exist_route:
                            del_routes.append(exist_route)
                    if del_routes:
                        requests.extend(self.get_delete_neighbor_af_routemaps_requests(vrf_name, conf_neighbor_val, afi, safi, del_routes))

            requests.extend(self.get_all_neighbors_af_modify_requests(match, conf_neighbors, vrf_name, as_val, want))
        return requests

    def get_modify_bgp_neighbors_af_requests(self, commands, have, want):
        requests = []
        if not commands:
            return requests

        # Create URL and payload
        for conf in commands:
            vrf_name = conf['vrf_name']
            as_val = conf['bgp_as']

            match = next((cfg for cfg in have if (cfg['vrf_name'] == vrf_name and (cfg['bgp_as'] == as_val))), None)
            modify_reqs = self.get_modify_requests(conf, match, vrf_name, as_val, want)
            if modify_reqs:
                requests.extend(modify_reqs)

        return requests

    def append_delete_request(self, requests, cur_var, mat_var, key, url, path):
        ret_value = False
        request = None
        if cur_var is not None and mat_var.get(key, None) == cur_var:
            requests.append({'path': url + path, 'method': DELETE})
            ret_value = True
        return ret_value

    def delete_ip_afi_requests(self, conf_ip_afi, mat_ip_afi, conf_afi_safi_val, url):
        requests = []
        default_policy_name = conf_ip_afi.get('default_policy_name', None)
        send_default_route = conf_ip_afi.get('send_default_route', None)
        if default_policy_name:
            self.append_delete_request(requests, default_policy_name, mat_ip_afi, 'default_policy_name', url, self.def_policy_name_path % (conf_afi_safi_val))
        if send_default_route:
            self.append_delete_request(requests, send_default_route, mat_ip_afi, 'send_default_route', url, self.send_def_route_path % (conf_afi_safi_val))

        return requests

    def delete_prefix_limit_requests(self, conf_prefix_limit, mat_prefix_limit, conf_afi_safi_val, url):
        requests = []
        max_prefixes = conf_prefix_limit.get('max_prefixes', None)
        prevent_teardown = conf_prefix_limit.get('prevent_teardown', None)
        restart_timer = conf_prefix_limit.get('restart_timer', None)
        warning_threshold = conf_prefix_limit.get('warning_threshold', None)
        discard_extra = conf_prefix_limit.get('discard_extra', None)
        if max_prefixes:
            self.append_delete_request(requests, max_prefixes, mat_prefix_limit, 'max_prefixes', url, self.max_prefixes_path % (conf_afi_safi_val))
        if prevent_teardown:
            self.append_delete_request(requests, prevent_teardown, mat_prefix_limit, 'prevent_teardown', url, self.prv_teardown_path % (conf_afi_safi_val))
        if restart_timer:
            self.append_delete_request(requests, restart_timer, mat_prefix_limit, 'restart_timer', url, self.restart_timer_path % (conf_afi_safi_val))
        if warning_threshold:
            self.append_delete_request(requests, warning_threshold, mat_prefix_limit, 'warning_threshold', url, self.wrn_threshold_path % (conf_afi_safi_val))
        if discard_extra:
            self.append_delete_request(requests, discard_extra, mat_prefix_limit, 'discard_extra', url, self.discard_extra_path % (conf_afi_safi_val))

        return requests

    def process_delete_specific_params(self, vrf_name, conf_neighbor_val, conf_nei_addr_fam, conf_afi, conf_safi, matched_nei_addr_fams, url):
        requests = []
        conf_afi_safi_val = ("%s-%s" % (conf_afi, conf_safi))

        mat_nei_addr_fam = None
        if matched_nei_addr_fams:
            mat_nei_addr_fam = next((e_af for e_af in matched_nei_addr_fams if (e_af['afi'] == conf_afi and e_af['safi'] == conf_safi)), None)

        if mat_nei_addr_fam:
            conf_allowas_in = conf_nei_addr_fam.get('allowas_in')
            conf_activate = conf_nei_addr_fam.get('activate')
            conf_fabric_external = conf_nei_addr_fam.get('fabric_external')
            conf_route_map = conf_nei_addr_fam.get('route_map')
            conf_route_reflector_client = conf_nei_addr_fam.get('route_reflector_client')
            conf_route_server_client = conf_nei_addr_fam.get('route_server_client')
            conf_prefix_list_in = conf_nei_addr_fam.get('prefix_list_in')
            conf_prefix_list_out = conf_nei_addr_fam.get('prefix_list_out')
            conf_ip_afi = conf_nei_addr_fam.get('ip_afi')
            conf_prefix_limit = conf_nei_addr_fam.get('prefix_limit')

            var_list = [conf_allowas_in, conf_activate, conf_fabric_external, conf_route_map, conf_route_reflector_client, conf_route_server_client,
                        conf_prefix_list_in, conf_prefix_list_out, conf_ip_afi, conf_prefix_limit]
            if len(list(filter(lambda var: (var is None), var_list))) == len(var_list):
                requests.append({'path': url, 'method': DELETE})
            else:
                mat_route_map = mat_nei_addr_fam.get('route_map', None)
                if conf_route_map and mat_route_map:
                    del_routes = []
                    for route in conf_route_map:
                        if any(e_route for e_route in mat_route_map if route['direction'] == e_route['direction']):
                            del_routes.append(route)
                    if del_routes:
                        requests.extend(self.get_delete_neighbor_af_routemaps_requests(vrf_name, conf_neighbor_val, conf_afi, conf_safi, del_routes))

                self.append_delete_request(requests, conf_activate, mat_nei_addr_fam, 'activate', url, self.activate_path)
                self.append_delete_request(requests, conf_fabric_external, mat_nei_addr_fam, 'fabric_external', url, self.fabric_external_path)
                self.append_delete_request(requests, conf_route_reflector_client, mat_nei_addr_fam, 'route_reflector_client', url, self.ref_client_path)
                self.append_delete_request(requests, conf_route_server_client, mat_nei_addr_fam, 'route_server_client', url, self.serv_client_path)
                self.append_delete_request(requests, conf_prefix_list_in, mat_nei_addr_fam, 'prefix_list_in', url, self.prefix_list_in_path)
                self.append_delete_request(requests, conf_prefix_list_out, mat_nei_addr_fam, 'prefix_list_out', url, self.prefix_list_out_path)

                mat_allowas_in = mat_nei_addr_fam.get('allowas_in', None)
                if conf_allowas_in is not None and mat_allowas_in:
                    origin = conf_allowas_in.get('origin', None)
                    value = conf_allowas_in.get('value', None)
                    mat_allowas_in_options = {}
                    mat_origin = mat_allowas_in.get('origin', None)
                    if mat_origin is not None:
                        mat_allowas_in_options.update({'origin': mat_origin})
                    mat_value = mat_allowas_in.get('value', None)
                    if mat_value is not None:
                        mat_allowas_in_options.update({'value': mat_value})

                    if origin is not None:
                        if self.append_delete_request(requests, origin, mat_allowas_in, 'origin', url, self.allowas_origin_path):
                            if mat_allowas_in_options.get('origin') is not None:
                                del (mat_allowas_in_options['origin'])
                    if value is not None:
                        if self.append_delete_request(requests, value, mat_allowas_in, 'value', url, self.allowas_value_path):
                            if mat_allowas_in_options.get('value') is not None:
                                del (mat_allowas_in_options['value'])
                    if not mat_allowas_in_options:
                        self.append_delete_request(requests, True, {'enabled': True}, 'enabled', url, self.allowas_enabled_path)

                mat_ip_afi = mat_nei_addr_fam.get('ip_afi', None)
                mat_prefix_limit = mat_nei_addr_fam.get('prefix_limit', None)
                if conf_ip_afi and mat_ip_afi:
                    requests.extend(self.delete_ip_afi_requests(conf_ip_afi, mat_ip_afi, conf_afi_safi_val, url))
                if conf_prefix_limit and mat_prefix_limit:
                    requests.extend(self.delete_prefix_limit_requests(conf_prefix_limit, mat_prefix_limit, conf_afi_safi_val, url))

        return requests

    def process_neighbor_delete_address_families(self, vrf_name, conf_nei_addr_fams, matched_nei_addr_fams, neighbor_val, is_delete_all):
        requests = []

        for conf_nei_addr_fam in conf_nei_addr_fams:
            conf_afi = conf_nei_addr_fam.get('afi', None)
            conf_safi = conf_nei_addr_fam.get('safi', None)
            if not conf_afi or not conf_safi:
                continue
            afi_safi = ("{0}_{1}".format(conf_afi, conf_safi)).upper()
            nbr_val = neighbor_val.replace('/', '%2f')
            url = "{0}={1}/{2}/{3}={4}/".format(self.network_instance_path, vrf_name, self.protocol_bgp_path, self.neighbor_path, nbr_val)
            url += "{0}=openconfig-bgp-types:{1}".format(self.afi_safi_path, afi_safi)
            if is_delete_all:
                requests.append({'path': url, 'method': DELETE})
            else:
                requests.extend(self.process_delete_specific_params(vrf_name, neighbor_val, conf_nei_addr_fam, conf_afi, conf_safi, matched_nei_addr_fams, url))

        return requests

    def get_delete_single_bgp_neighbors_af_request(self, conf, is_delete_all, match=None):
        requests = []
        vrf_name = conf['vrf_name']
        conf_neighbors = conf.get('neighbors', [])

        if match and not conf_neighbors:
            conf_neighbors = match.get('neighbors', [])
            if conf_neighbors:
                conf_neighbors = [{'neighbor': nei['neighbor']} for nei in conf_neighbors]

        if not conf_neighbors:
            return requests
        mat_neighbors = None
        if match:
            mat_neighbors = match.get('neighbors', [])

        for conf_neighbor in conf_neighbors:
            conf_neighbor_val = conf_neighbor.get('neighbor', None)
            if not conf_neighbor_val:
                continue

            mat_neighbor = None
            if mat_neighbors:
                mat_neighbor = next((e_nei for e_nei in mat_neighbors if e_nei['neighbor'] == conf_neighbor_val), None)

            conf_nei_addr_fams = conf_neighbor.get('address_family', None)
            if mat_neighbor and not conf_nei_addr_fams:
                conf_nei_addr_fams = mat_neighbor.get('address_family', None)
                if conf_nei_addr_fams:
                    conf_nei_addr_fams = [{'afi': af['afi'], 'safi': af['safi']} for af in conf_nei_addr_fams]

            if not conf_nei_addr_fams:
                continue

            mat_nei_addr_fams = None
            if mat_neighbor:
                mat_nei_addr_fams = mat_neighbor.get('address_family', None)

            requests.extend(self.process_neighbor_delete_address_families(vrf_name, conf_nei_addr_fams, mat_nei_addr_fams, conf_neighbor_val, is_delete_all))

        return requests

    def get_delete_bgp_neighbors_af_requests(self, commands, have, is_delete_all):
        requests = []
        for cmd in commands:
            vrf_name = cmd['vrf_name']
            as_val = cmd['bgp_as']
            match = None
            if not is_delete_all:
                match = next((have_cfg for have_cfg in have if have_cfg['vrf_name'] == vrf_name and have_cfg['bgp_as'] == as_val), None)
            requests.extend(self.get_delete_single_bgp_neighbors_af_request(cmd, is_delete_all, match))
        return requests

    def sort_lists_in_config(self, config):
        if config:
            config.sort(key=lambda x: (x['vrf_name'], x['bgp_as']))
            for cfg in config:
                if cfg.get('neighbors'):
                    cfg['neighbors'].sort(key=lambda x: x['neighbor'])
                    for nbr in cfg['neighbors']:
                        if nbr.get('address_family'):
                            nbr['address_family'].sort(key=lambda x: x['afi'])
                            for afis in nbr['address_family']:
                                if afis.get('route_map'):
                                    afis['route_map'].sort(key=lambda x: x['name'])

    def post_process_generated_config(self, configs):
        TEST_KEYS_remove_void_config = [
            {'neighbors': {'__test_keys': ('neighbor',)}},
            {'address_family': {'__test_keys': ('afi', 'safi')}},
        ]
        confs = remove_void_config(configs, TEST_KEYS_remove_void_config)
        return confs
