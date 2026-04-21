#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_bgp_af class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

try:
    from urllib import quote_plus
except ImportError:
    from urllib.parse import quote_plus

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    remove_empties,
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
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_CONFIG_IF_NO_NON_KEY_LEAF_OR_SUBCONFIG,
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
    validate_bgps
)
from ansible.module_utils.connection import ConnectionError

PATCH = 'patch'
DELETE = 'delete'
TEST_KEYS = [
    {'config': {'vrf_name': '', 'bgp_as': ''}},
    {'afis': {'afi': '', 'safi': ''}},
    {'redistribute': {'protocol': ''}},
    {'route_advertise_list': {'advertise_afi': ''}},
    {'vnis': {'vni_number': ''}},
    {'aggregate_address_config': {'prefix': ''}}
]
TEST_KEYS_sort_config = [
    {'config': {'__test_keys': ('bgp_as', 'vrf_name')}},
    {'afis': {'__test_keys': ('afi', 'safi')}},
    {'redistribute': {'__test_keys': ('protocol',)}},
    {'route_advertise_list': {'__test_keys': ('advertise_afi',)}},
    {'vnis': {'__test_keys': ('vni_number',)}},
    {'aggregate_address_config': {'__test_keys': ('prefix',)}}
]

is_delete_all = False


def __derive_bgp_af_sub_config_delete_op(key_set, command, exist_conf):
    new_conf = exist_conf
    done, new_conf = __DELETE_CONFIG_IF_NO_NON_KEY_LEAF_OR_SUBCONFIG(key_set, command, exist_conf)
    if done:
        return done, new_conf
    else:
        return __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, new_conf)


def __derive_bgp_af_delete_op(key_set, command, exist_conf):
    if is_delete_all:
        new_conf = []
        return True, new_conf

    return __derive_bgp_af_sub_config_delete_op(key_set, command, exist_conf)


TEST_KEYS_generate_config = [
    {'config': {'vrf_name': '', 'bgp_as': '',
                '__delete_op': __derive_bgp_af_delete_op}},
    {'afis': {'afi': '', 'safi': '',
              '__delete_op': __derive_bgp_af_sub_config_delete_op}},
    {'redistribute': {'protocol': '',
                      '__delete_op': __derive_bgp_af_sub_config_delete_op}},
    {'route_advertise_list': {'advertise_afi': '',
                              '__delete_op': __derive_bgp_af_sub_config_delete_op}},
    {'vnis': {'vni_number': '',
              '__delete_op': __derive_bgp_af_sub_config_delete_op}},
    {'aggregate_address_config': {'prefix': '',
                                  '__delete_op': __derive_bgp_af_sub_config_delete_op}}
]


class Bgp_af(ConfigBase):
    """
    The sonic_bgp_af class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'bgp_af',
    ]

    network_instance_path = '/data/openconfig-network-instance:network-instances/network-instance'
    protocol_bgp_path = 'protocols/protocol=BGP,bgp/bgp'
    l2vpn_evpn_config_path = 'l2vpn-evpn/openconfig-bgp-evpn-ext:config'
    l2vpn_evpn_route_advertise_path = 'l2vpn-evpn/openconfig-bgp-evpn-ext:route-advertise'
    l2vpn_evpn_vnis_path = 'l2vpn-evpn/openconfig-bgp-evpn-ext:vnis'
    afi_safi_path = 'global/afi-safis/afi-safi'
    table_connection_path = 'table-connections/table-connection'

    dad_attrs = (
        'enabled',
        'freeze',
        'max_moves',
        'time'
    )
    advertise_attrs_map = {
        'advertise_pip': 'advertise-pip',
        'advertise_pip_ip': 'advertise-pip-ip',
        'advertise_pip_peer_ip': 'advertise-pip-peer-ip',
        'advertise_svi_ip': 'advertise-svi-ip',
        'advertise_default_gw': 'advertise-default-gw',
        'advertise_all_vni': 'advertise-all-vni',
        'rd': 'route-distinguisher',
        'rt_in': 'import-rts',
        'rt_out': 'export-rts'
    }
    non_list_advertise_attrs = (
        'advertise_pip',
        'advertise_pip_ip',
        'advertise_pip_peer_ip',
        'advertise_svi_ip',
        'advertise_default_gw',
        'advertise_all_vni',
        'rd'
    )

    def __init__(self, module):
        super(Bgp_af, self).__init__(module)

    def get_bgp_af_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        bgp_af_facts = facts['ansible_network_resources'].get('bgp_af')
        if not bgp_af_facts:
            bgp_af_facts = []
        return bgp_af_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        existing_bgp_af_facts = self.get_bgp_af_facts()
        commands, requests = self.set_config(existing_bgp_af_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_bgp_af_facts = self.get_bgp_af_facts()

        result['before'] = existing_bgp_af_facts
        if result['changed']:
            result['after'] = changed_bgp_af_facts

        new_config = changed_bgp_af_facts
        old_config = existing_bgp_af_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_bgp_af_facts,
                                        TEST_KEYS_generate_config)
            new_config = remove_void_config(new_config, TEST_KEYS_sort_config)
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

    def set_config(self, existing_bgp_af_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        state = self._module.params['state']
        want = self._module.params['config']
        if want:
            convert_bgp_asn(want)
            # In state deleted, specific empty parameters are supported
            if state != 'deleted':
                want = [remove_empties(conf) for conf in want]
        else:
            want = []

        have = existing_bgp_af_facts
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

        if state == 'overridden':
            commands, requests = self._state_overridden(want, have)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have)

        return commands, requests

    def _state_replaced(self, want, have):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []
        validate_bgps(self._module, want, have)

        del_commands, del_requests = self.get_delete_commands_requests_for_replaced_overridden(want, have, 'replaced')
        if del_commands:
            commands = update_states(del_commands, 'deleted')
            requests = del_requests

        add_commands = get_diff(want, have, TEST_KEYS)
        if add_commands:
            commands.extend(update_states(add_commands, 'replaced'))
            requests.extend(self.get_modify_bgp_af_requests(add_commands, have))

        return commands, requests

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []
        validate_bgps(self._module, want, have)

        del_commands, del_requests = self.get_delete_commands_requests_for_replaced_overridden(want, have, 'overridden')
        if del_commands:
            commands = update_states(del_commands, 'deleted')
            requests = del_requests

        add_commands = get_diff(want, have, TEST_KEYS)
        if add_commands:
            commands.extend(update_states(add_commands, 'overridden'))
            requests.extend(self.get_modify_bgp_af_requests(add_commands, have))

        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :param want: the additive configuration as a dictionary
        :param obj_in_have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = get_diff(want, have, TEST_KEYS)
        validate_bgps(self._module, commands, have)
        requests = self.get_modify_bgp_af_requests(commands, have)
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
        # if want is none, then delete all the bgp_afs
        global is_delete_all
        is_delete_all = False
        if not want:
            commands = have
            is_delete_all = True
        else:
            commands = want

        requests = self.get_delete_bgp_af_requests(commands, have, is_delete_all)

        if commands and len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []
        return commands, requests

    def get_modify_address_family_request(self, vrf_name, conf_afi, conf_safi):
        afi_safi = ("%s_%s" % (conf_afi, conf_safi)).upper()
        url = '%s=%s/%s/global' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
        afi_safi_load = {'afi-safi-name': ("openconfig-bgp-types:%s" % (afi_safi))}
        afi_safis_load = {'afi-safis': {'afi-safi': [afi_safi_load]}}
        pay_load = {'openconfig-network-instance:global': afi_safis_load}

        return ({"path": url, "method": PATCH, "data": pay_load})

    def get_modify_evpn_adv_cfg_request(self, vrf_name, conf_afi, conf_safi, conf_addr_fam):
        request = None
        conf_adv_pip = conf_addr_fam.get('advertise_pip', None)
        conf_adv_pip_ip = conf_addr_fam.get('advertise_pip_ip', None)
        conf_adv_pip_peer_ip = conf_addr_fam.get('advertise_pip_peer_ip', None)
        conf_adv_svi_ip = conf_addr_fam.get('advertise_svi_ip', None)
        conf_adv_all_vni = conf_addr_fam.get('advertise_all_vni', None)
        conf_adv_default_gw = conf_addr_fam.get('advertise_default_gw', None)
        conf_rd = conf_addr_fam.get('rd', None)
        conf_rt_in = conf_addr_fam.get('rt_in', [])
        conf_rt_out = conf_addr_fam.get('rt_out', [])
        afi_safi = ("%s_%s" % (conf_afi, conf_safi)).upper()
        evpn_cfg = {}

        if conf_adv_pip is not None:
            evpn_cfg['advertise-pip'] = conf_adv_pip
        if conf_adv_pip_ip:
            evpn_cfg['advertise-pip-ip'] = conf_adv_pip_ip
        if conf_adv_pip_peer_ip:
            evpn_cfg['advertise-pip-peer-ip'] = conf_adv_pip_peer_ip
        if conf_adv_svi_ip is not None:
            evpn_cfg['advertise-svi-ip'] = conf_adv_svi_ip
        if conf_adv_all_vni is not None:
            evpn_cfg['advertise-all-vni'] = conf_adv_all_vni
        if conf_adv_default_gw is not None:
            evpn_cfg['advertise-default-gw'] = conf_adv_default_gw
        if conf_rd:
            evpn_cfg['route-distinguisher'] = conf_rd
        if conf_rt_in:
            evpn_cfg['import-rts'] = conf_rt_in
        if conf_rt_out:
            evpn_cfg['export-rts'] = conf_rt_out

        if evpn_cfg:
            url = '%s=%s/%s/global' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
            afi_safi_load = {'afi-safi-name': ("openconfig-bgp-types:%s" % (afi_safi))}
            afi_safi_load['l2vpn-evpn'] = {'openconfig-bgp-evpn-ext:config': evpn_cfg}
            afi_safis_load = {'afi-safis': {'afi-safi': [afi_safi_load]}}
            pay_load = {'openconfig-network-instance:global': afi_safis_load}
            request = {"path": url, "method": PATCH, "data": pay_load}

        return request

    def get_modify_evpn_vnis_request(self, vrf_name, conf_afi, conf_safi, conf_addr_fam):
        request = None
        conf_vnis = conf_addr_fam.get('vnis', [])
        afi_safi = ("%s_%s" % (conf_afi, conf_safi)).upper()
        vnis_dict = {}
        vni_list = []

        if conf_vnis:
            for vni in conf_vnis:
                vni_dict = {}
                cfg = {}
                vni_number = vni.get('vni_number', None)
                adv_default_gw = vni.get('advertise_default_gw', None)
                adv_svi_ip = vni.get('advertise_svi_ip', None)
                rd = vni.get('rd', None)
                rt_in = vni.get('rt_in', [])
                rt_out = vni.get('rt_out', [])

                if vni_number:
                    cfg['vni-number'] = vni_number
                if adv_default_gw is not None:
                    cfg['advertise-default-gw'] = adv_default_gw
                if adv_svi_ip is not None:
                    cfg['advertise-svi-ip'] = adv_svi_ip
                if rd:
                    cfg['route-distinguisher'] = rd
                if rt_in:
                    cfg['import-rts'] = rt_in
                if rt_out:
                    cfg['export-rts'] = rt_out
                if cfg:
                    vni_dict['config'] = cfg
                    vni_dict['vni-number'] = vni_number
                    vni_list.append(vni_dict)

        if vni_list:
            vnis_dict['vni'] = vni_list
            url = '%s=%s/%s/global' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
            afi_safi_load = {'afi-safi-name': ("openconfig-bgp-types:%s" % (afi_safi))}
            afi_safi_load['l2vpn-evpn'] = {'openconfig-bgp-evpn-ext:vnis': vnis_dict}
            afi_safis_load = {'afi-safis': {'afi-safi': [afi_safi_load]}}
            pay_load = {'openconfig-network-instance:global': afi_safis_load}
            request = {"path": url, "method": PATCH, "data": pay_load}

        return request

    def get_modify_route_advertise_list_request(self, vrf_name, conf_afi, conf_safi, conf_addr_fam):
        request = []
        route_advertise = []
        afi_safi = ('%s_%s' % (conf_afi, conf_safi)).upper()
        route_advertise_list = conf_addr_fam.get('route_advertise_list', [])
        if route_advertise_list:
            for rt_adv in route_advertise_list:
                advertise_afi = rt_adv.get('advertise_afi', None)
                route_map = rt_adv.get('route_map', None)
                if advertise_afi:
                    advertise_afi_safi = '%s_UNICAST' % advertise_afi.upper()
                    url = '%s=%s/%s' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
                    url += '/%s=%s/%s/route-advertise-list' % (self.afi_safi_path, afi_safi, self.l2vpn_evpn_route_advertise_path)
                    cfg = None
                    if route_map:
                        route_map_list = [route_map]
                        cfg = {'advertise-afi-safi': advertise_afi_safi, 'route-map': route_map_list}
                    else:
                        cfg = {'advertise-afi-safi': advertise_afi_safi}
                    route_advertise.append({'advertise-afi-safi': advertise_afi_safi, 'config': cfg})
            pay_load = {'openconfig-bgp-evpn-ext:route-advertise-list': route_advertise}
            request = {"path": url, "method": PATCH, "data": pay_load}
        return request

    def get_modify_redistribute_requests(self, vrf_name, conf_afi, conf_safi, conf_redis_arr):
        requests = []
        url = "%s=%s/table-connections" % (self.network_instance_path, vrf_name)
        cfgs = []
        for conf_redis in conf_redis_arr:
            conf_metric = conf_redis.get('metric', None)
            if conf_metric is not None:
                conf_metric = float(conf_redis['metric'])

            afi_cfg = "openconfig-types:%s" % (conf_afi.upper())
            cfg_data = {'address-family': afi_cfg}
            cfg_data['dst-protocol'] = "openconfig-policy-types:BGP"
            conf_protocol = conf_redis['protocol'].upper()
            if conf_protocol == 'CONNECTED':
                conf_protocol = "DIRECTLY_CONNECTED"
            cfg_data['src-protocol'] = "openconfig-policy-types:%s" % (conf_protocol)
            cfg_data['config'] = {'address-family': afi_cfg}
            if conf_metric is not None:
                cfg_data['config']['metric'] = conf_metric

            conf_route_map = conf_redis.get('route_map', None)
            if conf_route_map:
                cfg_data['config']['import-policy'] = [conf_route_map]

            cfgs.append(cfg_data)

        if cfgs:
            pay_load = {'openconfig-network-instance:table-connections': {'table-connection': cfgs}}
            requests.append({"path": url, "method": PATCH, "data": pay_load})
        return requests

    def get_modify_max_path_request(self, vrf_name, conf_afi, conf_safi, conf_max_path):
        request = None
        afi_safi = ("%s_%s" % (conf_afi, conf_safi)).upper()
        url = '%s=%s/%s/' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
        url += '%s=%s/use-multiple-paths' % (self.afi_safi_path, afi_safi)
        conf_ebgp = conf_max_path.get('ebgp', None)
        conf_ibgp = conf_max_path.get('ibgp', None)
        max_path_load = {}
        if conf_ebgp:
            max_path_load['ebgp'] = {'config': {'maximum-paths': conf_ebgp}}
        if conf_ibgp:
            max_path_load['ibgp'] = {'config': {'maximum-paths': conf_ibgp}}

        pay_load = {}
        if max_path_load:
            pay_load['openconfig-network-instance:use-multiple-paths'] = max_path_load

        request = {"path": url, "method": PATCH, "data": pay_load}
        return request

    def get_modify_network_request(self, vrf_name, conf_afi, conf_safi, conf_network):
        request = None
        afi_safi = ("%s_%s" % (conf_afi, conf_safi)).upper()
        url = '%s=%s/%s/' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
        url += '%s=%s/network-config' % (self.afi_safi_path, afi_safi)
        network_payload = []
        for each in conf_network:
            payload = {}
            payload = {'config': {'prefix': each}, 'prefix': each}
            network_payload.append(payload)
        if network_payload:
            new_payload = {'network-config': {'network': network_payload}}

        request = {"path": url, "method": PATCH, "data": new_payload}
        return request

    def get_modify_dampening_request(self, vrf_name, conf_afi, conf_safi, conf_dampening):
        request = None
        afi_safi = ("%s_%s" % (conf_afi, conf_safi)).upper()
        url = '%s=%s/%s/' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
        url += '%s=%s/route-flap-damping' % (self.afi_safi_path, afi_safi)
        damp_payload = {'route-flap-damping': {'config': {'enabled': conf_dampening}}}
        if damp_payload:
            request = {"path": url, "method": PATCH, "data": damp_payload}
        return request

    def get_modify_aggregate_request(self, vrf_name, conf_afi, conf_safi, conf_aggregate):
        request = None

        if conf_aggregate:
            addr_list = []
            for addr in conf_aggregate:
                config_dict = {}
                prefix = addr.get('prefix')
                as_set = addr.get('as_set')
                policy_name = addr.get('policy_name')
                summary_only = addr.get('summary_only')

                if as_set is not None:
                    config_dict['as-set'] = as_set
                if policy_name:
                    config_dict['policy-name'] = policy_name
                if summary_only is not None:
                    config_dict['summary-only'] = summary_only
                if prefix:
                    config_dict['prefix'] = prefix
                    addr_list.append({'prefix': prefix, 'config': config_dict})
            if addr_list:
                payload = {'openconfig-network-instance:aggregate-address-config': {'aggregate-address': addr_list}}
                afi_safi = ("%s_%s" % (conf_afi, conf_safi)).upper()
                url = '%s=%s/%s/' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
                url += '%s=%s/aggregate-address-config' % (self.afi_safi_path, afi_safi)
                request = {'path': url, 'method': PATCH, 'data': payload}

        return request

    def get_modify_import_request(self, vrf_name, conf_afi, conf_safi, conf_import):
        request = None
        url = '{0}={1}/{2}/{3}={4}_{5}/openconfig-bgp-ext:import-network-instance'.format(self.network_instance_path, vrf_name, self.protocol_bgp_path,
                                                                                          self.afi_safi_path, conf_afi.upper(), conf_safi.upper())
        import_config_payload = {}
        import_payload = {'openconfig-bgp-ext:import-network-instance': {'config': import_config_payload}}
        if conf_import and conf_import.get('vrf'):
            if conf_import['vrf'].get('vrf_list'):
                import_config_payload['name'] = conf_import['vrf']['vrf_list']
            if conf_import['vrf'].get('route_map'):
                import_config_payload['policy-name'] = conf_import['vrf']['route_map']
        if import_config_payload:
            request = {"path": url, "method": PATCH, "data": import_payload}
        return request

    def get_modify_dad_requests(self, vrf_name, conf_afi, conf_safi, conf_addr_fam):
        requests = []
        url = '{0}={1}/{2}/{3}={4}_{5}/l2vpn-evpn/openconfig-bgp-evpn-ext:dup-addr-detection/config'.format(self.network_instance_path, vrf_name,
                                                                                                            self.protocol_bgp_path, self.afi_safi_path,
                                                                                                            conf_afi.upper(), conf_safi.upper())

        dad_payload = {}
        conf_dad = conf_addr_fam.get('dup_addr_detection')
        if conf_dad:
            for attr in self.dad_attrs:
                if conf_dad.get(attr) is not None:
                    dad_payload[attr.replace('_', '-')] = conf_dad[attr]

            if dad_payload:
                requests.append({"path": url, "method": PATCH, "data": {'openconfig-bgp-evpn-ext:config': dad_payload}})

        return requests

    def get_modify_single_af_request(self, vrf_name, conf_afi, conf_safi, conf_addr_fam):
        requests = []

        requests.append(self.get_modify_address_family_request(vrf_name, conf_afi, conf_safi))
        if conf_afi == 'ipv4' and conf_safi == 'unicast':
            conf_dampening = conf_addr_fam.get('dampening', None)
            if conf_dampening:
                request = self.get_modify_dampening_request(vrf_name, conf_afi, conf_safi, conf_dampening)
                if request:
                    requests.append(request)
        if conf_afi in ['ipv4', 'ipv6'] and conf_safi == 'unicast':
            conf_redis_arr = conf_addr_fam.get('redistribute', [])
            if conf_redis_arr:
                requests.extend(self.get_modify_redistribute_requests(vrf_name, conf_afi, conf_safi, conf_redis_arr))
            conf_max_path = conf_addr_fam.get('max_path', None)
            if conf_max_path:
                request = self.get_modify_max_path_request(vrf_name, conf_afi, conf_safi, conf_max_path)
                if request:
                    requests.append(request)
            conf_network = conf_addr_fam.get('network', [])
            if conf_network:
                request = self.get_modify_network_request(vrf_name, conf_afi, conf_safi, conf_network)
                if request:
                    requests.append(request)
            conf_import = conf_addr_fam.get('import', None)
            if conf_import:
                import_req = self.get_modify_import_request(vrf_name, conf_afi, conf_safi, conf_import)
                if import_req:
                    requests.append(import_req)
            conf_aggregate = conf_addr_fam.get('aggregate_address_config')
            if conf_aggregate:
                request = self.get_modify_aggregate_request(vrf_name, conf_afi, conf_safi, conf_aggregate)
                if request:
                    requests.append(request)
        elif conf_afi == "l2vpn" and conf_safi == 'evpn':
            cfg_req = self.get_modify_evpn_adv_cfg_request(vrf_name, conf_afi, conf_safi, conf_addr_fam)
            vni_req = self.get_modify_evpn_vnis_request(vrf_name, conf_afi, conf_safi, conf_addr_fam)
            rt_adv_req = self.get_modify_route_advertise_list_request(vrf_name, conf_afi, conf_safi, conf_addr_fam)
            dad_reqs = self.get_modify_dad_requests(vrf_name, conf_afi, conf_safi, conf_addr_fam)
            dad_enabled = conf_addr_fam.get('dup_addr_detection', {}).get('enabled')
            # 'dup_addr_detection' can be modified irrespective of 'advertise_all_vni' configuration,
            # but it can be disabled only if 'advertise_all_vni' is enabled.
            if dad_reqs and dad_enabled:
                requests.extend(dad_reqs)
            if cfg_req:
                requests.append(cfg_req)
            if dad_reqs and not dad_enabled:
                requests.extend(dad_reqs)
            if vni_req:
                requests.append(vni_req)
            if rt_adv_req:
                requests.append(rt_adv_req)
        return requests

    def get_modify_all_af_requests(self, conf_addr_fams, vrf_name):
        requests = []
        for conf_addr_fam in conf_addr_fams:
            conf_afi = conf_addr_fam.get('afi', None)
            conf_safi = conf_addr_fam.get('safi', None)
            if conf_afi and conf_safi:
                requests.extend(self.get_modify_single_af_request(vrf_name, conf_afi, conf_safi, conf_addr_fam))
        return requests

    def get_modify_requests(self, conf, match, vrf_name):
        requests = []
        payload = {}
        conf_addr_fams = conf.get('address_family', None)
        if conf_addr_fams:
            conf_addr_fams = conf_addr_fams.get('afis', [])

        mat_addr_fams = []
        if match:
            mat_addr_fams = match.get('address_family', None)
            if mat_addr_fams:
                mat_addr_fams = mat_addr_fams.get('afis', [])

        if conf_addr_fams and not mat_addr_fams:
            requests.extend(self.get_modify_all_af_requests(conf_addr_fams, vrf_name))
        else:
            for conf_addr_fam in conf_addr_fams:
                conf_afi = conf_addr_fam.get('afi', None)
                conf_safi = conf_addr_fam.get('safi', None)

                if conf_afi is None or conf_safi is None:
                    continue

                mat_addr_fam = next((e_addr_fam for e_addr_fam in mat_addr_fams if (e_addr_fam['afi'] == conf_afi and e_addr_fam['safi'] == conf_safi)), None)

                if mat_addr_fam is None:
                    requests.extend(self.get_modify_single_af_request(vrf_name, conf_afi, conf_safi, conf_addr_fam))
                    continue

                if conf_afi == 'ipv4' and conf_safi == 'unicast':
                    conf_dampening = conf_addr_fam.get('dampening', None)
                    if conf_dampening is not None:
                        request = self.get_modify_dampening_request(vrf_name, conf_afi, conf_safi, conf_dampening)
                        if request:
                            requests.append(request)

                if conf_afi == "l2vpn" and conf_safi == "evpn":
                    cfg_req = self.get_modify_evpn_adv_cfg_request(vrf_name, conf_afi, conf_safi, conf_addr_fam)
                    vni_req = self.get_modify_evpn_vnis_request(vrf_name, conf_afi, conf_safi, conf_addr_fam)
                    rt_adv_req = self.get_modify_route_advertise_list_request(vrf_name, conf_afi, conf_safi, conf_addr_fam)
                    dad_reqs = self.get_modify_dad_requests(vrf_name, conf_afi, conf_safi, conf_addr_fam)
                    dad_enabled = conf_addr_fam.get('dup_addr_detection', {}).get('enabled')
                    # 'dup_addr_detection' can be modified irrespective of 'advertise_all_vni' configuration,
                    # but it can be disabled only if 'advertise_all_vni' is enabled.
                    if dad_reqs and dad_enabled:
                        requests.extend(dad_reqs)
                    if cfg_req:
                        requests.append(cfg_req)
                    if dad_reqs and not dad_enabled:
                        requests.extend(dad_reqs)
                    if vni_req:
                        requests.append(vni_req)
                    if rt_adv_req:
                        requests.append(rt_adv_req)

                elif conf_afi in ["ipv4", "ipv6"] and conf_safi == "unicast":
                    conf_redis_arr = conf_addr_fam.get('redistribute', [])
                    conf_max_path = conf_addr_fam.get('max_path', None)
                    conf_network = conf_addr_fam.get('network', [])
                    conf_import = conf_addr_fam.get('import', None)
                    conf_aggregate = conf_addr_fam.get('aggregate_address_config')
                    if not conf_redis_arr and not conf_max_path and not conf_network and not conf_import and not conf_aggregate:
                        continue

                    url = "%s=%s/table-connections" % (self.network_instance_path, vrf_name)
                    pay_loads = []
                    modify_redis_arr = []
                    for conf_redis in conf_redis_arr:
                        conf_metric = conf_redis.get('metric', None)
                        if conf_metric is not None:
                            conf_metric = float(conf_redis['metric'])

                        conf_route_map = conf_redis.get('route_map', None)

                        have_redis_arr = mat_addr_fam.get('redistribute', [])
                        have_redis = None
                        have_route_map = None
                        if have_redis_arr:
                            have_redis = next((redis_cfg for redis_cfg in have_redis_arr if conf_redis['protocol'] == redis_cfg['protocol']), None)

                        # Check the route_map, if existing route_map is different from required route_map, delete the existing route map
                        if conf_route_map and have_redis:
                            have_route_map = have_redis.get('route_map', None)
                            if have_route_map and have_route_map != conf_route_map:
                                requests.append(self.get_delete_redistribute_route_map_request(vrf_name, conf_afi, have_redis, have_route_map))

                        modify_redis = {}
                        if conf_metric is not None:
                            modify_redis['metric'] = conf_metric
                        if conf_route_map:
                            modify_redis['route_map'] = conf_route_map

                        if modify_redis or have_redis is None:
                            modify_redis['protocol'] = conf_redis['protocol']
                            modify_redis_arr.append(modify_redis)

                    if modify_redis_arr:
                        requests.extend(self.get_modify_redistribute_requests(vrf_name, conf_afi, conf_safi, modify_redis_arr))
                    if conf_max_path:
                        max_path_req = self.get_modify_max_path_request(vrf_name, conf_afi, conf_safi, conf_max_path)
                        if max_path_req:
                            requests.append(max_path_req)

                    if conf_network:
                        network_req = self.get_modify_network_request(vrf_name, conf_afi, conf_safi, conf_network)
                        if network_req:
                            requests.append(network_req)
                    if conf_import:
                        import_req = self.get_modify_import_request(vrf_name, conf_afi, conf_safi, conf_import)
                        if import_req:
                            requests.append(import_req)
                    if conf_aggregate:
                        aggregate_req = self.get_modify_aggregate_request(vrf_name, conf_afi, conf_safi, conf_aggregate)
                        if aggregate_req:
                            requests.append(aggregate_req)

        return requests

    def get_modify_bgp_af_requests(self, commands, have):
        requests = []
        if not commands:
            return requests

        # Create URL and payload
        for conf in commands:
            vrf_name = conf['vrf_name']
            as_val = conf['bgp_as']

            match = next((cfg for cfg in have if (cfg['vrf_name'] == vrf_name and (cfg['bgp_as'] == as_val))), None)
            modify_reqs = self.get_modify_requests(conf, match, vrf_name)
            if modify_reqs:
                requests.extend(modify_reqs)

        return requests

    def get_delete_advertise_attribute_request(self, vrf_name, conf_afi, conf_safi, attr):
        afi_safi = ("%s_%s" % (conf_afi, conf_safi)).upper()
        url = '%s=%s/%s' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
        url += '/%s=%s/%s/%s' % (self.afi_safi_path, afi_safi, self.l2vpn_evpn_config_path, attr)

        return ({"path": url, "method": DELETE})

    def get_delete_route_advertise_request(self, vrf_name, conf_afi, conf_safi):
        afi_safi = ('%s_%s' % (conf_afi, conf_safi)).upper()
        url = '%s=%s/%s' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
        url += '/%s=%s/%s' % (self.afi_safi_path, afi_safi, self.l2vpn_evpn_route_advertise_path)

        return ({'path': url, 'method': DELETE})

    def get_delete_route_advertise_list_request(self, vrf_name, conf_afi, conf_safi, advertise_afi):
        afi_safi = ('%s_%s' % (conf_afi, conf_safi)).upper()
        advertise_afi_safi = '%s_UNICAST' % advertise_afi.upper()
        url = '%s=%s/%s' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
        url += '/%s=%s/%s/route-advertise-list=%s' % (self.afi_safi_path, afi_safi, self.l2vpn_evpn_route_advertise_path, advertise_afi_safi)

        return ({'path': url, 'method': DELETE})

    def get_delete_route_advertise_route_map_request(self, vrf_name, conf_afi, conf_safi, advertise_afi, route_map):
        afi_safi = ('%s_%s' % (conf_afi, conf_safi)).upper()
        advertise_afi_safi = '%s_UNICAST' % advertise_afi.upper()
        url = '%s=%s/%s' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
        url += '/%s=%s/%s/route-advertise-list=%s' % (self.afi_safi_path, afi_safi, self.l2vpn_evpn_route_advertise_path, advertise_afi_safi)
        url += '/config/route-map=%s' % route_map

        return ({'path': url, 'method': DELETE})

    def get_delete_all_vnis_request(self, vrf_name, conf_afi, conf_safi, conf_vnis):
        requests = []
        for vni in conf_vnis:
            requests.append(self.get_delete_vni_request(vrf_name, conf_afi, conf_safi, vni['vni_number']))

        return requests

    def get_delete_vni_request(self, vrf_name, conf_afi, conf_safi, vni_number):
        afi_safi = ('%s_%s' % (conf_afi, conf_safi)).upper()
        url = '%s=%s/%s' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
        url += '/%s=%s/%s/vni=%s' % (self.afi_safi_path, afi_safi, self.l2vpn_evpn_vnis_path, vni_number)

        return ({'path': url, 'method': DELETE})

    def get_delete_vni_cfg_attr_request(self, vrf_name, conf_afi, conf_safi, vni_number, attr):
        afi_safi = ('%s_%s' % (conf_afi, conf_safi)).upper()
        url = '%s=%s/%s' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
        url += '/%s=%s/%s/vni=%s' % (self.afi_safi_path, afi_safi, self.l2vpn_evpn_vnis_path, vni_number)
        url += '/config/%s' % attr

        return ({'path': url, 'method': DELETE})

    def get_delete_rt(self, conf_rt, mat_rt):
        del_rt_list = []
        for rt in conf_rt:
            if mat_rt and rt in mat_rt:
                del_rt_list.append(rt)
        encoded_del_rt_list = quote_plus(','.join(del_rt_list))

        return encoded_del_rt_list

    def get_delete_route_advertise_requests(self, vrf_name, conf_afi, conf_safi, conf_route_adv_list, is_delete_all, mat_route_adv_list):
        requests = []
        if is_delete_all:
            requests.append(self.get_delete_route_advertise_request(vrf_name, conf_afi, conf_safi))
        else:
            for conf_rt_adv in conf_route_adv_list:
                conf_advertise_afi = conf_rt_adv.get('advertise_afi', None)
                conf_route_map = conf_rt_adv.get('route_map', None)
                # Check if the commands to be deleted are configured
                for mat_rt_adv in mat_route_adv_list:
                    mat_advertise_afi = mat_rt_adv.get('advertise_afi', None)
                    mat_route_map = mat_rt_adv.get('route_map', None)
                    # Deletion at advertise-afi-safi level
                    if (not conf_route_map and conf_advertise_afi == mat_advertise_afi):
                        requests.append(self.get_delete_route_advertise_list_request(vrf_name, conf_afi, conf_safi, conf_advertise_afi))
                    # Deletion at route-map level
                    if (conf_route_map and conf_advertise_afi == mat_advertise_afi and conf_route_map == mat_route_map):
                        requests.append(self.get_delete_route_advertise_route_map_request(vrf_name, conf_afi, conf_safi, conf_advertise_afi, conf_route_map))

        return requests

    def get_delete_vnis_requests(self, vrf_name, conf_afi, conf_safi, conf_vnis, is_delete_all, mat_vnis):
        requests = []
        if is_delete_all:
            requests.extend(self.get_delete_all_vnis_request(vrf_name, conf_afi, conf_safi, conf_vnis))
        else:
            for conf_vni in conf_vnis:
                conf_vni_number = conf_vni.get('vni_number', None)
                conf_adv_default_gw = conf_vni.get('advertise_default_gw', None)
                conf_adv_svi_ip = conf_vni.get('advertise_svi_ip', None)
                conf_rd = conf_vni.get('rd', None)
                conf_rt_in = conf_vni.get('rt_in', None)
                conf_rt_out = conf_vni.get('rt_out', None)
                # Check if the commands to be deleted are configured
                for mat_vni in mat_vnis:
                    mat_vni_number = mat_vni.get('vni_number', None)
                    mat_adv_default_gw = mat_vni.get('advertise_default_gw', None)
                    mat_adv_svi_ip = mat_vni.get('advertise_svi_ip', None)
                    mat_rd = mat_vni.get('rd', None)
                    mat_rt_in = mat_vni.get('rt_in', None)
                    mat_rt_out = mat_vni.get('rt_out', None)
                    # Deletion at vni-number level
                    if (conf_vni_number and conf_vni_number == mat_vni_number and not conf_adv_default_gw and not conf_adv_svi_ip and not conf_rd and not
                            conf_rt_in and not conf_rt_out):
                        requests.append(self.get_delete_vni_request(vrf_name, conf_afi, conf_safi, conf_vni_number))
                    # Deletion at config/attribute level
                    if conf_vni_number == mat_vni_number:
                        if conf_adv_default_gw is not None and conf_adv_default_gw == mat_adv_default_gw:
                            requests.append(self.get_delete_vni_cfg_attr_request(vrf_name, conf_afi, conf_safi, conf_vni_number, 'advertise-default-gw'))
                        if conf_adv_svi_ip is not None and conf_adv_svi_ip == mat_adv_svi_ip:
                            requests.append(self.get_delete_vni_cfg_attr_request(vrf_name, conf_afi, conf_safi, conf_vni_number, 'advertise-svi-ip'))
                        if conf_rd and conf_rd == mat_rd:
                            requests.append(self.get_delete_vni_cfg_attr_request(vrf_name, conf_afi, conf_safi, conf_vni_number, 'route-distinguisher'))
                        if conf_rt_in:
                            del_rt_list = self.get_delete_rt(conf_rt_in, mat_rt_in)
                            if del_rt_list:
                                requests.append(self.get_delete_vni_cfg_attr_request(vrf_name, conf_afi, conf_safi, conf_vni_number, 'import-rts=%s' %
                                                del_rt_list))
                        if conf_rt_out:
                            del_rt_list = self.get_delete_rt(conf_rt_out, mat_rt_out)
                            if del_rt_list:
                                requests.append(self.get_delete_vni_cfg_attr_request(vrf_name, conf_afi, conf_safi, conf_vni_number, 'export-rts=%s' %
                                                del_rt_list))

        return requests

    def get_delete_aggregate_requests(self, vrf_name, conf_afi, conf_safi, conf_aggregate, is_delete_all, mat_aggregate):
        requests = []

        if is_delete_all:
            requests.append(self.get_delete_aggregate_attr(vrf_name, conf_afi, conf_safi, None, None))
            return requests

        mat_addr_dict = {mat_addr.get('prefix'): mat_addr for mat_addr in mat_aggregate}
        for addr in conf_aggregate:
            prefix = addr.get('prefix')
            mat_addr = mat_addr_dict.get(prefix)

            if mat_addr is None:
                continue
            as_set = addr.get('as_set')
            policy_name = addr.get('policy_name')
            summary_only = addr.get('summary_only')
            mat_as_set = mat_addr.get('as_set')
            mat_policy_name = mat_addr.get('policy_name')
            mat_summary_only = mat_addr.get('summary_only')

            if as_set is not None and as_set == mat_as_set:
                requests.append(self.get_delete_aggregate_attr(vrf_name, conf_afi, conf_safi, prefix, 'as-set'))
            if policy_name and policy_name == mat_policy_name:
                requests.append(self.get_delete_aggregate_attr(vrf_name, conf_afi, conf_safi, prefix, 'policy-name'))
            if summary_only is not None and summary_only == mat_summary_only:
                requests.append(self.get_delete_aggregate_attr(vrf_name, conf_afi, conf_safi, prefix, 'summary-only'))
            if as_set is None and not policy_name and summary_only is None:
                requests.append(self.get_delete_aggregate_attr(vrf_name, conf_afi, conf_safi, prefix, None))

        return requests

    def get_delete_dampening_request(self, vrf_name, conf_afi, conf_safi):
        afi_safi = ("%s_%s" % (conf_afi, conf_safi)).upper()
        url = '%s=%s/%s' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
        url += '/%s=%s/route-flap-damping/config/enabled' % (self.afi_safi_path, afi_safi)

        return ({"path": url, "method": DELETE})

    def get_delete_address_family_request(self, vrf_name, conf_afi, conf_safi):
        request = None

        afi_safi = ("%s_%s" % (conf_afi, conf_safi)).upper()
        url = '%s=%s/%s' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
        url += '/%s=openconfig-bgp-types:%s' % (self.afi_safi_path, afi_safi)
        request = {"path": url, "method": DELETE}

        return request

    def get_delete_aggregate_attr(self, vrf_name, conf_afi, conf_safi, prefix, attr):
        request = None

        afi_safi = ("%s_%s" % (conf_afi, conf_safi)).upper()
        url = '%s=%s/%s' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
        url += '/%s=%s/aggregate-address-config' % (self.afi_safi_path, afi_safi)
        if prefix:
            url += '/aggregate-address=%s' % (prefix.replace('/', '%2F'))
        if attr:
            url += '/config/%s' % (attr)
        request = {"path": url, "method": DELETE}

        return request

    def get_delete_single_bgp_af_request(self, conf, is_delete_all, match=None):
        requests = []
        vrf_name = conf['vrf_name']

        conf_addr_fams = conf.get('address_family', None)
        if conf_addr_fams is None:
            return requests

        conf_addr_fams = conf_addr_fams.get('afis', [])

        if match and not conf_addr_fams:
            conf_addr_fams = match.get('address_family', None)
            if conf_addr_fams:
                conf_addr_fams = conf_addr_fams.get('afis', [])
                conf_addr_fams = [{'afi': af['afi'], 'safi': af['safi']} for af in conf_addr_fams]

        if not conf_addr_fams:
            return requests

        for conf_addr_fam in conf_addr_fams:
            conf_afi = conf_addr_fam.get('afi', None)
            conf_safi = conf_addr_fam.get('safi', None)
            if not conf_afi or not conf_safi:
                continue
            conf_redis_arr = conf_addr_fam.get('redistribute', [])
            conf_adv_pip = conf_addr_fam.get('advertise_pip', None)
            conf_adv_pip_ip = conf_addr_fam.get('advertise_pip_ip', None)
            conf_adv_pip_peer_ip = conf_addr_fam.get('advertise_pip_peer_ip', None)
            conf_adv_svi_ip = conf_addr_fam.get('advertise_svi_ip', None)
            conf_adv_all_vni = conf_addr_fam.get('advertise_all_vni', None)
            conf_adv_default_gw = conf_addr_fam.get('advertise_default_gw', None)
            conf_max_path = conf_addr_fam.get('max_path', None)
            conf_dampening = conf_addr_fam.get('dampening', None)
            conf_network = conf_addr_fam.get('network', [])
            conf_route_adv_list = conf_addr_fam.get('route_advertise_list', [])
            conf_rd = conf_addr_fam.get('rd', None)
            conf_rt_in = conf_addr_fam.get('rt_in', [])
            conf_rt_out = conf_addr_fam.get('rt_out', [])
            conf_vnis = conf_addr_fam.get('vnis', [])
            conf_import = conf_addr_fam.get('import', None)
            conf_aggregate = conf_addr_fam.get('aggregate_address_config')
            conf_dad = conf_addr_fam.get('dup_addr_detection')

            if is_delete_all:
                if conf_adv_pip_ip:
                    requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'advertise-pip-ip'))
                if conf_adv_pip_peer_ip:
                    requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'advertise-pip-peer-ip'))
                if conf_adv_pip is not None:
                    requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'advertise-pip'))
                if conf_adv_svi_ip is not None:
                    requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'advertise-svi-ip'))
                # Delete 'dup_addr_detection' configuration before 'advertise_all_vni'
                if conf_dad:
                    requests.extend(self.get_delete_dad_requests(vrf_name, conf_afi, conf_safi, conf_dad, is_delete_all, None))
                if conf_adv_all_vni is not None:
                    requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'advertise-all-vni'))
                if conf_dampening:
                    requests.append(self.get_delete_dampening_request(vrf_name, conf_afi, conf_safi))
                if conf_network:
                    requests.extend(self.get_delete_network_request(vrf_name, conf_afi, conf_safi, conf_network, is_delete_all, None))
                if conf_adv_default_gw is not None:
                    requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'advertise-default-gw'))
                if conf_route_adv_list:
                    requests.extend(self.get_delete_route_advertise_requests(vrf_name, conf_afi, conf_safi, conf_route_adv_list, is_delete_all, None))
                if conf_rd:
                    requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'route-distinguisher'))
                if conf_rt_in:
                    requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'import-rts'))
                if conf_rt_out:
                    requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'export-rts'))
                if conf_redis_arr:
                    requests.extend(self.get_delete_redistribute_requests(vrf_name, conf_afi, conf_safi, conf_redis_arr, is_delete_all, None))
                if conf_max_path:
                    requests.extend(self.get_delete_max_path_requests(vrf_name, conf_afi, conf_safi, conf_max_path, is_delete_all, None))
                if conf_vnis:
                    requests.extend(self.get_delete_vnis_requests(vrf_name, conf_afi, conf_safi, conf_vnis, is_delete_all, None))
                if conf_import:
                    requests.extend(self.get_delete_import_requests(vrf_name, conf_afi, conf_safi, conf_import, is_delete_all, None))
                if conf_aggregate:
                    requests.append(self.get_delete_aggregate_attr(vrf_name, conf_afi, conf_safi, None, None))
                addr_family_del_req = self.get_delete_address_family_request(vrf_name, conf_afi, conf_safi)
                if addr_family_del_req:
                    requests.append(addr_family_del_req)
            elif match:
                match_addr_fams = match.get('address_family', None)
                if match_addr_fams:
                    match_addr_fams = match_addr_fams.get('afis', [])
                if not match_addr_fams:
                    continue
                for match_addr_fam in match_addr_fams:
                    mat_afi = match_addr_fam.get('afi', None)
                    mat_safi = match_addr_fam.get('safi', None)
                    if mat_afi and mat_safi and mat_afi == conf_afi and mat_safi == conf_safi:
                        mat_advt_pip = match_addr_fam.get('advertise_pip', None)
                        mat_advt_pip_ip = match_addr_fam.get('advertise_pip_ip', None)
                        mat_advt_pip_peer_ip = match_addr_fam.get('advertise_pip_peer_ip', None)
                        mat_advt_svi_ip = match_addr_fam.get('advertise_svi_ip', None)
                        mat_advt_all_vni = match_addr_fam.get('advertise_all_vni', None)
                        mat_redis_arr = match_addr_fam.get('redistribute', [])
                        mat_advt_defaut_gw = match_addr_fam.get('advertise_default_gw', None)
                        mat_max_path = match_addr_fam.get('max_path', None)
                        mat_dampening = match_addr_fam.get('dampening', None)
                        mat_network = match_addr_fam.get('network', [])
                        mat_route_adv_list = match_addr_fam.get('route_advertise_list', None)
                        mat_rd = match_addr_fam.get('rd', None)
                        mat_rt_in = match_addr_fam.get('rt_in', [])
                        mat_rt_out = match_addr_fam.get('rt_out', [])
                        mat_vnis = match_addr_fam.get('vnis', [])
                        mat_import = match_addr_fam.get('import', None)
                        mat_aggregate = match_addr_fam.get('aggregate_address_config')
                        mat_dad = match_addr_fam.get('dup_addr_detection')

                        if (conf_adv_pip is None and not conf_adv_pip_ip and not conf_adv_pip_peer_ip and conf_adv_svi_ip is None and not conf_import
                                and conf_adv_all_vni is None and not conf_redis_arr and conf_adv_default_gw is None and not conf_max_path and conf_dampening is
                                None and not conf_network and not conf_route_adv_list and not conf_rd and not conf_rt_in and not conf_rt_out and not conf_vnis
                                and not conf_aggregate and not conf_dad):
                            if mat_advt_pip_ip:
                                requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'advertise-pip-ip'))
                            if mat_advt_pip_peer_ip:
                                requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'advertise-pip-peer-ip'))
                            if mat_advt_pip is not None:
                                requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'advertise-pip'))
                            if mat_advt_svi_ip is not None:
                                requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'advertise-svi-ip'))
                            # Delete 'dup_addr_detection' configuration before 'advertise_all_vni'
                            if mat_dad:
                                requests.extend(self.get_delete_dad_requests(vrf_name, conf_afi, conf_safi, mat_dad, is_delete_all, mat_dad))
                            if mat_advt_all_vni is not None:
                                requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'advertise-all-vni'))
                            if mat_dampening:
                                requests.append(self.get_delete_dampening_request(vrf_name, conf_afi, conf_safi))
                            if mat_advt_defaut_gw is not None:
                                requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'advertise-default-gw'))
                            if mat_route_adv_list:
                                requests.extend(self.get_delete_route_advertise_requests(vrf_name, conf_afi, conf_safi, mat_route_adv_list, is_delete_all,
                                                mat_route_adv_list))
                            if mat_rd:
                                requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'route-distinguisher'))
                            if mat_rt_in:
                                requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'import-rts'))
                            if mat_rt_out:
                                requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'export-rts'))
                            if mat_redis_arr:
                                requests.extend(self.get_delete_redistribute_requests(vrf_name, conf_afi, conf_safi, mat_redis_arr, False, mat_redis_arr))
                            if mat_max_path:
                                requests.extend(self.get_delete_max_path_requests(vrf_name, conf_afi, conf_safi, mat_max_path, is_delete_all, mat_max_path))
                            if mat_network:
                                requests.extend(self.get_delete_network_request(vrf_name, conf_afi, conf_safi, mat_network, False, mat_network))
                            if mat_vnis:
                                requests.extend(self.get_delete_vnis_requests(vrf_name, conf_afi, conf_safi, mat_vnis, is_delete_all, mat_vnis))
                            if mat_import:
                                requests.extend(self.get_delete_import_requests(vrf_name, conf_afi, conf_safi, mat_import, is_delete_all, mat_import))
                            if mat_aggregate:
                                requests.extend(self.get_delete_aggregate_requests(vrf_name, conf_afi, conf_safi, mat_aggregate, is_delete_all,
                                                                                   mat_aggregate))
                            addr_family_del_req = self.get_delete_address_family_request(vrf_name, conf_afi, conf_safi)
                            if addr_family_del_req:
                                requests.append(addr_family_del_req)
                        else:
                            if conf_adv_pip_ip and conf_adv_pip_ip == mat_advt_pip_ip:
                                requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'advertise-pip-ip'))
                            if conf_adv_pip_peer_ip and conf_adv_pip_peer_ip == mat_advt_pip_peer_ip:
                                requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'advertise-pip-peer-ip'))
                            if conf_adv_pip is not None and conf_adv_pip == mat_advt_pip:
                                requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'advertise-pip'))
                            if conf_adv_svi_ip is not None and conf_adv_svi_ip == mat_advt_svi_ip:
                                requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'advertise-svi-ip'))
                            # Delete 'dup_addr_detection' configuration before 'advertise_all_vni'
                            if conf_dad and mat_dad:
                                requests.extend(self.get_delete_dad_requests(vrf_name, conf_afi, conf_safi, conf_dad, is_delete_all, mat_dad))
                            if conf_adv_all_vni is not None and conf_adv_all_vni == mat_advt_all_vni:
                                requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'advertise-all-vni'))
                            if conf_dampening and conf_dampening == mat_dampening:
                                requests.append(self.get_delete_dampening_request(vrf_name, conf_afi, conf_safi))
                            if conf_adv_default_gw is not None and conf_adv_default_gw == mat_advt_defaut_gw:
                                requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'advertise-default-gw'))
                            if conf_route_adv_list and mat_route_adv_list:
                                requests.extend(self.get_delete_route_advertise_requests(vrf_name, conf_afi, conf_safi, conf_route_adv_list, is_delete_all,
                                                mat_route_adv_list))
                            if conf_rd and conf_rd == mat_rd:
                                requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'route-distinguisher'))
                            if conf_rt_in:
                                del_rt_list = self.get_delete_rt(conf_rt_in, mat_rt_in)
                                if del_rt_list:
                                    requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'import-rts=%s' %
                                                    del_rt_list))
                            if conf_rt_out:
                                del_rt_list = self.get_delete_rt(conf_rt_out, mat_rt_out)
                                if del_rt_list:
                                    requests.append(self.get_delete_advertise_attribute_request(vrf_name, conf_afi, conf_safi, 'export-rts=%s' %
                                                    del_rt_list))
                            if conf_redis_arr and mat_redis_arr:
                                requests.extend(self.get_delete_redistribute_requests(vrf_name, conf_afi, conf_safi, conf_redis_arr, False, mat_redis_arr))
                            if conf_max_path and mat_max_path:
                                requests.extend(self.get_delete_max_path_requests(vrf_name, conf_afi, conf_safi, conf_max_path, is_delete_all, mat_max_path))
                            if conf_network and mat_network:
                                requests.extend(self.get_delete_network_request(vrf_name, conf_afi, conf_safi, conf_network, False, mat_network))
                            if conf_vnis and mat_vnis:
                                requests.extend(self.get_delete_vnis_requests(vrf_name, conf_afi, conf_safi, conf_vnis, is_delete_all, mat_vnis))
                            if conf_import and mat_import:
                                requests.extend(self.get_delete_import_requests(vrf_name, conf_afi, conf_safi, conf_import, is_delete_all, mat_import))
                            if conf_aggregate and mat_aggregate:
                                requests.extend(self.get_delete_aggregate_requests(vrf_name, conf_afi, conf_safi, conf_aggregate, is_delete_all, mat_aggregate))
                        break

        return requests

    def get_delete_network_request(self, vrf_name, conf_afi, conf_safi, conf_network, is_delete_all, mat_network):
        requests = []
        afi_safi = ("%s_%s" % (conf_afi, conf_safi)).upper()
        url = '%s=%s/%s/' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
        url += '%s=%s/network-config/network=' % (self.afi_safi_path, afi_safi)
        mat_list = []
        for conf in conf_network:
            if mat_network:
                mat_prefix = next((pre for pre in mat_network if pre == conf), None)
                if mat_prefix:
                    mat_list.append(mat_prefix)
        if not is_delete_all and mat_list:
            for each in mat_list:
                tmp = each.replace('/', '%2f')
                requests.append({'path': url + tmp, 'method': DELETE})
        elif is_delete_all:
            for each in conf_network:
                tmp = each.replace('/', '%2f')
                requests.append({'path': url + tmp, 'method': DELETE})
        return requests

    def get_delete_max_path_requests(self, vrf_name, conf_afi, conf_safi, conf_max_path, is_delete_all, mat_max_path):
        requests = []
        afi_safi = ("%s_%s" % (conf_afi, conf_safi)).upper()
        url = '%s=%s/%s/' % (self.network_instance_path, vrf_name, self.protocol_bgp_path)
        url += '%s=%s/use-multiple-paths/' % (self.afi_safi_path, afi_safi)

        conf_ebgp = conf_max_path.get('ebgp', None)
        conf_ibgp = conf_max_path.get('ibgp', None)
        mat_ebgp = None
        mat_ibgp = None
        if mat_max_path:
            mat_ebgp = mat_max_path.get('ebgp', None)
            mat_ibgp = mat_max_path.get('ibgp', None)

        if (conf_ebgp and mat_ebgp and mat_ebgp != 1) or (is_delete_all and conf_ebgp != 1):
            requests.append({'path': url + 'ebgp/config/maximum-paths', 'method': DELETE})
        if (conf_ibgp and mat_ibgp and mat_ibgp != 1) or (is_delete_all and conf_ibgp != 1):
            requests.append({'path': url + 'ibgp/config/maximum-paths', 'method': DELETE})

        return requests

    def get_delete_redistribute_route_map_request(self, vrf_name, conf_afi, conf_redis, conf_route_map):
        addr_family = "openconfig-types:%s" % (conf_afi.upper())
        conf_protocol = conf_redis['protocol'].upper()
        if conf_protocol == 'CONNECTED':
            conf_protocol = "DIRECTLY_CONNECTED"
        src_protocol = "openconfig-policy-types:%s" % (conf_protocol)
        dst_protocol = "openconfig-policy-types:BGP"
        url = '%s=%s/%s=' % (self.network_instance_path, vrf_name, self.table_connection_path)
        url += '%s,%s,%s/config/import-policy=%s' % (src_protocol, dst_protocol, addr_family, conf_route_map)
        return ({'path': url, 'method': DELETE})

    def get_delete_redistribute_metric_request(self, vrf_name, conf_afi, conf_redis):
        addr_family = "openconfig-types:%s" % (conf_afi.upper())
        conf_protocol = conf_redis['protocol'].upper()
        if conf_protocol == 'CONNECTED':
            conf_protocol = "DIRECTLY_CONNECTED"
        src_protocol = "openconfig-policy-types:%s" % (conf_protocol)
        dst_protocol = "openconfig-policy-types:BGP"
        url = '%s=%s/%s=' % (self.network_instance_path, vrf_name, self.table_connection_path)
        url += '%s,%s,%s/config/metric' % (src_protocol, dst_protocol, addr_family)
        return {'path': url, 'method': DELETE}

    def get_delete_redistribute_requests(self, vrf_name, conf_afi, conf_safi, conf_redis_arr, is_delete_all, mat_redis_arr):
        requests = []
        for conf_redis in conf_redis_arr:
            addr_family = "openconfig-types:%s" % (conf_afi.upper())
            conf_protocol = conf_redis['protocol'].upper()

            ext_metric_flag = False
            ext_route_flag = False
            mat_redis = None
            mat_metric = None
            mat_route_map = None
            if not is_delete_all:
                mat_redis = next((redis_cfg for redis_cfg in mat_redis_arr if redis_cfg['protocol'].upper() == conf_protocol), None)
                if mat_redis:
                    mat_metric = mat_redis.get('metric', None)
                    mat_route_map = mat_redis.get('route_map', None)
                    if mat_metric:
                        ext_metric_flag = True
                    if mat_route_map:
                        ext_route_flag = True

            if conf_protocol == 'CONNECTED':
                conf_protocol = "DIRECTLY_CONNECTED"

            src_protocol = "openconfig-policy-types:%s" % (conf_protocol)
            dst_protocol = "openconfig-policy-types:BGP"

            conf_route_map = conf_redis.get('route_map', None)
            conf_metric = conf_redis.get('metric', None)
            if conf_metric is not None:
                conf_metric = float(conf_redis['metric'])

            url = '%s=%s/%s=' % (self.network_instance_path, vrf_name, self.table_connection_path)

            new_metric_flag = conf_metric is not None
            new_route_flag = conf_route_map is not None
            is_delete_protocol = False
            if is_delete_all:
                is_delete_protocol = True
            else:
                is_delete_protocol = (new_metric_flag == ext_metric_flag) and (new_route_flag == ext_route_flag)

            if is_delete_protocol:
                url += '%s,%s,%s' % (src_protocol, dst_protocol, addr_family)
                requests.append({'path': url, 'method': DELETE})
                continue

            if new_metric_flag and ext_metric_flag:
                url += '%s,%s,%s/config/metric' % (src_protocol, dst_protocol, addr_family)
                requests.append({'path': url, 'method': DELETE})

            if new_route_flag and ext_route_flag:
                url += '%s,%s,%s/config/import-policy=%s' % (src_protocol, dst_protocol, addr_family, conf_route_map)
                requests.append({'path': url, 'method': DELETE})

        return requests

    def get_delete_import_requests(self, vrf_name, conf_afi, conf_safi, conf_import, is_delete_all, mat_import):
        requests = []
        url = '{0}={1}/{2}/{3}={4}_{5}/openconfig-bgp-ext:import-network-instance'.format(self.network_instance_path, vrf_name, self.protocol_bgp_path,
                                                                                          self.afi_safi_path, conf_afi.upper(), conf_safi.upper())
        import_vrf_url = url + '/config/name={vrf}'
        import_vrf_all_url = url + '/config/name'
        import_vrf_route_map_url = url + '/config/policy-name'

        if conf_import.get('vrf'):
            mat_vrf = mat_import['vrf'] if mat_import and mat_import.get('vrf') else {}
            if conf_import['vrf'].get('vrf_list'):
                if is_delete_all:
                    requests.append({'path': import_vrf_all_url, 'method': DELETE})
                elif mat_vrf.get('vrf_list'):
                    for vrf in set(conf_import['vrf']['vrf_list']).intersection(mat_vrf['vrf_list']):
                        requests.append({'path': import_vrf_url.format(vrf=vrf), 'method': DELETE})

            if conf_import['vrf'].get('route_map'):
                if is_delete_all or conf_import['vrf']['route_map'] == mat_vrf.get('route_map'):
                    requests.append({'path': import_vrf_route_map_url, 'method': DELETE})

        return requests

    def get_delete_dad_requests(self, vrf_name, conf_afi, conf_safi, conf_dad, is_delete_all, mat_dad):
        requests = []
        url = '{0}={1}/{2}/{3}={4}_{5}/l2vpn-evpn/openconfig-bgp-evpn-ext:dup-addr-detection/config'.format(self.network_instance_path, vrf_name,
                                                                                                            self.protocol_bgp_path, self.afi_safi_path,
                                                                                                            conf_afi.upper(), conf_safi.upper())

        # Duplicate address detection is enabled by default
        # Hence, delete (set to enable) the config only when it is disabled
        if conf_dad.get('enabled') is False and (is_delete_all or (conf_dad['enabled'] == mat_dad.get('enabled'))):
            payload = {'openconfig-bgp-evpn-ext:enabled': True}
            requests.append({'path': url + '/enabled', 'method': PATCH, 'data': payload})

        for attr in self.dad_attrs:
            if attr == 'enabled':
                continue

            if conf_dad.get(attr) is not None and (is_delete_all or (conf_dad[attr] == mat_dad.get(attr))):
                requests.append({'path': '{0}/{1}'.format(url, attr.replace('_', '-')), 'method': DELETE})

        return requests

    def get_delete_bgp_af_requests(self, commands, have, is_delete_all):
        requests = []
        for cmd in commands:
            vrf_name = cmd['vrf_name']
            as_val = cmd['bgp_as']
            match_cfg = None
            if not is_delete_all:
                match_cfg = next((have_cfg for have_cfg in have if have_cfg['vrf_name'] == vrf_name and have_cfg['bgp_as'] == as_val), None)
            requests.extend(self.get_delete_single_bgp_af_request(cmd, is_delete_all, match_cfg))
        return requests

    def get_delete_commands_requests_for_replaced_overridden(self, want, have, state):
        """Returns the commands and requests necessary to remove applicable
        current configurations when state is replaced or overridden
        """
        commands = []
        requests = []
        if not have:
            return commands, requests

        for conf in have:
            as_val = conf['bgp_as']
            vrf_name = conf['vrf_name']
            if conf.get('address_family') and conf['address_family'].get('afis'):
                afi_list = conf['address_family']['afis']
            else:
                continue

            match_cfg = next((cfg for cfg in want if cfg['vrf_name'] == vrf_name and cfg['bgp_as'] == as_val), None)
            if not match_cfg:
                # Delete all address-families in BGPs that are not
                # specified in overridden
                if state == 'overridden':
                    commands.append(conf)
                    requests.extend(self.get_delete_single_bgp_af_request(conf, True))
                continue

            match_afi_list = []
            if match_cfg.get('address_family') and match_cfg['address_family'].get('afis'):
                match_afi_list = match_cfg['address_family']['afis']

            # Delete AF configs in BGPs that are replaced/overridden
            afi_command_list = []
            for afi_conf in afi_list:
                afi_command = {}
                afi = afi_conf['afi']
                safi = afi_conf['safi']

                match_afi_cfg = next((afi_cfg for afi_cfg in match_afi_list if afi_cfg['afi'] == afi and afi_cfg['safi'] == safi), None)
                # Delete address-families that are not specified in overridden
                if not match_afi_cfg:
                    if state == 'overridden':
                        afi_command_list.append(afi_conf)
                        requests.extend(self.get_delete_single_bgp_af_request({'bgp_as': as_val, 'vrf_name': vrf_name, 'address_family': {'afis': [afi_conf]}},
                                                                              True))
                    continue

                if afi == 'ipv4' and safi == 'unicast':
                    if afi_conf.get('dampening') and match_afi_cfg.get('dampening') is None:
                        afi_command['dampening'] = afi_conf['dampening']
                        requests.append(self.get_delete_dampening_request(vrf_name, afi, safi))

                if afi == 'l2vpn' and safi == 'evpn':
                    dad_conf = afi_conf['dup_addr_detection'].copy() if afi_conf.get('dup_addr_detection') else {}
                    # Duplicate address detection is enabled by default
                    if dad_conf.get('enabled'):
                        dad_conf.pop('enabled')

                    if dad_conf:
                        match_dad_cfg = match_afi_cfg.get('dup_addr_detection', {})
                        if not match_dad_cfg:
                            afi_command['dup_addr_detection'] = dad_conf
                            requests.extend(self.get_delete_dad_requests(vrf_name, afi, safi, afi_command['dup_addr_detection'], True, None))
                        else:
                            dad_command = {}
                            for attr in self.dad_attrs:
                                if dad_conf.get(attr) is not None and match_dad_cfg.get(attr) is None:
                                    dad_command[attr] = dad_conf[attr]

                            if dad_command:
                                afi_command['dup_addr_detection'] = dad_command
                                requests.extend(self.get_delete_dad_requests(vrf_name, afi, safi,
                                                                             afi_command['dup_addr_detection'], False, afi_command['dup_addr_detection']))

                    for option in self.non_list_advertise_attrs:
                        if afi_conf.get(option) is not None and match_afi_cfg.get(option) is None:
                            afi_command[option] = afi_conf[option]
                            requests.append(self.get_delete_advertise_attribute_request(vrf_name, afi, safi, self.advertise_attrs_map[option]))

                    for option in ('rt_in', 'rt_out'):
                        if afi_conf.get(option):
                            del_rt = self._get_diff_list(afi_conf[option], match_afi_cfg.get(option, []))
                            if del_rt:
                                afi_command[option] = del_rt
                                requests.append(self.get_delete_advertise_attribute_request(vrf_name, afi, safi,
                                                                                            '{0}={1}'.format(self.advertise_attrs_map[option],
                                                                                                             quote_plus(','.join(del_rt)))))

                    if afi_conf.get('route_advertise_list'):
                        route_adv_list = []
                        match_route_adv_list = match_afi_cfg.get('route_advertise_list', [])
                        for route_adv in afi_conf['route_advertise_list']:
                            advertise_afi = route_adv['advertise_afi']
                            route_map = route_adv.get('route_map')
                            match_route_adv = next((adv_cfg for adv_cfg in match_route_adv_list if adv_cfg['advertise_afi'] == advertise_afi), None)
                            if not match_route_adv:
                                route_adv_list.append(route_adv)
                                requests.append(self.get_delete_route_advertise_list_request(vrf_name, afi, safi, advertise_afi))
                            # Delete existing route-map before configuring
                            # new route-map.
                            elif route_map and route_map != match_route_adv.get('route_map'):
                                route_adv_list.append(route_adv)
                                requests.append(self.get_delete_route_advertise_route_map_request(vrf_name, afi, safi, advertise_afi, route_map))

                        if route_adv_list:
                            afi_command['route_advertise_list'] = route_adv_list

                    if afi_conf.get('vnis'):
                        vni_command_list = []
                        match_vni_list = match_afi_cfg.get('vnis', [])
                        for vni_conf in afi_conf['vnis']:
                            vni_number = vni_conf['vni_number']
                            match_vni = next((vni_cfg for vni_cfg in match_vni_list if vni_cfg['vni_number'] == vni_number), None)
                            # Delete entire VNIs that are not specified
                            if not match_vni:
                                vni_command_list.append(vni_conf)
                                requests.append(self.get_delete_vni_request(vrf_name, afi, safi, vni_number))
                            else:
                                vni_command = {}
                                for option in ('advertise_default_gw', 'advertise_svi_ip', 'rd'):
                                    if vni_conf.get(option) is not None and match_vni.get(option) is None:
                                        vni_command[option] = vni_conf[option]
                                        requests.append(self.get_delete_vni_cfg_attr_request(vrf_name, afi, safi, vni_number,
                                                                                             self.advertise_attrs_map[option]))

                                for option in ('rt_in', 'rt_out'):
                                    if vni_conf.get(option):
                                        del_rt = self._get_diff_list(vni_conf[option], match_vni.get(option, []))
                                        if del_rt:
                                            vni_command[option] = del_rt
                                            requests.append(self.get_delete_vni_cfg_attr_request(vrf_name, afi, safi, vni_number,
                                                                                                 '{0}={1}'.format(self.advertise_attrs_map[option],
                                                                                                                  quote_plus(','.join(del_rt)))))

                                if vni_command:
                                    vni_command['vni_number'] = vni_number
                                    vni_command_list.append(vni_command)

                        if vni_command_list:
                            afi_command['vnis'] = vni_command_list

                elif afi in ['ipv4', 'ipv6'] and safi == 'unicast':
                    if afi_conf.get('network'):
                        del_network = self._get_diff_list(afi_conf['network'], match_afi_cfg.get('network', []))
                        if del_network:
                            afi_command['network'] = del_network
                            requests.extend(self.get_delete_network_request(vrf_name, afi, safi, del_network, True, None))

                    if afi_conf.get('redistribute'):
                        match_redis_list = match_afi_cfg.get('redistribute')
                        if not match_redis_list:
                            afi_command['redistribute'] = afi_conf['redistribute']
                            requests.extend(self.get_delete_redistribute_requests(vrf_name, afi, safi, afi_conf['redistribute'], True, None))
                        else:
                            redis_command_list = []
                            for redis_conf in afi_conf['redistribute']:
                                protocol = redis_conf['protocol']
                                match_redis = next((redis_cfg for redis_cfg in match_redis_list if redis_cfg['protocol'] == protocol), None)
                                # Delete complete protocol redistribute
                                # configuration if not specified
                                if not match_redis:
                                    redis_command_list.append(redis_conf)
                                    requests.extend(self.get_delete_redistribute_requests(vrf_name, afi, safi, [redis_conf], True, None))
                                # Delete metric, route_map for specified
                                # protocol if they are not specified.
                                else:
                                    redis_command = {}
                                    if redis_conf.get('metric') is not None and match_redis.get('metric') is None:
                                        redis_command['metric'] = redis_conf['metric']
                                        requests.append(self.get_delete_redistribute_metric_request(vrf_name, afi, redis_conf))
                                    if redis_conf.get('route_map') is not None and match_redis.get('route_map') is None:
                                        redis_command['route_map'] = redis_conf['route_map']
                                        requests.append(self.get_delete_redistribute_route_map_request(vrf_name, afi, redis_conf, redis_command['route_map']))

                                    if redis_command:
                                        redis_command['protocol'] = protocol
                                        redis_command_list.append(redis_command)

                            if redis_command_list:
                                afi_command['redistribute'] = redis_command_list

                    if afi_conf.get('max_path'):
                        max_path_command = {}
                        match_max_path = match_afi_cfg.get('max_path', {})
                        if afi_conf['max_path'].get('ibgp') and afi_conf['max_path']['ibgp'] != 1 and match_max_path.get('ibgp') is None:
                            max_path_command['ibgp'] = afi_conf['max_path']['ibgp']
                        if afi_conf['max_path'].get('ebgp') and afi_conf['max_path']['ebgp'] != 1 and match_max_path.get('ebgp') is None:
                            max_path_command['ebgp'] = afi_conf['max_path']['ebgp']

                        if max_path_command:
                            afi_command['max_path'] = max_path_command
                            requests.extend(self.get_delete_max_path_requests(vrf_name, afi, safi, afi_command['max_path'], False, afi_command['max_path']))

                    if afi_conf.get('import') and afi_conf['import'].get('vrf'):
                        match_import = match_afi_cfg['import'] if 'import' in match_afi_cfg else {}
                        if not match_import or (match_import and not match_import.get('vrf')):
                            afi_command['import'] = afi_conf['import']
                            requests.extend(self.get_delete_import_requests(vrf_name, afi, safi, afi_conf['import'], True, None))
                        else:
                            import_vrf_command = {'vrf': {}}
                            if afi_conf['import']['vrf'].get('vrf_list'):
                                del_import_vrf_list = self._get_diff_list(afi_conf['import']['vrf']['vrf_list'], match_import['vrf'].get('vrf_list'))
                                if del_import_vrf_list:
                                    import_vrf_command['vrf']['vrf_list'] = del_import_vrf_list
                            if afi_conf['import']['vrf'].get('route_map') and not match_import['vrf'].get('route_map'):
                                import_vrf_command['vrf']['route_map'] = afi_conf['import']['vrf']['route_map']

                            if import_vrf_command['vrf']:
                                afi_command['import'] = import_vrf_command
                                requests.extend(self.get_delete_import_requests(vrf_name, afi, safi, afi_command['import'], False, afi_command['import']))

                    if afi_conf.get('aggregate_address_config'):
                        aggregate_cmd_list = []
                        match_aggregate = match_afi_cfg.get('aggregate_address_config')
                        if match_aggregate:
                            match_addr_dict = {mat_addr.get('prefix'): mat_addr for mat_addr in match_aggregate}
                            for addr in afi_conf['aggregate_address_config']:
                                prefix = addr['prefix']
                                match_addr = match_addr_dict.get(prefix)

                                if not match_addr:
                                    aggregate_cmd_list.append(addr)
                                    requests.append(self.get_delete_aggregate_attr(vrf_name, afi, safi, prefix, None))
                                else:
                                    aggregate_cmd = {}
                                    for option in ('as_set', 'policy_name', 'summary_only'):
                                        if addr.get(option) is not None and match_addr.get(option) is None:
                                            aggregate_cmd[option] = addr[option]
                                            attr = option.replace('_', '-')
                                            requests.append(self.get_delete_aggregate_attr(vrf_name, afi, safi, prefix, attr))
                                    if aggregate_cmd:
                                        aggregate_cmd['prefix'] = prefix
                                        aggregate_cmd_list.append(aggregate_cmd)
                        if aggregate_cmd_list:
                            afi_command['aggregate_address_config'] = aggregate_cmd_list

                if afi_command:
                    afi_command['afi'] = afi
                    afi_command['safi'] = safi
                    afi_command_list.append(afi_command)

            if afi_command_list:
                commands.append({'bgp_as': as_val, 'vrf_name': vrf_name, 'address_family': {'afis': afi_command_list}})

        return commands, requests

    @staticmethod
    def _get_diff_list(base_list, compare_with_list):
        if not compare_with_list:
            return base_list

        return [item for item in base_list if item not in compare_with_list]
