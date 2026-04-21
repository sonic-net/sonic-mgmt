#
# -*- coding: utf-8 -*-
# Copyright 2023 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic bgp_af fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.bgp_af.bgp_af import Bgp_afArgs

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.bgp_utils import (
    get_bgp_af_data,
    get_all_bgp_af_redistribute,
)


class Bgp_afFacts(object):
    """ The sonic bgp_af fact class
    """

    afi_safi_types_map = {
        'openconfig-bgp-types:IPV4_UNICAST': 'ipv4_unicast',
        'openconfig-bgp-types:IPV6_UNICAST': 'ipv6_unicast',
        'openconfig-bgp-types:L2VPN_EVPN': 'l2vpn_evpn',
    }

    af_params_map = {
        'afi': 'afi-safi-name',
        'route_map': 'policy-name',
        'prefix': 'prefix',
        'neighbor': 'neighbor-address',
        'route_reflector_client': 'route-reflector-client',
        'route_server_client': 'route-server-client',
        'next_hop_self': ['next-hop-self', 'enabled'],
        'remove_private_as': ['remove-private-as', 'enabled'],
        'prefix_list_in': ['prefix-list', 'import-policy'],
        'prefix_list_out': ['prefix-list', 'export-policy'],
        'maximum_prefix': ['prefix-limit', 'max-prefixes'],
        'activate': 'enabled',
        'advertise_pip': ['l2vpn-evpn', 'openconfig-bgp-evpn-ext:config', 'advertise-pip'],
        'advertise_pip_ip': ['l2vpn-evpn', 'openconfig-bgp-evpn-ext:config', 'advertise-pip-ip'],
        'advertise_pip_peer_ip': ['l2vpn-evpn', 'openconfig-bgp-evpn-ext:config', 'advertise-pip-peer-ip'],
        'advertise_svi_ip': ['l2vpn-evpn', 'openconfig-bgp-evpn-ext:config', 'advertise-svi-ip'],
        'advertise_all_vni': ['l2vpn-evpn', 'openconfig-bgp-evpn-ext:config', 'advertise-all-vni'],
        'advertise_default_gw': ['l2vpn-evpn', 'openconfig-bgp-evpn-ext:config', 'advertise-default-gw'],
        'ebgp': ['use-multiple-paths', 'ebgp', 'maximum-paths'],
        'ibgp': ['use-multiple-paths', 'ibgp', 'maximum-paths'],
        'network': ['network-config', 'network'],
        'dampening': ['route-flap-damping', 'config', 'enabled'],
        'route_advertise_list': ['l2vpn-evpn', 'openconfig-bgp-evpn-ext:route-advertise', 'route-advertise-list'],
        'rd': ['l2vpn-evpn', 'openconfig-bgp-evpn-ext:config', 'route-distinguisher'],
        'rt_in': ['l2vpn-evpn', 'openconfig-bgp-evpn-ext:config', 'import-rts'],
        'rt_out': ['l2vpn-evpn', 'openconfig-bgp-evpn-ext:config', 'export-rts'],
        'vnis': ['l2vpn-evpn', 'openconfig-bgp-evpn-ext:vnis', 'vni'],
        'import_vrf_list': ['openconfig-bgp-ext:import-network-instance', 'config', 'name'],
        'import_vrf_route_map': ['openconfig-bgp-ext:import-network-instance', 'config', 'policy-name'],
        'aggregate_address_config': ['aggregate-address-config', 'aggregate-address'],
        'dad': ['l2vpn-evpn', 'openconfig-bgp-evpn-ext:dup-addr-detection']
    }

    af_redis_params_map = {
        'protocol': 'src-protocol',
        'afi': 'address-family',
        'metric': 'metric',
        'route_map': 'import-policy'
    }

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Bgp_afArgs.argument_spec
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
            data = get_bgp_af_data(self._module, self.af_params_map)
            vrf_list = [e_bgp_af['vrf_name'] for e_bgp_af in data]
            self.update_max_paths(data)
            self.update_network(data)
            self.update_route_advertise_list(data)
            self.update_vnis(data)
            self.update_import(data)
            self.update_dad(data)
            bgp_redis_data = get_all_bgp_af_redistribute(self._module, vrf_list, self.af_redis_params_map)
            self.update_redis_data(data, bgp_redis_data)
            self.update_afis(data)

        # operate on a collection of resource x
        for conf in data:
            if conf:
                obj = self.render_config(self.generated_spec, conf)
        # split the config into instances of the resource
                if obj:
                    objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('bgp_af', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['bgp_af'] = remove_empties_from_list(params['config'])
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

    def check_afi(self, afi, redis_data):
        afi_rhs = afi
        afi_lhs = redis_data.get('afi', None)
        return (afi_lhs and (afi_rhs == afi_lhs))

    def update_redis_data(self, objs, af_redis_data):
        if not (af_redis_data or objs):
            return

        for conf in objs:
            vrf_name = conf['vrf_name']
            raw_af_redis_data = next((e_af_redis for e_af_redis in af_redis_data if vrf_name in e_af_redis), None)
            if not raw_af_redis_data:
                continue
            norm_af_redis_data = self.normalize_af_redis_params(raw_af_redis_data[vrf_name])
            if norm_af_redis_data:
                if 'address_family' in conf:
                    afs = conf['address_family']
                    if not afs:
                        continue
                    for e_af in afs:
                        if 'afi' in e_af:
                            afi = e_af['afi']
                            redis_arr = []
                            for e_redis_data in norm_af_redis_data:
                                if self.check_afi(afi, e_redis_data):
                                    e_redis_data.pop('afi')
                                    redis_arr.append(e_redis_data)
                            e_af.update({'redistribute': redis_arr})
                else:
                    addr_fams = []
                    for e_norm_af_redis in norm_af_redis_data:
                        afi = e_norm_af_redis['afi']
                        e_norm_af_redis.pop('afi')
                        mat_addr_fam = next((each_addr_fam for each_addr_fam in addr_fams if each_addr_fam['afi'] == afi), None)
                        if mat_addr_fam:
                            mat_addr_fam['redistribute'].append(e_norm_af_redis)
                        else:
                            addr_fams.append({'redistribute': [e_norm_af_redis], 'afi': afi})

                    if addr_fams:
                        conf.update({'address_family': addr_fams})

    def update_max_paths(self, data):
        for conf in data:
            afs = conf.get('address_family', [])
            if afs:
                for af in afs:
                    max_path = {}
                    ebgp = af.get('ebgp', None)
                    if ebgp:
                        af.pop('ebgp')
                        max_path['ebgp'] = ebgp
                    ibgp = af.get('ibgp', None)
                    if ibgp:
                        af.pop('ibgp')
                        max_path['ibgp'] = ibgp
                    if max_path:
                        af['max_path'] = max_path

    def update_network(self, data):
        for conf in data:
            afs = conf.get('address_family', [])
            if afs:
                for af in afs:
                    temp = []
                    network = af.get('network')
                    dampening = af.get('dampening')
                    aggregate_address_config = af.get('aggregate_address_config')

                    if network:
                        for e in network:
                            prefix = e.get('prefix')
                            if prefix:
                                temp.append(prefix)
                    af['network'] = temp
                    if dampening:
                        af.pop('dampening')
                        af['dampening'] = dampening
                    if aggregate_address_config:
                        addr_list = []
                        for addr in aggregate_address_config:
                            addr_dict = {}
                            prefix = addr.get('prefix')
                            config = addr.get('config')

                            if prefix:
                                addr_dict['prefix'] = prefix
                            if config:
                                as_set = config.get('as-set')
                                policy_name = config.get('policy-name')
                                summary_only = config.get('summary-only')

                                if as_set is not None:
                                    addr_dict['as_set'] = as_set
                                if policy_name:
                                    addr_dict['policy_name'] = policy_name
                                if summary_only is not None:
                                    addr_dict['summary_only'] = summary_only
                            if addr_dict:
                                addr_list.append(addr_dict)
                        if addr_list:
                            af['aggregate_address_config'] = addr_list

    def update_afis(self, data):
        for conf in data:
            if 'address_family' in conf:
                conf['address_family'] = {'afis': conf['address_family']}

    def update_route_advertise_list(self, data):
        for conf in data:
            afs = conf.get('address_family', [])
            if afs:
                for af in afs:
                    rt_adv_lst = []
                    route_advertise_list = af.get('route_advertise_list', None)
                    if route_advertise_list:
                        for rt in route_advertise_list:
                            rt_adv_dict = {}
                            advertise_afi = rt['advertise-afi-safi'].split(':')[1].split('_')[0].lower()
                            route_map_config = rt['config']
                            route_map = route_map_config.get('route-map', None)
                            if advertise_afi:
                                rt_adv_dict['advertise_afi'] = advertise_afi
                            if route_map:
                                rt_adv_dict['route_map'] = route_map[0]
                            if rt_adv_dict and rt_adv_dict not in rt_adv_lst:
                                rt_adv_lst.append(rt_adv_dict)
                        af['route_advertise_list'] = rt_adv_lst

    def update_vnis(self, data):
        for conf in data:
            afs = conf.get('address_family', [])
            if afs:
                for af in afs:
                    vnis = af.get('vnis', None)
                    if vnis:
                        vnis_list = []
                        for vni in vnis:
                            vni_dict = {}
                            vni_config = vni['config']
                            vni_number = vni_config.get('vni-number', None)
                            vni_adv_gw = vni_config.get('advertise-default-gw', None)
                            vni_adv_svi = vni_config.get('advertise-svi-ip', None)
                            vni_rd = vni_config.get('route-distinguisher', None)
                            vni_rt_in = vni_config.get('import-rts', [])
                            vni_rt_out = vni_config.get('export-rts', [])
                            if vni_number:
                                vni_dict['vni_number'] = vni_number
                            if vni_adv_gw is not None:
                                vni_dict['advertise_default_gw'] = vni_adv_gw
                            if vni_adv_svi is not None:
                                vni_dict['advertise_svi_ip'] = vni_adv_svi
                            if vni_rd:
                                vni_dict['rd'] = vni_rd
                            if vni_rt_in:
                                vni_dict['rt_in'] = vni_rt_in
                            if vni_rt_out:
                                vni_dict['rt_out'] = vni_rt_out
                            vnis_list.append(vni_dict)
                        af['vnis'] = vnis_list

    def update_import(self, data):
        for conf in data:
            afs = conf.get('address_family', [])
            if afs:
                for af in afs:
                    import_vrf = {}
                    if af.get('import_vrf_list'):
                        import_vrf['vrf_list'] = af.pop('import_vrf_list')
                    if af.get('import_vrf_route_map'):
                        import_vrf['route_map'] = af.pop('import_vrf_route_map')
                    if import_vrf:
                        af['import'] = {'vrf': import_vrf}

    def update_dad(self, data):
        dad_options = ('enabled', 'freeze', 'max-moves', 'time')
        for conf in data:
            afs = conf.get('address_family', [])
            if afs:
                for af in afs:
                    dup_addr_detection = {}
                    dad_config = af.pop('dad', {})
                    if dad_config.get('config'):
                        for option in dad_options:
                            if option in dad_config['config']:
                                dup_addr_detection[option.replace('-', '_')] = dad_config['config'][option]
                        dup_addr_detection.setdefault('enabled', True)

                        if dup_addr_detection:
                            af['dup_addr_detection'] = dup_addr_detection

    def normalize_af_redis_params(self, af):
        norm_af = list()
        for e_af in af:
            temp = e_af.copy()
            for key, val in e_af.items():
                if 'afi' == key or 'protocol' == key and val:
                    if ':' in val:
                        temp[key] = val.split(':')[1].lower()
                    if '_' in val:
                        temp[key] = val.split('_')[1].lower()
                elif 'route_map' == key and val:
                    temp['route_map'] = val[0]

            norm_af.append(temp)
        return norm_af
