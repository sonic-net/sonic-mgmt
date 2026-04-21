#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic ipv6_router_advertisement fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ipv6_router_advertisement.ipv6_router_advertisement import (
    Ipv6_router_advertisementArgs
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

DEFAULT_VALUES = {
    'suppress': True,
    'ra_fast_retrans': True,
    'adv_interval_option': False,
    'home_agent_config': False,
    'managed_config': False,
    'other_config': False
}

OPTION_TO_PAYLOAD_MAP = {
    'adv_interval_option': 'openconfig-interfaces-ext:adv-interval-option',
    'dnssl': 'openconfig-interfaces-ext:dns-search-names',
    'home_agent_config': 'openconfig-interfaces-ext:home-agent-config',
    'home_agent_lifetime': 'openconfig-interfaces-ext:home-agent-lifetime',
    'home_agent_preference': 'openconfig-interfaces-ext:home-agent-preference',
    'managed_config': 'openconfig-interfaces-ext:managed-config',
    'min_ra_interval': 'openconfig-interfaces-ext:min-ra-interval',
    'min_ra_interval_msec': 'openconfig-interfaces-ext:min-ra-interval-msec',
    'mtu': 'openconfig-interfaces-ext:mtu',
    'other_config': 'openconfig-interfaces-ext:other-config',
    'ra_fast_retrans': 'openconfig-interfaces-ext:ra-fast-retrans',
    'ra_hop_limit': 'openconfig-interfaces-ext:ra-hop-limit',
    'ra_interval': 'interval',
    'ra_interval_msec': 'openconfig-interfaces-ext:ra-interval-msec',
    'ra_lifetime': 'lifetime',
    'ra_prefixes': 'openconfig-interfaces-ext:ra-prefixes',
    'ra_retrans_interval': 'openconfig-interfaces-ext:ra-retrans-interval',
    'rdnss': 'openconfig-interfaces-ext:rdnss-addresses',
    'reachable_time': 'openconfig-interfaces-ext:reachable-time',
    'router_preference': 'openconfig-interfaces-ext:router-preference',
    'suppress': 'suppress'
}


class Ipv6_router_advertisementFacts(object):
    """ The sonic ipv6_router_advertisement fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Ipv6_router_advertisementArgs.argument_spec
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
        """ Populate the facts for ipv6_router_advertisement
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass
        if not data:
            objs = self.get_ipv6_router_advertisement()

        ansible_facts['ansible_network_resources'].pop('ipv6_router_advertisement', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['ipv6_router_advertisement'] = remove_empties_from_list(params['config'])

        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_ipv6_router_advertisement(self):
        url = 'data/openconfig-interfaces:interfaces/interface'
        method = 'GET'
        request = [{'path': url, 'method': method}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        interfaces = []
        if 'openconfig-interfaces:interface' in response[0][1]:
            interfaces = response[0][1].get('openconfig-interfaces:interface', [])

        ipv6_rtadv_configs = []
        for interface in interfaces:
            intf_name = interface['name']
            if intf_name.startswith('Vlan'):
                ipv6_conf = interface.get('openconfig-vlan:routed-vlan', {}).get('openconfig-if-ip:ipv6')
                ipv6_rtadv_config = self.render_config(ipv6_conf, intf_name)
                if ipv6_rtadv_config:
                    ipv6_rtadv_configs.append(ipv6_rtadv_config)
            elif not (intf_name == 'eth0' or intf_name.startswith('Management') or '.' in intf_name or '|' in intf_name):
                if interface.get('subinterfaces', {}).get('subinterface'):
                    for sub_intf in interface['subinterfaces']['subinterface']:
                        if sub_intf.get('index', 0) != 0:
                            intf_name = interface['name'] + '.' + str(sub_intf['index'])
                        else:
                            intf_name = interface['name']
                        ipv6_rtadv_config = self.render_config(sub_intf.get('openconfig-if-ip:ipv6'), intf_name)
                        if ipv6_rtadv_config:
                            ipv6_rtadv_configs.append(ipv6_rtadv_config)

        return ipv6_rtadv_configs

    def render_config(self, ipv6_conf, intf_name):
        ipv6_rtadv = {}
        if not ipv6_conf:
            return ipv6_rtadv

        rtadv = ipv6_conf.get('router-advertisement')
        if rtadv:
            if rtadv.get('config'):
                rtadv_config = rtadv['config']
                for option, field in OPTION_TO_PAYLOAD_MAP.items():
                    if field in rtadv_config:
                        if option == 'router_preference':
                            ipv6_rtadv[option] = rtadv_config[field].split('openconfig-interfaces-ext:')[-1].lower()
                        else:
                            ipv6_rtadv[option] = rtadv_config[field]

            if rtadv.get(OPTION_TO_PAYLOAD_MAP['dnssl']):
                self.parse_and_update_dnssl_conf(ipv6_rtadv, rtadv[OPTION_TO_PAYLOAD_MAP['dnssl']])
            if rtadv.get(OPTION_TO_PAYLOAD_MAP['ra_prefixes']):
                self.parse_and_update_ra_prefixes_conf(ipv6_rtadv, rtadv[OPTION_TO_PAYLOAD_MAP['ra_prefixes']])
            if rtadv.get(OPTION_TO_PAYLOAD_MAP['rdnss']):
                self.parse_and_update_rdnss_conf(ipv6_rtadv, rtadv[OPTION_TO_PAYLOAD_MAP['rdnss']])

            # Fill in default values
            for option, def_value in DEFAULT_VALUES.items():
                ipv6_rtadv.setdefault(option, def_value)

        if ipv6_rtadv:
            ipv6_rtadv['name'] = intf_name

        return ipv6_rtadv

    @staticmethod
    def parse_and_update_dnssl_conf(ipv6_rtadv, dnssl_conf):
        if dnssl_conf:
            parsed_dnssl_list = []
            for item in dnssl_conf.get('dns-search-name', []):
                parsed_conf = {}
                if item.get('dnssl-name'):
                    parsed_conf['dnssl_name'] = item['dnssl-name']
                    if item.get('config') and 'valid-lifetime' in item['config']:
                        parsed_conf['valid_lifetime'] = item['config']['valid-lifetime']
                    parsed_dnssl_list.append(parsed_conf)

            if parsed_dnssl_list:
                ipv6_rtadv['dnssl'] = parsed_dnssl_list

    @staticmethod
    def parse_and_update_ra_prefixes_conf(ipv6_rtadv, ra_prefixes_conf):
        if ra_prefixes_conf:
            parsed_ra_prefixes = []
            for item in ra_prefixes_conf.get('ra-prefix', []):
                parsed_conf = {}
                if item.get('prefix'):
                    parsed_conf = {
                        'prefix': item['prefix'],
                        'no_autoconfig': False,
                        'off_link': False,
                        'router_address': False
                    }
                    if item.get('config'):
                        for option in ('no-autoconfig', 'off-link', 'preferred-lifetime', 'router-address', 'valid-lifetime'):
                            if option in item['config']:
                                parsed_conf[option.replace('-', '_')] = item['config'][option]
                    parsed_ra_prefixes.append(parsed_conf)

            if parsed_ra_prefixes:
                ipv6_rtadv['ra_prefixes'] = parsed_ra_prefixes

    @staticmethod
    def parse_and_update_rdnss_conf(ipv6_rtadv, rdnss_conf):
        if rdnss_conf:
            parsed_rdnss_list = []
            for item in rdnss_conf.get('rdnss-address', []):
                parsed_conf = {}
                if item.get('address'):
                    parsed_conf['address'] = item['address']
                    if item.get('config') and 'valid-lifetime' in item['config']:
                        parsed_conf['valid_lifetime'] = item['config']['valid-lifetime']
                    parsed_rdnss_list.append(parsed_conf)

            if parsed_rdnss_list:
                ipv6_rtadv['rdnss'] = parsed_rdnss_list
