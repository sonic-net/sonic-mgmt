#
# -*- coding: utf-8 -*-
# Copyright 2020 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic l3_interfaces fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.l3_interfaces.l3_interfaces import L3_interfacesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

DEFAULT_IPV6_VALUES = {
    'autoconf': False,
    'dad': 'DISABLE',
    'enabled': False
}


class L3_interfacesFacts(object):
    """ The sonic l3_interfaces fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = L3_interfacesArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def get_l3_interfaces(self):
        url = "data/openconfig-interfaces:interfaces/interface"
        method = "GET"
        request = [{"path": url, "method": method}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        l3_lists = []
        if "openconfig-interfaces:interface" in response[0][1]:
            l3_lists = response[0][1].get("openconfig-interfaces:interface", [])

        l3_configs = []
        for l3 in l3_lists:
            l3_name = l3['name']
            if l3_name.startswith('Vlan'):
                l3_config = self.transform_config(l3.get('openconfig-vlan:routed-vlan'), l3_name, is_vlan=True)
                if l3_config:
                    l3_configs.append(l3_config)
            elif not (l3_name == 'eth0' or l3_name.startswith('Management') or '.' in l3_name or '|' in l3_name):
                if l3.get('subinterfaces', {}).get('subinterface'):
                    for sub_intf in l3['subinterfaces']['subinterface']:
                        if sub_intf.get('index', 0) != 0:
                            l3_name = l3['name'] + '.' + str(sub_intf['index'])
                        else:
                            l3_name = l3['name']
                        l3_config = self.transform_config(sub_intf, l3_name)
                        if l3_config:
                            l3_configs.append(l3_config)

        return l3_configs

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for l3_interfaces
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass
        if not data:
            objs = self.get_l3_interfaces()

        ansible_facts['ansible_network_resources'].pop('l3_interfaces', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['l3_interfaces'] = remove_empties_from_list(params['config'])

        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def transform_config(self, conf, intf_name, is_vlan=False):
        transformed_conf = {}
        only_defaults = True
        if not conf:
            return transformed_conf

        ipv4 = {}
        ipv6 = {}
        conf_ipv4 = conf.get('openconfig-if-ip:ipv4')
        conf_ipv6 = conf.get('openconfig-if-ip:ipv6')

        if conf_ipv4:
            if conf_ipv4.get('addresses') and conf_ipv4['addresses'].get('address'):
                ipv4_addrs = []
                for item in conf_ipv4['addresses']['address']:
                    if item.get('config') and item['config'].get('ip'):
                        ipv4_addrs.append({
                            'address': item['config']['ip'] + '/' + str(item['config']['prefix-length']),
                            'secondary': item['config'].get('secondary', False)
                        })
                if ipv4_addrs:
                    ipv4['addresses'] = ipv4_addrs

            if is_vlan:
                if (conf_ipv4.get('openconfig-interfaces-ext:sag-ipv4') and conf_ipv4['openconfig-interfaces-ext:sag-ipv4'].get('config')
                        and conf_ipv4['openconfig-interfaces-ext:sag-ipv4']['config'].get('static-anycast-gateway')):
                    ipv4['anycast_addresses'] = conf_ipv4['openconfig-interfaces-ext:sag-ipv4']['config']['static-anycast-gateway']

            conf_proxy_arp = conf_ipv4.get('proxy-arp', {}).get('config')
            if conf_proxy_arp and 'mode' in conf_proxy_arp:
                ipv4.setdefault('proxy_arp', {})['mode'] = conf_proxy_arp['mode']

            if ipv4:
                only_defaults = False
                transformed_conf['ipv4'] = ipv4

        if conf_ipv6:
            if conf_ipv6.get('addresses') and conf_ipv6['addresses'].get('address'):
                ipv6_addrs = []
                for item in conf_ipv6['addresses']['address']:
                    if item.get('config') and item['config'].get('ip'):
                        temp = {'address': item['config']['ip'] + '/' + str(item['config']['prefix-length'])}
                        if item['config'].get('openconfig-interfaces-private:eui64'):
                            temp['eui64'] = item['config']['openconfig-interfaces-private:eui64']
                        ipv6_addrs.append(temp)
                if ipv6_addrs:
                    ipv6['addresses'] = ipv6_addrs

            if is_vlan:
                if (conf_ipv6.get('openconfig-interfaces-ext:sag-ipv6') and conf_ipv6['openconfig-interfaces-ext:sag-ipv6'].get('config')
                        and conf_ipv6['openconfig-interfaces-ext:sag-ipv6']['config'].get('static-anycast-gateway')):
                    ipv6['anycast_addresses'] = conf_ipv6['openconfig-interfaces-ext:sag-ipv6']['config']['static-anycast-gateway']

            if conf_ipv6.get('config'):
                if 'enabled' in conf_ipv6['config']:
                    ipv6['enabled'] = conf_ipv6['config']['enabled']
                if 'ipv6_dad' in conf_ipv6['config']:
                    ipv6['dad'] = conf_ipv6['config']['ipv6_dad']
                if 'ipv6_autoconfig' in conf_ipv6['config']:
                    ipv6['autoconf'] = conf_ipv6['config']['ipv6_autoconfig']

            conf_nd_proxy = conf_ipv6.get('nd-proxy', {}).get('config')
            if conf_nd_proxy:
                ipv6.setdefault('nd_proxy', {})
                if 'mode' in conf_nd_proxy:
                    ipv6['nd_proxy']['mode'] = conf_nd_proxy['mode']
                if 'nd-proxy-rules' in conf_nd_proxy:
                    ipv6['nd_proxy']['nd_proxy_rules'] = conf_nd_proxy['nd-proxy-rules']

            for option, value in ipv6.items():
                if option == 'nd_proxy':
                    # If nd_proxy is present and has any keys, it's not default
                    if value:  # value is a dict, so non-empty means non-default
                        only_defaults = False
                        break
                elif (option not in DEFAULT_IPV6_VALUES) or (value != DEFAULT_IPV6_VALUES[option]):
                    only_defaults = False
                    break

            # Update facts for interface only when at least one option is not default
            if ipv6 and not only_defaults:
                transformed_conf['ipv6'] = ipv6

        if transformed_conf:
            transformed_conf['name'] = intf_name

        return transformed_conf
