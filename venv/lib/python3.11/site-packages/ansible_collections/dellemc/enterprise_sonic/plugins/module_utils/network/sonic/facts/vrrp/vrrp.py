#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic vrrp fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils \
    import (
        remove_empties_from_list
    )
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.vrrp.vrrp import VrrpArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

VRRP_ATTRIBUTES = {
    'virtual-router-id': 'virtual_router_id',
    'advertisement-interval': 'advertisement_interval',
    'preempt': 'preempt',
    'priority': 'priority',
    'openconfig-interfaces-ext:use-v2-checksum': 'use_v2_checksum',
    'openconfig-interfaces-ext:version': 'version',
}


class VrrpFacts(object):
    """ The sonic vrrp fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = VrrpArgs.argument_spec
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
        """ Populate the facts for vrrp
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []
        if connection:  # just for linting purposes, remove
            pass
        all_vrrp_configs = {}

        if not data:
            all_vrrp_configs = self.get_vrrp()

        for vrrp_config in all_vrrp_configs:
            obj = self.render_config(self.generated_spec, vrrp_config)
            if obj:
                objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('vrrp', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['vrrp'] = remove_empties_from_list(params['config'])
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

    def get_vrrp(self):
        """Get all VRRP/VRRP6 configurations available in chassis"""
        request = [{'path': 'data/openconfig-interfaces:interfaces', 'method': 'GET'}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)
        vrrp_configs = []

        if 'openconfig-interfaces:interfaces' in response[0][1]:
            interfaces = response[0][1].get('openconfig-interfaces:interfaces', {})
            if interfaces.get('interface'):
                interfaces = interfaces['interface']
                for interface in interfaces:
                    intf_name = interface.get('name')
                    openconfig = None
                    if 'Eth' in intf_name or 'PortChannel' in intf_name:
                        sub_interface = interface.get('subinterfaces', {})
                        sub_intf_list = sub_interface.get('subinterface', {})
                        for sub_intf in sub_intf_list:
                            if sub_intf.get('index') != 0:
                                intf_name = intf_name + '.' + str(sub_intf.get('index'))
                            openconfig = sub_intf
                            if openconfig:
                                vrrp_intf_config = self.get_vrrp_from_interface(openconfig, intf_name)
                                if vrrp_intf_config:
                                    vrrp_configs.append(vrrp_intf_config)
                    elif 'Vlan' in intf_name:
                        openconfig = interface.get('openconfig-vlan:routed-vlan')
                        if openconfig:
                            vrrp_intf_config = self.get_vrrp_from_interface(openconfig, intf_name)
                            if vrrp_intf_config:
                                vrrp_configs.append(vrrp_intf_config)

        return vrrp_configs

    def get_vrrp_from_interface(self, openconfig, intf_name):
        vrrp = {}
        ipv4_dict = openconfig.get('openconfig-if-ip:ipv4')
        ipv6_dict = openconfig.get('openconfig-if-ip:ipv6')
        ipv4_vrrp_list, ipv6_vrrp_list = [], []
        if ipv4_dict and ipv4_dict.get('addresses') and ipv4_dict['addresses'].get('address'):
            ipv4_address_list = ipv4_dict['addresses']['address']
            for ipv4_addr in ipv4_address_list:
                if ipv4_addr.get('vrrp') and ipv4_addr['vrrp'].get('vrrp-group'):
                    ipv4_list = self.get_vrrp_from_ip_dict(ipv4_addr['vrrp']['vrrp-group'], 'ipv4')
                    if ipv4_list:
                        ipv4_vrrp_list.extend(ipv4_list)
        if ipv6_dict and ipv6_dict.get('addresses') and ipv6_dict['addresses'].get('address'):
            ipv6_address_list = ipv6_dict['addresses']['address']
            for ipv6_addr in ipv6_address_list:
                if ipv6_addr.get('vrrp') and ipv6_addr['vrrp'].get('vrrp-group'):
                    ipv6_list = self.get_vrrp_from_ip_dict(ipv6_addr['vrrp']['vrrp-group'], 'ipv6')
                    if ipv6_list:
                        ipv6_vrrp_list.extend(ipv6_list)
        if ipv4_vrrp_list or ipv6_vrrp_list:
            vrrp['group'] = []
            if ipv4_vrrp_list:
                vrrp['group'].extend(ipv4_vrrp_list)
            if ipv6_vrrp_list:
                vrrp['group'].extend(ipv6_vrrp_list)
        if vrrp:
            vrrp['name'] = intf_name
        return vrrp

    def get_vrrp_from_ip_dict(self, vrrp_group, afi):
        vrrp_object = []
        for group in vrrp_group:
            vrrp_dict = {}
            track_interface = group.get('openconfig-interfaces-ext:vrrp-track')
            track_intf_group = []
            config = group.get('config', [])
            for cfg in config:
                if cfg == 'virtual-address':
                    if config.get('virtual-address'):
                        vrrp_dict['virtual_address'] = []
                        for address in config['virtual-address']:
                            if address:
                                vrrp_dict['virtual_address'].append({'address': address})
                else:
                    if cfg in VRRP_ATTRIBUTES:
                        vrrp_dict[VRRP_ATTRIBUTES[cfg]] = config[cfg]
            if track_interface:
                for track_intf in track_interface.get('vrrp-track-interface', []):
                    track_cfg = track_intf.get('config', None)
                    if track_cfg and 'track-intf' in track_cfg and 'priority-increment' in track_cfg:
                        track_intf_group.append({'interface': track_cfg['track-intf'], 'priority_increment': track_cfg['priority-increment']})
            if track_intf_group:
                vrrp_dict['track_interface'] = track_intf_group
            if vrrp_dict:
                vrrp_dict['afi'] = afi
                vrrp_object.append(vrrp_dict)
        return vrrp_object
