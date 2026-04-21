#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic ip_neighbor_interfaces fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ip_neighbor_interfaces.ip_neighbor_interfaces import (
    Ip_neighbor_interfacesArgs
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError


class Ip_neighbor_interfacesFacts(object):
    """ The sonic ip_neighbor_interfaces fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Ip_neighbor_interfacesArgs.argument_spec
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
        """ Populate the facts for ip_neighbor_interfaces
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass

        if not data:
            objs = self.get_ip_neighbor_interfaces()

        ansible_facts['ansible_network_resources'].pop('ip_neighbor_interfaces', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['ip_neighbor_interfaces'] = remove_empties_from_list(params['config'])

        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_ip_neighbor_interfaces(self):
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

        ip_neighbor_configs = []
        for interface in interfaces:
            intf_name = interface['name']
            if intf_name.startswith('Vlan'):
                intf_neighbor_config = self.render_config(interface.get('openconfig-vlan:routed-vlan'), intf_name)
                if intf_neighbor_config:
                    ip_neighbor_configs.append(intf_neighbor_config)
            elif not (intf_name == 'eth0' or intf_name.startswith('Management') or '.' in intf_name or '|' in intf_name):
                if interface.get('subinterfaces', {}).get('subinterface'):
                    for sub_intf in interface['subinterfaces']['subinterface']:
                        if sub_intf.get('index', 0) != 0:
                            intf_name = interface['name'] + '.' + str(sub_intf['index'])
                        else:
                            intf_name = interface['name']
                        intf_neighbor_config = self.render_config(sub_intf, intf_name)
                        if intf_neighbor_config:
                            ip_neighbor_configs.append(intf_neighbor_config)

        return ip_neighbor_configs

    def render_config(self, conf, intf_name):
        ip_neighbors = {}
        if not conf:
            return ip_neighbors

        ipv4_conf = conf.get('openconfig-if-ip:ipv4')
        ipv6_conf = conf.get('openconfig-if-ip:ipv6')
        ipv4_neighbors, ipv6_neighbors = [], []

        if ipv4_conf and ipv4_conf.get('neighbors') and ipv4_conf['neighbors'].get('neighbor'):
            for neighbor in ipv4_conf['neighbors']['neighbor']:
                if neighbor.get('config'):
                    ipv4_neighbors.append({
                        'ip': neighbor['config']['ip'],
                        'mac': neighbor['config']['link-layer-address'],
                    })
            if ipv4_neighbors:
                ip_neighbors['ipv4_neighbors'] = ipv4_neighbors

        if ipv6_conf and ipv6_conf.get('neighbors') and ipv6_conf['neighbors'].get('neighbor'):
            for neighbor in ipv6_conf['neighbors']['neighbor']:
                if neighbor.get('config'):
                    ipv6_neighbors.append({
                        'ip': neighbor['config']['ip'],
                        'mac': neighbor['config']['link-layer-address'],
                    })
            if ipv6_neighbors:
                ip_neighbors['ipv6_neighbors'] = ipv6_neighbors

        if ip_neighbors:
            ip_neighbors['name'] = intf_name

        return ip_neighbors
