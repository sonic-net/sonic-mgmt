#
# -*- coding: utf-8 -*-
# © Copyright 2023 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic interfaces fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.interfaces.interfaces import InterfacesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

GET = "get"


class InterfacesFacts(object):
    """ The sonic interfaces fact class
    """
    loop_backs = ","

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = InterfacesArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def get_all_interfaces(self):
        """Get all the interfaces available in chassis"""
        all_interfaces = {}
        request = [{"path": "data/openconfig-interfaces:interfaces", "method": GET}]
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        if "openconfig-interfaces:interfaces" in response[0][1]:
            all_interfaces = response[0][1].get("openconfig-interfaces:interfaces", {})

        return all_interfaces['interface']

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for interfaces
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []
        if connection:  # just for linting purposes, remove
            pass

        if not data:
            # typically data is populated from the current device configuration
            # data = connection.get('show running-config | section ^interface')
            # using mock data instead
            data = self.get_all_interfaces()
        # operate on a collection of resource x
        self.reset_loop_backs()

        for conf in data:
            if conf:
                obj = self.render_config(self.generated_spec, conf)
                obj = self.transform_config(obj)
        # split the config into instances of the resource
                if obj:
                    objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('interfaces', None)
        facts = {}
        if objs:
            facts['interfaces'] = []
            params = utils.validate_config(self.argument_spec, {'config': objs})
            for cfg in params['config']:
                facts['interfaces'].append(utils.remove_empties(cfg))
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

    def transform_config(self, conf):
        trans_cfg = {}
        if conf.get('config') is None:
            return trans_cfg

        exist_cfg = conf['config']
        is_loop_back = False
        name = conf['name']
        if name.startswith('Loopback'):
            is_loop_back = True
            pos = name.find('|')
            if pos > 0:
                name = name[0:pos]

        if not (is_loop_back and self.is_loop_back_already_exist(name)) and (name != "eth0") and (name != "Management0"):
            trans_cfg['name'] = name
            trans_cfg['enabled'] = exist_cfg['enabled'] if exist_cfg.get('enabled') is not None else True
            trans_cfg['description'] = exist_cfg.get('description')
            if is_loop_back:
                self.update_loop_backs(name)
            else:
                # VLAN/Portchannel
                trans_cfg['mtu'] = exist_cfg['mtu'] if exist_cfg.get('mtu') else 9100

        if name.startswith('Eth') and 'openconfig-if-ethernet:ethernet' in conf:
            if conf['openconfig-if-ethernet:ethernet'].get('config', None):
                eth_conf = conf['openconfig-if-ethernet:ethernet']['config']
                if 'auto-negotiate' in eth_conf:
                    trans_cfg['auto_negotiate'] = eth_conf['auto-negotiate']
                trans_cfg['speed'] = eth_conf['port-speed'].split(':', 1)[-1]
                if 'openconfig-if-ethernet-ext2:advertised-speed' in eth_conf:
                    adv_speed_str = eth_conf['openconfig-if-ethernet-ext2:advertised-speed']
                    if adv_speed_str != '':
                        trans_cfg['advertised_speed'] = adv_speed_str.split(",")
                        trans_cfg['advertised_speed'].sort()
                if 'openconfig-if-ethernet-ext2:port-fec' in eth_conf:
                    trans_cfg['fec'] = eth_conf['openconfig-if-ethernet-ext2:port-fec'].split(':', 1)[-1]
                if 'openconfig-if-ethernet-ext2:unreliable-los' in eth_conf:
                    trans_cfg['unreliable_los'] = eth_conf['openconfig-if-ethernet-ext2:unreliable-los'].split(':', 1)[-1]

        return trans_cfg

    def reset_loop_backs(self):
        self.loop_backs = ","

    def update_loop_backs(self, loop_back):
        self.loop_backs += "{0},".format(loop_back)

    def is_loop_back_already_exist(self, loop_back):
        return (",{0},".format(loop_back) in self.loop_backs)
