from __future__ import absolute_import, division, print_function
__metaclass__ = type
#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic br_l2pt fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""
import re
from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.br_l2pt.br_l2pt import Br_l2ptArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

GET = 'get'


class Br_l2ptFacts(object):
    """ The sonic br_l2pt fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Br_l2ptArgs.argument_spec
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
        """ Populate the facts for br_l2pt
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = self.get_all_l2pt_interfaces()

        ansible_facts['ansible_network_resources'].pop('br_l2pt', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['br_l2pt'] = remove_empties_from_list(params['config'])

        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_all_l2pt_interfaces(self):
        """ Get all br_l2pt configurations
        :rtype: list
        :returns: configs
        """
        l2pt_interfaces_path = 'data/openconfig-interfaces:interfaces'
        request = [{'path': l2pt_interfaces_path, 'method': GET}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        resp = response[0][1].get('openconfig-interfaces:interfaces')
        l2pt_interface_configs = []
        if resp:
            resp = resp.get('interface', [])
            for interface in resp:
                name = interface.get('name', [])
                if not name or not re.search('Eth', interface['name']):
                    continue
                config = interface.get('openconfig-interfaces-ext:bridge-l2pt-params', {}).get('bridge-l2pt-param', [])
                if config:
                    l2pt_intf_data = {'name': name, 'bridge_l2pt_params': []}
                    for proto_config in config:
                        proto = proto_config.get('protocol', None)
                        if proto:
                            proto_dict = {'protocol': proto}
                            proto_dict['vlan_ids'] = self.replace_ranges(proto_config.get('config').get('vlan-ids', []))
                            l2pt_intf_data['bridge_l2pt_params'].append(proto_dict)
                    l2pt_interface_configs.append(l2pt_intf_data)

        return l2pt_interface_configs

    def replace_ranges(self, vlan_ids):
        """
        Replace ranges that use a dash with two dots for REST request format.
        """
        new_vlan_ids = []
        for vid in vlan_ids:
            if isinstance(vid, str) and ".." in vid:
                temp = vid.replace("..", "-")
            else:
                temp = int(vid)
            new_vlan_ids.append(temp)
        return new_vlan_ids
