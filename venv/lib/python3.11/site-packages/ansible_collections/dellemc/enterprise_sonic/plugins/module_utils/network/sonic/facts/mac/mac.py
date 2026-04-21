#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic mac_address fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy

from ansible.module_utils.connection import ConnectionError
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.mac.mac import MacArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.bgp_utils import (
    get_all_vrfs,
)

NETWORK_INSTANCE_PATH = '/data/openconfig-network-instance:network-instances/network-instance'


class MacFacts(object):
    """ The sonic mac fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = MacArgs.argument_spec
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
        """ Populate the facts for mac_address
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []

        if not data:
            data = self.update_mac(self._module)
        objs = data
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['mac'] = remove_empties_from_list(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def update_mac(self, module):
        mac_address_cfg_list = []
        vrfs = get_all_vrfs(module)
        for vrf_name in vrfs:
            aging_time = self.get_config(vrf_name, module, 'fdb/config/mac-aging-time', 'openconfig-network-instance:mac-aging-time')
            dampening_cfg_dict = self.get_config(vrf_name, module, 'openconfig-mac-dampening:mac-dampening/config', 'openconfig-mac-dampening:config')
            entries_dict = self.get_config(vrf_name, module, 'fdb/mac-table/entries', 'openconfig-network-instance:entries')
            cfg_dict = {}
            mac_dict = {}
            mac_table_entries = []
            dampening_interval = dampening_cfg_dict.get('interval', None)
            dampening_threshold = dampening_cfg_dict.get('threshold', None)

            if entries_dict:
                entry_list = entries_dict.get('entry', [])
                for entry in entry_list:
                    entry_dict = {}
                    mac_address = entry.get('mac-address', None)
                    vlan_id = entry.get('vlan', None)
                    interface = entry.get('interface', {}).get('interface-ref', {}).get('config', {}).get('interface', None)
                    if mac_address:
                        entry_dict['mac_address'] = mac_address
                    if vlan_id:
                        entry_dict['vlan_id'] = vlan_id
                    if interface:
                        entry_dict['interface'] = interface
                    if entry_dict:
                        mac_table_entries.append(entry_dict)

            if aging_time:
                mac_dict['aging_time'] = aging_time
            if dampening_interval:
                mac_dict['dampening_interval'] = dampening_interval
            if dampening_threshold:
                mac_dict['dampening_threshold'] = dampening_threshold
            if mac_table_entries:
                mac_dict['mac_table_entries'] = mac_table_entries
            if mac_dict:
                cfg_dict['mac'] = mac_dict
            cfg_dict['vrf_name'] = vrf_name
            mac_address_cfg_list.append(cfg_dict)

        return mac_address_cfg_list

    def get_config(self, vrf_name, module, path, name):
        cfg_dict = {}
        get_path = '%s=%s/%s' % (NETWORK_INSTANCE_PATH, vrf_name, path)
        request = {'path': get_path, 'method': 'get'}

        try:
            response = edit_config(module, to_request(module, request))
            if name in response[0][1]:
                cfg_dict = response[0][1].get(name, None)
        except ConnectionError as exc:
            module.fail_json(msg=str(exc), code=exc.code)
        return cfg_dict
