#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic qos_maps fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible.module_utils.connection import ConnectionError
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    remove_empties
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.qos_maps.qos_maps import Qos_mapsArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)

QOS_PATH = '/data/openconfig-qos:qos'


class Qos_mapsFacts(object):
    """ The sonic qos_maps fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Qos_mapsArgs.argument_spec
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
        """ Populate the facts for qos_maps
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []

        if not data:
            data = self.update_qos_maps(self._module)
        objs = data
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['qos_maps'] = remove_empties(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def update_qos_maps(self, module):
        """
        Convert OC configuration to Ansible

        :param module: QoS maps module
        :rtype: dictionary
        :returns: The QoS maps configuration
        """
        config_dict = {}

        dscp_maps = self.get_config(module, 'openconfig-qos-maps-ext:dscp-maps')
        if dscp_maps:
            lookup_dict = {'oc_map': 'dscp-map', 'oc_attr1': 'dscp', 'oc_attr2': 'fwd-group', 'attr1': 'dscp', 'attr2': 'fwd_group',
                           'map_name': 'dscp_maps'}
            self.update_config(dscp_maps, lookup_dict, config_dict)

        dot1p_maps = self.get_config(module, 'openconfig-qos-maps-ext:dot1p-maps')
        if dot1p_maps:
            lookup_dict = {'oc_map': 'dot1p-map', 'oc_attr1': 'dot1p', 'oc_attr2': 'fwd-group', 'attr1': 'dot1p', 'attr2': 'fwd_group',
                           'map_name': 'dot1p_maps'}
            self.update_config(dot1p_maps, lookup_dict, config_dict)

        fwd_group_queue_maps = self.get_config(module, 'openconfig-qos-maps-ext:forwarding-group-queue-maps')
        if fwd_group_queue_maps:
            lookup_dict = {'oc_map': 'forwarding-group-queue-map', 'oc_attr1': 'output-queue-index', 'oc_attr2': 'fwd-group', 'attr1': 'queue_index',
                           'attr2': 'fwd_group', 'map_name': 'fwd_group_queue_maps'}
            self.update_config(fwd_group_queue_maps, lookup_dict, config_dict)

        fwd_group_dscp_maps = self.get_config(module, 'openconfig-qos-maps-ext:forwarding-group-dscp-maps')
        if fwd_group_dscp_maps:
            lookup_dict = {'oc_map': 'forwarding-group-dscp-map', 'oc_attr1': 'dscp', 'oc_attr2': 'fwd-group', 'attr1': 'dscp', 'attr2': 'fwd_group',
                           'map_name': 'fwd_group_dscp_maps'}
            self.update_config(fwd_group_dscp_maps, lookup_dict, config_dict)

        fwd_group_dot1p_maps = self.get_config(module, 'openconfig-qos-maps-ext:forwarding-group-dot1p-maps')
        if fwd_group_dot1p_maps:
            lookup_dict = {'oc_map': 'forwarding-group-dot1p-map', 'oc_attr1': 'dot1p', 'oc_attr2': 'fwd-group', 'attr1': 'dot1p',
                           'attr2': 'fwd_group', 'map_name': 'fwd_group_dot1p_maps'}
            self.update_config(fwd_group_dot1p_maps, lookup_dict, config_dict)

        fwd_group_pg_maps = self.get_config(module, 'openconfig-qos-maps-ext:forwarding-group-priority-group-maps')
        if fwd_group_pg_maps:
            lookup_dict = {'oc_map': 'forwarding-group-priority-group-map', 'oc_attr1': 'priority-group-index', 'oc_attr2': 'fwd-group',
                           'attr1': 'pg_index', 'attr2': 'fwd_group', 'map_name': 'fwd_group_pg_maps'}
            self.update_config(fwd_group_pg_maps, lookup_dict, config_dict)

        pfc_priority_queue_maps = self.get_config(module, 'openconfig-qos-maps-ext:pfc-priority-queue-maps')
        if pfc_priority_queue_maps:
            lookup_dict = {'oc_map': 'pfc-priority-queue-map', 'oc_attr1': 'dot1p', 'oc_attr2': 'output-queue-index', 'attr1': 'dot1p',
                           'attr2': 'queue_index', 'map_name': 'pfc_priority_queue_maps'}
            self.update_config(pfc_priority_queue_maps, lookup_dict, config_dict)

        pfc_priority_pg_maps = self.get_config(module, 'openconfig-qos-maps-ext:pfc-priority-priority-group-maps')
        if pfc_priority_pg_maps:
            lookup_dict = {'oc_map': 'pfc-priority-priority-group-map', 'oc_attr1': 'dot1p', 'oc_attr2': 'priority-group-index', 'attr1': 'dot1p',
                           'attr2': 'pg_index', 'map_name': 'pfc_priority_pg_maps'}
            self.update_config(pfc_priority_pg_maps, lookup_dict, config_dict)

        return config_dict

    def get_config(self, module, map_path):
        cfg = None
        get_path = '%s/%s' % (QOS_PATH, map_path)
        request = {'path': get_path, 'method': 'get'}

        try:
            response = edit_config(module, to_request(module, request))
            if map_path in response[0][1]:
                cfg = response[0][1].get(map_path)
        except ConnectionError as exc:
            module.fail_json(msg=str(exc), code=exc.code)

        return cfg

    def update_config(self, maps_cfg, lookup_dict, config_dict):
        """
        Get the Ansible maps list for a specified QoS map and update QoS maps config

        :param maps_cfg: Dictionary of OC maps configuration for a specified QoS map
        :param lookup_dict: Dictionary of OC and Ansible data used to process a specified QoS map
        :param config_dict: Dictionary of configuration for QoS maps module
        """
        maps_list = []
        maps = maps_cfg.get(lookup_dict['oc_map'])

        if maps:
            for m in maps:
                map_dict = {}
                name = m.get('name')
                oc_map = lookup_dict['oc_map']
                map_entries = m.get(oc_map + '-entries')

                if map_entries:
                    entries = map_entries.get(oc_map + '-entry')
                    if entries:
                        entries_list = []
                        for entry in entries:
                            entry_dict = {}
                            entry_cfg = entry.get('config')
                            oc_attr1 = lookup_dict['oc_attr1']
                            oc_attr2 = lookup_dict['oc_attr2']
                            attr1 = entry_cfg.get(oc_attr1)
                            attr2 = entry_cfg.get(oc_attr2)

                            if attr1 is not None:
                                attr1_key = lookup_dict['attr1']
                                entry_dict[attr1_key] = attr1
                            if attr2 is not None:
                                attr2_key = lookup_dict['attr2']
                                entry_dict[attr2_key] = attr2
                            if entry_dict:
                                entries_list.append(entry_dict)

                        if entries_list:
                            map_dict['entries'] = entries_list

                if name:
                    map_dict['name'] = name
                if map_dict:
                    maps_list.append(map_dict)
        if maps_list:
            map_name = lookup_dict['map_name']
            config_dict[map_name] = maps_list
