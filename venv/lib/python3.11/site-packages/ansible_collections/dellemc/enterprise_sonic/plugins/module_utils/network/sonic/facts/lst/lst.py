#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic lst fact class
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
    remove_empties
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.lst.lst import LstArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)


class LstFacts(object):
    """
    The sonic lst fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = LstArgs.argument_spec
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
        """
        Populate the facts for lst
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []

        if not data:
            cfg = self.get_config(self._module)
            data = self.update_lst(cfg)
        objs = data
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['lst'] = remove_empties(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_config(self, module):
        cfg = None
        get_path = 'data/openconfig-lst-ext:lst'
        request = {'path': get_path, 'method': 'get'}

        try:
            response = edit_config(module, to_request(module, request))
            if 'openconfig-lst-ext:lst' in response[0][1]:
                cfg = response[0][1].get('openconfig-lst-ext:lst')
        except ConnectionError as exc:
            module.fail_json(msg=str(exc), code=exc.code)

        return cfg

    def update_lst(self, cfg):
        config_dict = {}
        enum_dict = {'openconfig-lst-ext:GROUP_L3': 'l3', 'openconfig-lst-ext:ONLINE_PERCENTAGE': 'percentage'}

        if cfg:
            if 'lst-groups' in cfg and 'lst-group' in cfg['lst-groups']:
                lst_group = cfg['lst-groups']['lst-group']
                lst_groups_list = []
                for group in lst_group:
                    group_dict = {}
                    name = group.get('name')
                    config = group.get('config')

                    if name:
                        group_dict['name'] = name
                    if config:
                        # For all_evpn_es_downstream and all_mclags_downstream attributes, current SONiC behavior treats none value as false
                        all_evpn_es_downstream = config.get('all-evpn-es-downstream', False)
                        all_mclags_downstream = config.get('all-mclags-downstream', False)
                        group_description = config.get('description')
                        group_type = config.get('type')
                        threshold_down = config.get('threshold-down')
                        threshold_type = config.get('threshold-type')
                        threshold_up = config.get('threshold-up')
                        timeout = config.get('timeout')

                        group_dict['all_evpn_es_downstream'] = all_evpn_es_downstream
                        group_dict['all_mclags_downstream'] = all_mclags_downstream
                        if group_description:
                            group_dict['group_description'] = group_description
                        if group_type:
                            group_dict['group_type'] = enum_dict[group_type]
                        if threshold_down is not None:
                            group_dict['threshold_down'] = int(threshold_down)
                        if threshold_type:
                            group_dict['threshold_type'] = enum_dict[threshold_type]
                        if threshold_up is not None:
                            group_dict['threshold_up'] = int(threshold_up)
                        if timeout:
                            group_dict['timeout'] = timeout
                    if group_dict:
                        lst_groups_list.append(group_dict)
                if lst_groups_list:
                    config_dict['lst_groups'] = lst_groups_list

            if 'interfaces' in cfg and 'interface' in cfg['interfaces']:
                interface = cfg['interfaces']['interface']
                interfaces_list = []
                for intf in interface:
                    intf_dict = {}
                    name = intf.get('id')

                    if name:
                        intf_dict['name'] = name
                    if 'downstream-group' in intf and 'config' in intf['downstream-group'] and 'group-name' in intf['downstream-group']['config']:
                        downstream_group = intf['downstream-group']['config']['group-name']
                        intf_dict['downstream_group'] = downstream_group
                    if 'upstream-groups' in intf and 'upstream-group' in intf['upstream-groups']:
                        upstream_group = intf['upstream-groups']['upstream-group']
                        groups_list = []
                        for group in upstream_group:
                            group_name = group.get('group-name')
                            if group_name:
                                groups_list.append({'group_name': group_name})
                        if groups_list:
                            intf_dict['upstream_groups'] = groups_list
                    if intf_dict:
                        interfaces_list.append(intf_dict)
                if interfaces_list:
                    config_dict['interfaces'] = interfaces_list

        return config_dict
