#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_qos_maps class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from copy import deepcopy
from ansible.module_utils.connection import ConnectionError
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    remove_empties,
    update_states
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_CONFIG_IF_NO_SUBCONFIG,
    get_new_config,
    get_formatted_config_diff
)


QOS_PATH = '/data/openconfig-qos:qos'
PATCH = 'patch'
DELETE = 'delete'
TEST_KEYS_formatted_diff = [
    {'dscp_maps': {'name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'dot1p_maps': {'name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'fwd_group_queue_maps': {'name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'fwd_group_dscp_maps': {'name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'fwd_group_dot1p_maps': {'name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'fwd_group_pg_maps': {'name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'pfc_priority_queue_maps': {'name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'pfc_priority_pg_maps': {'name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'entries': {'dscp': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'entries': {'dot1p': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'entries': {'fwd_group': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}}
]
lookup_list = [
    {'map_name': 'dscp_maps', 'oc_map': 'dscp-map', 'attr1': 'dscp', 'attr2': 'fwd_group', 'oc_attr1': 'dscp', 'oc_attr2': 'fwd-group'},
    {'map_name': 'dot1p_maps', 'oc_map': 'dot1p-map', 'attr1': 'dot1p', 'attr2': 'fwd_group', 'oc_attr1': 'dot1p', 'oc_attr2': 'fwd-group'},
    {'map_name': 'fwd_group_queue_maps', 'oc_map': 'forwarding-group-queue-map', 'attr1': 'fwd_group', 'attr2': 'queue_index',
     'oc_attr1': 'fwd-group', 'oc_attr2': 'output-queue-index'},
    {'map_name': 'fwd_group_dscp_maps', 'oc_map': 'forwarding-group-dscp-map', 'attr1': 'fwd_group', 'attr2': 'dscp', 'oc_attr1': 'fwd-group',
     'oc_attr2': 'dscp'},
    {'map_name': 'fwd_group_dot1p_maps', 'oc_map': 'forwarding-group-dot1p-map', 'attr1': 'fwd_group', 'attr2': 'dot1p', 'oc_attr1': 'fwd-group',
     'oc_attr2': 'dot1p'},
    {'map_name': 'fwd_group_pg_maps', 'oc_map': 'forwarding-group-priority-group-map', 'attr1': 'fwd_group', 'attr2': 'pg_index',
     'oc_attr1': 'fwd-group', 'oc_attr2': 'priority-group-index'},
    {'map_name': 'pfc_priority_queue_maps', 'oc_map': 'pfc-priority-queue-map', 'attr1': 'dot1p', 'attr2': 'queue_index', 'oc_attr1': 'dot1p',
     'oc_attr2': 'output-queue-index'},
    {'map_name': 'pfc_priority_pg_maps', 'oc_map': 'pfc-priority-priority-group-map', 'attr1': 'dot1p', 'attr2': 'pg_index', 'oc_attr1': 'dot1p',
     'oc_attr2': 'priority-group-index'}
]


class Qos_maps(ConfigBase):
    """
    The sonic_qos_maps class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'qos_maps',
    ]

    def __init__(self, module):
        super(Qos_maps, self).__init__(module)

    def get_qos_maps_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        qos_maps_facts = facts['ansible_network_resources'].get('qos_maps')
        if not qos_maps_facts:
            return {}
        return qos_maps_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = []
        commands = []

        existing_qos_maps_facts = self.get_qos_maps_facts()
        commands, requests = self.set_config(existing_qos_maps_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_qos_maps_facts = self.get_qos_maps_facts()

        result['before'] = existing_qos_maps_facts
        if result['changed']:
            result['after'] = changed_qos_maps_facts

        new_config = changed_qos_maps_facts
        old_config = existing_qos_maps_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_qos_maps_facts,
                                        TEST_KEYS_formatted_diff)
            result['after(generated)'] = new_config
        if self._module._diff:
            self.sort_lists_in_config(new_config)
            self.sort_lists_in_config(old_config)
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)

        result['warnings'] = warnings
        return result

    def set_config(self, existing_qos_maps_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = remove_empties(self._module.params['config'])
        have = existing_qos_maps_facts
        resp = self.set_state(want, have)
        return to_list(resp)

    def set_state(self, want, have):
        """ Select the appropriate function based on the state provided

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []
        state = self._module.params['state']
        diff = get_diff(want, have)

        if state == 'overridden':
            commands, requests = self._state_overridden(want, have)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have, diff)
        return commands, requests

    def _state_replaced(self, want, have, diff):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []
        mod_commands = []

        self.sort_lists_in_config(want)
        self.sort_lists_in_config(have)
        replaced_config = self.get_replaced_config(want, have)

        if replaced_config:
            is_delete_all = replaced_config == have
            del_requests = self.get_delete_qos_maps_requests(replaced_config, have, is_delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(replaced_config, 'deleted'))
            mod_commands = want
        else:
            mod_commands = diff

        if mod_commands:
            mod_request = self.get_modify_qos_maps_request(mod_commands)

            if mod_request:
                requests.append(mod_request)
                commands.extend(update_states(mod_commands, 'replaced'))
        return commands, requests

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []
        self.sort_lists_in_config(want)
        self.sort_lists_in_config(have)

        if have and have != want:
            is_delete_all = True
            del_requests = self.get_delete_qos_maps_requests(have, None, is_delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(have, 'deleted'))
            have = []

        if not have and want:
            mod_commands = want
            mod_request = self.get_modify_qos_maps_request(mod_commands)

            if mod_request:
                requests.append(mod_request)
                commands.extend(update_states(mod_commands, 'overridden'))

        return commands, requests

    def _state_merged(self, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        requests = self.get_modify_qos_maps_request(commands)
        if commands and len(requests) > 0:
            commands = update_states(commands, 'merged')
        else:
            commands = []
        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        is_delete_all = False

        if not want:
            commands = deepcopy(have)
            is_delete_all = True
        else:
            commands = deepcopy(want)

        requests = self.get_delete_qos_maps_requests(commands, have, is_delete_all)

        if commands and len(requests) > 0:
            commands = update_states(commands, 'deleted')
        else:
            commands = []
        return commands, requests

    def get_modify_qos_maps_request(self, commands):
        request = None

        if commands:
            qos_dict = {}

            for lookup_dict in lookup_list:
                map_name = lookup_dict.get('map_name')
                maps = commands.get(map_name)
                if maps:
                    self.update_qos_dict(maps, lookup_dict, qos_dict)

            if qos_dict:
                payload = {'openconfig-qos:qos': qos_dict}
                request = {'path': QOS_PATH, 'method': PATCH, 'data': payload}

        return request

    def get_delete_qos_maps_requests(self, commands, have, is_delete_all):
        requests = []

        if not commands:
            return requests

        if is_delete_all:
            url = '%s/openconfig-qos-maps-ext:dscp-maps' % (QOS_PATH)
            requests.append({'path': url, 'method': DELETE})
            url = '%s/openconfig-qos-maps-ext:dot1p-maps' % (QOS_PATH)
            requests.append({'path': url, 'method': DELETE})
            url = '%s/openconfig-qos-maps-ext:forwarding-group-queue-maps' % (QOS_PATH)
            requests.append({'path': url, 'method': DELETE})
            url = '%s/openconfig-qos-maps-ext:forwarding-group-dscp-maps' % (QOS_PATH)
            requests.append({'path': url, 'method': DELETE})
            url = '%s/openconfig-qos-maps-ext:forwarding-group-dot1p-maps' % (QOS_PATH)
            requests.append({'path': url, 'method': DELETE})
            url = '%s/openconfig-qos-maps-ext:forwarding-group-priority-group-maps' % (QOS_PATH)
            requests.append({'path': url, 'method': DELETE})
            url = '%s/openconfig-qos-maps-ext:pfc-priority-queue-maps' % (QOS_PATH)
            requests.append({'path': url, 'method': DELETE})
            url = '%s/openconfig-qos-maps-ext:pfc-priority-priority-group-maps' % (QOS_PATH)
            requests.append({'path': url, 'method': DELETE})

            return requests

        for lookup_dict in lookup_list:
            self.update_qos_map_deletion(commands, have, lookup_dict, requests)

        return requests

    def update_qos_dict(self, maps, lookup_dict, qos_dict):
        map_list = []
        for m in maps:
            map_dict = {}
            name = m.get('name')
            entries = m.get('entries')
            oc_map = lookup_dict['oc_map']

            if name:
                map_dict.update({'name': name, 'config': {'name': name}})
            if entries:
                entry_list = []
                for entry in entries:
                    entry_dict = {}
                    attr1_key = lookup_dict['attr1']
                    attr2_key = lookup_dict['attr2']
                    attr1 = entry.get(attr1_key)
                    attr2 = entry.get(attr2_key)
                    if attr1 is not None:
                        oc_attr1 = lookup_dict['oc_attr1']
                        entry_dict[oc_attr1] = attr1
                        entry_dict['config'] = {oc_attr1: attr1}
                        if attr2 is not None:
                            oc_attr2 = lookup_dict['oc_attr2']
                            entry_dict['config'].update({oc_attr2: attr2})
                    if entry_dict:
                        entry_list.append(entry_dict)
                if entry_list:
                    map_dict.update({oc_map + '-entries': {oc_map + '-entry': entry_list}})
            if map_dict:
                map_list.append(map_dict)
        if map_list:
            all_maps_dict = {'openconfig-qos-maps-ext:' + oc_map + 's': {oc_map: map_list}}
            if all_maps_dict:
                qos_dict.update(all_maps_dict)

    def update_qos_map_deletion(self, commands, have, lookup_dict, requests):
        map_name = lookup_dict['map_name']
        maps = commands.get(map_name)
        cfg_maps = have.get(map_name)
        maps_list = []

        if maps and cfg_maps:
            for m in maps:
                name = m.get('name')
                entries = m.get('entries')

                for cfg_m in cfg_maps:
                    cfg_name = cfg_m.get('name')
                    cfg_entries = cfg_m.get('entries')

                    if name and name == cfg_name:
                        map_dict = {}
                        oc_map = lookup_dict['oc_map']
                        if not entries:
                            url = '%s/openconfig-qos-maps-ext:%ss/%s=%s' % (QOS_PATH, oc_map, oc_map, name)
                            requests.append({'path': url, 'method': DELETE})
                            map_dict.update({'name': name})

                        else:
                            if entries and cfg_entries:
                                entries_list = []
                                for entry in entries:
                                    entry_dict = {}
                                    attr1_key = lookup_dict['attr1']
                                    attr2_key = lookup_dict['attr2']
                                    attr1 = entry.get(attr1_key)
                                    attr2 = entry.get(attr2_key)

                                    for cfg_entry in cfg_entries:
                                        cfg_attr1 = cfg_entry.get(attr1_key)
                                        cfg_attr2 = cfg_entry.get(attr2_key)

                                        if attr1 is not None and attr1 == cfg_attr1:
                                            oc_attr2 = lookup_dict['oc_attr2']
                                            if attr2 is not None and attr2 == cfg_attr2:
                                                url = '%s/openconfig-qos-maps-ext:%ss/%s=%s/' % (QOS_PATH, oc_map, oc_map, name)
                                                url += '%s-entries/%s-entry=%s/config/%s' % (oc_map, oc_map, attr1, oc_attr2)
                                                requests.append({'path': url, 'method': DELETE})
                                                entry_dict.update({attr1_key: attr1, attr2_key: attr2})
                                            if attr2 is None:
                                                url = '%s/openconfig-qos-maps-ext:%ss/%s=%s/' % (QOS_PATH, oc_map, oc_map, name)
                                                url += '%s-entries/%s-entry=%s' % (oc_map, oc_map, attr1)
                                                requests.append({'path': url, 'method': DELETE})
                                                entry_dict.update({attr1_key: attr1})
                                            if entry_dict:
                                                entries_list.append(entry_dict)

                                if entries_list:
                                    map_dict.update({'name': name, 'entries': entries_list})

                        if map_dict:
                            maps_list.append(map_dict)
                        break
        if maps_list:
            commands[map_name] = maps_list
        elif map_name in commands:
            commands.pop(map_name)

    def sort_lists_in_config(self, config):
        if config:
            if 'dscp_maps' in config and config['dscp_maps']:
                config['dscp_maps'].sort(key=lambda x: x['name'])
                for m in config['dscp_maps']:
                    if 'entries' in m and m['entries']:
                        m['entries'].sort(key=lambda x: x['dscp'])
            if 'dot1p_maps' in config and config['dot1p_maps']:
                config['dot1p_maps'].sort(key=lambda x: x['name'])
                for m in config['dot1p_maps']:
                    if 'entries' in m and m['entries']:
                        m['entries'].sort(key=lambda x: x['dot1p'])
            if 'fwd_group_queue_maps' in config and config['fwd_group_queue_maps']:
                config['fwd_group_queue_maps'].sort(key=lambda x: x['name'])
                for m in config['fwd_group_queue_maps']:
                    if 'entries' in m and m['entries']:
                        m['entries'].sort(key=lambda x: x['fwd_group'])
            if 'fwd_group_dscp_maps' in config and config['fwd_group_dscp_maps']:
                config['fwd_group_dscp_maps'].sort(key=lambda x: x['name'])
                for m in config['fwd_group_dscp_maps']:
                    if 'entries' in m and m['entries']:
                        m['entries'].sort(key=lambda x: x['fwd_group'])
            if 'fwd_group_dot1p_maps' in config and config['fwd_group_dot1p_maps']:
                config['fwd_group_dot1p_maps'].sort(key=lambda x: x['name'])
                for m in config['fwd_group_dot1p_maps']:
                    if 'entries' in m and m['entries']:
                        m['entries'].sort(key=lambda x: x['fwd_group'])
            if 'fwd_group_pg_maps' in config and config['fwd_group_pg_maps']:
                config['fwd_group_pg_maps'].sort(key=lambda x: x['name'])
                for m in config['fwd_group_pg_maps']:
                    if 'entries' in m and m['entries']:
                        m['entries'].sort(key=lambda x: x['fwd_group'])
            if 'pfc_priority_queue_maps' in config and config['pfc_priority_queue_maps']:
                config['pfc_priority_queue_maps'].sort(key=lambda x: x['name'])
                for m in config['pfc_priority_queue_maps']:
                    if 'entries' in m and m['entries']:
                        m['entries'].sort(key=lambda x: x['dot1p'])
            if 'pfc_priority_pg_maps' in config and config['pfc_priority_pg_maps']:
                config['pfc_priority_pg_maps'].sort(key=lambda x: x['name'])
                for m in config['pfc_priority_pg_maps']:
                    if 'entries' in m and m['entries']:
                        m['entries'].sort(key=lambda x: x['dot1p'])

    def get_replaced_config(self, want, have):
        config_dict = {}

        if want and have:
            self.update_replaced_config(want, have, 'dscp_maps', config_dict)
            self.update_replaced_config(want, have, 'dot1p_maps', config_dict)
            self.update_replaced_config(want, have, 'fwd_group_queue_maps', config_dict)
            self.update_replaced_config(want, have, 'fwd_group_dscp_maps', config_dict)
            self.update_replaced_config(want, have, 'fwd_group_dot1p_maps', config_dict)
            self.update_replaced_config(want, have, 'fwd_group_pg_maps', config_dict)
            self.update_replaced_config(want, have, 'pfc_priority_queue_maps', config_dict)
            self.update_replaced_config(want, have, 'pfc_priority_pg_maps', config_dict)

        return config_dict

    def update_replaced_config(self, want, have, map_name, config_dict):
        maps = want.get(map_name)
        cfg_maps = have.get(map_name)
        maps_list = []

        if maps and cfg_maps:
            for m in maps:
                name = m.get('name')
                entries = m.get('entries')

                for cfg_m in cfg_maps:
                    cfg_name = cfg_m.get('name')
                    cfg_entries = cfg_m.get('entries')

                    if name and name == cfg_name:
                        if entries != cfg_entries:
                            maps_list.append({'name': cfg_name})
        if maps_list:
            config_dict[map_name] = maps_list
