#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_qos_interfaces class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    remove_empties_from_list,
    update_states
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_CONFIG_IF_NO_SUBCONFIG,
    __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF,
    get_new_config,
    get_formatted_config_diff
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)

QOS_INTF_PATH = '/data/openconfig-qos:qos/interfaces'
QOS_QUEUE_PATH = '/data/openconfig-qos:qos/queues'
PATCH = 'patch'
DELETE = 'delete'
TEST_KEYS = [
    {'config': {'name': ''}},
    {'queues': {'id': ''}},
    {'priorities': {'dot1p': ''}}
]


def __derive_pfc_delete_op(key_set, command, exist_conf):
    new_conf = exist_conf
    asymmetric = command.get('asymmetric')
    priorities = command.get('priorities')
    watchdog_action = command.get('watchdog_action')
    watchdog_detect_time = command.get('watchdog_detect_time')
    watchdog_restore_time = command.get('watchdog_restore_time')
    cfg_asymmetric = new_conf.get('asymmetric')
    cfg_priorities = new_conf.get('priorities')
    cfg_watchdog_action = new_conf.get('watchdog_action')
    cfg_watchdog_detect_time = new_conf.get('watchdog_detect_time')
    cfg_watchdog_restore_time = new_conf.get('watchdog_restore_time')

    if asymmetric and asymmetric == cfg_asymmetric:
        new_conf['asymmetric'] = False
    if watchdog_action and cfg_watchdog_action != 'drop':
        new_conf['watchdog_action'] = 'drop'
    if watchdog_detect_time and watchdog_detect_time == cfg_watchdog_detect_time:
        new_conf.pop('watchdog_detect_time')
    if watchdog_restore_time and watchdog_restore_time == cfg_watchdog_restore_time:
        new_conf.pop('watchdog_restore_time')
    if priorities and cfg_priorities:
        cfg_priority_dict = {cfg_priority.get('dot1p'): cfg_priority for cfg_priority in cfg_priorities}
        for priority in priorities:
            dot1p = priority.get('dot1p')
            enable = priority.get('enable')
            cfg_priority = cfg_priority_dict.get(dot1p)
            if cfg_priority is None:
                continue
            cfg_enable = cfg_priority.get('enable')
            if enable and enable == cfg_enable:
                cfg_priority['enable'] = False
    return True, new_conf


TEST_KEYS_formatted_diff = [
    {'config': {'name': '', '__delete_op': __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'queues': {'id': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'pfc': {'__delete_op': __derive_pfc_delete_op}}
]


class Qos_interfaces(ConfigBase):
    """
    The sonic_qos_interfaces class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'qos_interfaces',
    ]

    def __init__(self, module):
        super(Qos_interfaces, self).__init__(module)

    def get_qos_interfaces_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        qos_interfaces_facts = facts['ansible_network_resources'].get('qos_interfaces')
        if not qos_interfaces_facts:
            return []
        return qos_interfaces_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = []
        commands = []

        existing_qos_interfaces_facts = self.get_qos_interfaces_facts()
        commands, requests = self.set_config(existing_qos_interfaces_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_qos_interfaces_facts = self.get_qos_interfaces_facts()

        result['before'] = existing_qos_interfaces_facts
        if result['changed']:
            result['after'] = changed_qos_interfaces_facts

        new_config = changed_qos_interfaces_facts
        old_config = existing_qos_interfaces_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_qos_interfaces_facts,
                                        TEST_KEYS_formatted_diff)
            self.post_process_generated_config(new_config)
            result['after(generated)'] = new_config
        if self._module._diff:
            self.sort_lists_in_config(new_config)
            self.sort_lists_in_config(old_config)
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)

        result['warnings'] = warnings
        return result

    def set_config(self, existing_qos_interfaces_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = remove_empties_from_list(self._module.params['config'])
        have = existing_qos_interfaces_facts
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
        diff = get_diff(want, have, TEST_KEYS)

        if state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(diff)
        return commands, requests

    def _state_merged(self, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        requests = self.get_modify_qos_interfaces_requests(commands)

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

        self.remove_default_entries(commands)
        requests = self.get_delete_qos_interfaces_requests(commands, have, is_delete_all)

        if commands and len(requests) > 0:
            commands = update_states(commands, 'deleted')
        else:
            commands = []
        return commands, requests

    def get_modify_qos_interfaces_requests(self, commands):
        requests = []

        if commands:
            intf_list = []
            queue_list = []
            for intf in commands:
                intf_dict = {}
                name = intf.get('name')
                scheduler_policy = intf.get('scheduler_policy')
                cable_length = intf.get('cable_length')
                qos_maps = intf.get('qos_maps')
                pfc = intf.get('pfc')
                queues = intf.get('queues')

                if name:
                    intf_dict.update({'interface-id': name, 'config': {'interface-id': name}})
                if scheduler_policy:
                    intf_dict['output'] = {'scheduler-policy': {'config': {'name': scheduler_policy}}}
                if cable_length:
                    intf_dict['openconfig-qos-buffer:cable-length'] = {'config': {'length': cable_length}}
                if qos_maps:
                    map_dict = {}
                    dscp_fwd_group = qos_maps.get('dscp_fwd_group')
                    dot1p_fwd_group = qos_maps.get('dot1p_fwd_group')
                    fwd_group_dscp = qos_maps.get('fwd_group_dscp')
                    fwd_group_dot1p = qos_maps.get('fwd_group_dot1p')
                    fwd_group_queue = qos_maps.get('fwd_group_queue')
                    fwd_group_pg = qos_maps.get('fwd_group_pg')
                    pfc_priority_queue = qos_maps.get('pfc_priority_queue')
                    pfc_priority_pg = qos_maps.get('pfc_priority_pg')

                    if dscp_fwd_group:
                        map_dict['dscp-to-forwarding-group'] = dscp_fwd_group
                    if dot1p_fwd_group:
                        map_dict['dot1p-to-forwarding-group'] = dot1p_fwd_group
                    if fwd_group_dscp:
                        map_dict['forwarding-group-to-dscp'] = fwd_group_dscp
                    if fwd_group_dot1p:
                        map_dict['forwarding-group-to-dot1p'] = fwd_group_dot1p
                    if fwd_group_queue:
                        map_dict['forwarding-group-to-queue'] = fwd_group_queue
                    if fwd_group_pg:
                        map_dict['forwarding-group-to-priority-group'] = fwd_group_pg
                    if pfc_priority_queue:
                        map_dict['pfc-priority-to-queue'] = pfc_priority_queue
                    if pfc_priority_pg:
                        map_dict['pfc-priority-to-priority-group'] = pfc_priority_pg
                    if map_dict:
                        intf_dict['openconfig-qos-maps-ext:interface-maps'] = {'config': map_dict}
                if pfc:
                    pfc_dict = {}
                    watchdog_dict = {}
                    asymmetric = pfc.get('asymmetric')
                    watchdog_action = pfc.get('watchdog_action')
                    watchdog_detect_time = pfc.get('watchdog_detect_time')
                    watchdog_restore_time = pfc.get('watchdog_restore_time')
                    priorities = pfc.get('priorities')

                    if asymmetric is not None:
                        pfc_dict['config'] = {'asymmetric': asymmetric}
                    if watchdog_action:
                        watchdog_dict['action'] = watchdog_action.upper()
                    if watchdog_detect_time:
                        watchdog_dict['detection-time'] = watchdog_detect_time
                    if watchdog_restore_time:
                        watchdog_dict['restoration-time'] = watchdog_restore_time
                    if watchdog_dict:
                        pfc_dict['watchdog'] = {'config': watchdog_dict}
                    if priorities:
                        priority_list = []
                        for priority in priorities:
                            priority_dict = {}
                            dot1p = priority.get('dot1p')
                            enable = priority.get('enable')

                            if dot1p is not None:
                                priority_dict['dot1p'] = dot1p
                                priority_dict['config'] = {'dot1p': dot1p}
                            if enable is not None:
                                priority_dict['config']['enable'] = enable
                            if priority_dict:
                                priority_list.append(priority_dict)
                        if priority_list:
                            pfc_dict['pfc-priorities'] = {'pfc-priority': priority_list}
                    if pfc_dict:
                        intf_dict['pfc'] = pfc_dict
                if intf_dict:
                    intf_list.append(intf_dict)
                if queues:
                    queue_list = []
                    for queue in queues:
                        queue_dict = {}
                        queue_id = queue.get('id')
                        wred_profile = queue.get('wred_profile')

                        if queue_id is not None:
                            queue_name = name + ':' + str(queue_id)
                            queue_dict.update({'name': queue_name, 'config': {'name': queue_name}})
                        if wred_profile:
                            queue_dict['wred'] = {'config': {'wred-profile': wred_profile}}
                        if queue_dict:
                            queue_list.append(queue_dict)
                    if queue_list:
                        payload = {'openconfig-qos:queues': {'queue': queue_list}}
                        requests.append({'path': QOS_QUEUE_PATH, 'method': PATCH, 'data': payload})
            if intf_list:
                payload = {'openconfig-qos:interfaces': {'interface': intf_list}}
                requests.append({'path': QOS_INTF_PATH, 'method': PATCH, 'data': payload})

        return requests

    def get_delete_qos_interfaces_requests(self, commands, have, is_delete_all):
        requests = []

        if not commands:
            return requests

        if is_delete_all:
            requests.append({'path': QOS_INTF_PATH, 'method': DELETE})
            requests.append({'path': QOS_QUEUE_PATH, 'method': DELETE})
            return requests

        config_list = []
        cfg_intf_dict = {cfg_intf.get('name'): cfg_intf for cfg_intf in have}
        for intf in commands:
            name = intf.get('name')
            scheduler_policy = intf.get('scheduler_policy')
            cable_length = intf.get('cable_length')
            qos_maps = intf.get('qos_maps')
            pfc = intf.get('pfc')
            queues = intf.get('queues')

            cfg_intf = cfg_intf_dict.get(name)
            if cfg_intf is None:
                continue
            config_dict = {}
            cfg_scheduler_policy = cfg_intf.get('scheduler_policy')
            cfg_cable_length = cfg_intf.get('cable_length')
            cfg_qos_maps = cfg_intf.get('qos_maps')
            cfg_pfc = cfg_intf.get('pfc')
            cfg_queues = cfg_intf.get('queues')

            if scheduler_policy and scheduler_policy == cfg_scheduler_policy:
                url = '%s/interface=%s/output/scheduler-policy' % (QOS_INTF_PATH, name)
                requests.append({'path': url, 'method': DELETE})
                config_dict.update({'name': name, 'scheduler_policy': scheduler_policy})

            if cable_length and cable_length == cfg_cable_length:
                url = '%s/interface=%s/openconfig-qos-buffer:cable-length' % (QOS_INTF_PATH, name)
                requests.append({'path': url, 'method': DELETE})
                config_dict.update({'name': name, 'cable_length': cable_length})

            if qos_maps and cfg_qos_maps:
                maps_dict = {}
                dscp_fwd_group = qos_maps.get('dscp_fwd_group')
                dot1p_fwd_group = qos_maps.get('dot1p_fwd_group')
                fwd_group_dscp = qos_maps.get('fwd_group_dscp')
                fwd_group_dot1p = qos_maps.get('fwd_group_dot1p')
                fwd_group_queue = qos_maps.get('fwd_group_queue')
                fwd_group_pg = qos_maps.get('fwd_group_pg')
                pfc_priority_queue = qos_maps.get('pfc_priority_queue')
                pfc_priority_pg = qos_maps.get('pfc_priority_pg')

                cfg_dscp_fwd_group = cfg_qos_maps.get('dscp_fwd_group')
                cfg_dot1p_fwd_group = cfg_qos_maps.get('dot1p_fwd_group')
                cfg_fwd_group_dscp = cfg_qos_maps.get('fwd_group_dscp')
                cfg_fwd_group_dot1p = cfg_qos_maps.get('fwd_group_dot1p')
                cfg_fwd_group_queue = cfg_qos_maps.get('fwd_group_queue')
                cfg_fwd_group_pg = cfg_qos_maps.get('fwd_group_pg')
                cfg_pfc_priority_queue = cfg_qos_maps.get('pfc_priority_queue')
                cfg_pfc_priority_pg = cfg_qos_maps.get('pfc_priority_pg')

                if dscp_fwd_group and dscp_fwd_group == cfg_dscp_fwd_group:
                    requests.append(self.get_delete_map_request(name, 'dscp-to-forwarding-group'))
                    maps_dict['dscp_fwd_group'] = dscp_fwd_group
                if dot1p_fwd_group and dot1p_fwd_group == cfg_dot1p_fwd_group:
                    requests.append(self.get_delete_map_request(name, 'dot1p-to-forwarding-group'))
                    maps_dict['dot1p_fwd_group'] = dot1p_fwd_group
                if fwd_group_dscp and fwd_group_dscp == cfg_fwd_group_dscp:
                    requests.append(self.get_delete_map_request(name, 'forwarding-group-to-dscp'))
                    maps_dict['fwd_group_dscp'] = fwd_group_dscp
                if fwd_group_dot1p and fwd_group_dot1p == cfg_fwd_group_dot1p:
                    requests.append(self.get_delete_map_request(name, 'forwarding-group-to-dot1p'))
                    maps_dict['fwd_group_dot1p'] = fwd_group_dot1p
                if fwd_group_queue and fwd_group_queue == cfg_fwd_group_queue:
                    requests.append(self.get_delete_map_request(name, 'forwarding-group-to-queue'))
                    maps_dict['fwd_group_queue'] = fwd_group_queue
                if fwd_group_pg and fwd_group_pg == cfg_fwd_group_pg:
                    requests.append(self.get_delete_map_request(name, 'forwarding-group-to-priority-group'))
                    maps_dict['fwd_group_pg'] = fwd_group_pg
                if pfc_priority_queue and pfc_priority_queue == cfg_pfc_priority_queue:
                    requests.append(self.get_delete_map_request(name, 'pfc-priority-to-queue'))
                    maps_dict['pfc_priority_queue'] = pfc_priority_queue
                if pfc_priority_pg and pfc_priority_pg == cfg_pfc_priority_pg:
                    requests.append(self.get_delete_map_request(name, 'pfc-priority-to-priority-group'))
                    maps_dict['pfc_priority_pg'] = pfc_priority_pg
                if maps_dict:
                    config_dict.update({'name': name, 'qos_maps': maps_dict})

            if pfc and cfg_pfc:
                pfc_dict = {}
                asymmetric = pfc.get('asymmetric')
                watchdog_action = pfc.get('watchdog_action')
                watchdog_detect_time = pfc.get('watchdog_detect_time')
                watchdog_restore_time = pfc.get('watchdog_restore_time')
                priorities = pfc.get('priorities')

                cfg_asymmetric = cfg_pfc.get('asymmetric')
                cfg_watchdog_action = cfg_pfc.get('watchdog_action')
                cfg_watchdog_detect_time = cfg_pfc.get('watchdog_detect_time')
                cfg_watchdog_restore_time = cfg_pfc.get('watchdog_restore_time')
                cfg_priorities = cfg_pfc.get('priorities')

                # default false
                if asymmetric and asymmetric == cfg_asymmetric:
                    url = '%s/interface=%s/pfc/config/asymmetric' % (QOS_INTF_PATH, name)
                    requests.append({'path': url, 'method': DELETE})
                    pfc_dict['asymmetric'] = asymmetric
                if watchdog_action and watchdog_action == cfg_watchdog_action:
                    requests.append(self.get_delete_watchdog_request(name, 'action'))
                    pfc_dict['watchdog_action'] = watchdog_action
                if watchdog_detect_time and watchdog_detect_time == cfg_watchdog_detect_time:
                    requests.append(self.get_delete_watchdog_request(name, 'detection-time'))
                    pfc_dict['watchdog_detect_time'] = watchdog_detect_time
                if watchdog_restore_time and watchdog_restore_time == cfg_watchdog_restore_time:
                    requests.append(self.get_delete_watchdog_request(name, 'restoration-time'))
                    pfc_dict['watchdog_restore_time'] = watchdog_restore_time
                if priorities and cfg_priorities:
                    priorities_list = []
                    cfg_priority_dict = {cfg_priority.get('dot1p'): cfg_priority for cfg_priority in cfg_priorities}
                    for priority in priorities:
                        dot1p = priority.get('dot1p')
                        enable = priority.get('enable')

                        cfg_priority = cfg_priority_dict.get(dot1p)
                        if cfg_priority is None:
                            continue
                        cfg_enable = cfg_priority.get('enable')

                        # default false
                        if enable and enable == cfg_enable:
                            url = '%s/interface=%s/pfc/pfc-priorities/pfc-priority=%s/config/enable' % (QOS_INTF_PATH, name, dot1p)
                            requests.append({'path': url, 'method': DELETE})
                            priorities_dict = {'dot1p': dot1p, 'enable': enable}
                            priorities_list.append(priorities_dict)
                        elif enable is None:
                            self._module.fail_json(msg='Deletion of PFC priority not supported')
                    if priorities_list:
                        pfc_dict['priorities'] = priorities_list
                if pfc_dict:
                    config_dict.update({'name': name, 'pfc': pfc_dict})

            if queues and cfg_queues:
                queues_list = []
                cfg_queue_dict = {cfg_queue.get('id'): cfg_queue for cfg_queue in cfg_queues}
                for queue in queues:
                    queue_id = queue.get('id')
                    wred_profile = queue.get('wred_profile')

                    cfg_queue = cfg_queue_dict.get(queue_id)
                    if cfg_queue is None:
                        continue
                    queues_dict = {}
                    cfg_wred_profile = cfg_queue.get('wred_profile')
                    queue_name = name + ':' + str(queue_id)
                    if wred_profile and wred_profile == cfg_wred_profile:
                        url = '%s/queue=%s/wred/config/wred-profile' % (QOS_QUEUE_PATH, queue_name)
                        requests.append({'path': url, 'method': DELETE})
                        queues_dict.update({'id': queue_id, 'wred_profile': wred_profile})
                    elif not wred_profile:
                        url = '%s/queue=%s' % (QOS_QUEUE_PATH, queue_name)
                        requests.append({'path': url, 'method': DELETE})
                        queues_dict['id'] = queue_id
                    if queues_dict:
                        queues_list.append(queues_dict)
                if queues_list:
                    config_dict.update({'name': name, 'queues': queues_list})
            if config_dict:
                config_list.append(config_dict)
            if not scheduler_policy and not qos_maps and not pfc and not queues and not cable_length:
                self._module.fail_json(msg='Deletion of a QoS interface not supported')
        commands = config_list

        return requests

    def get_delete_map_request(self, name, map_name):
        url = '%s/interface=%s/openconfig-qos-maps-ext:interface-maps/config/%s' % (QOS_INTF_PATH, name, map_name)
        request = {'path': url, 'method': DELETE}

        return request

    def get_delete_watchdog_request(self, name, attr):
        url = '%s/interface=%s/pfc/watchdog/config/%s' % (QOS_INTF_PATH, name, attr)
        request = {'path': url, 'method': DELETE}

        return request

    def remove_default_entries(self, data):
        if data:
            intf_pop_list = []
            for intf in data:
                pfc = intf.get('pfc')
                if pfc:
                    asymmetric = pfc.get('asymmetric')
                    watchdog_action = pfc.get('watchdog_action')
                    priorities = pfc.get('priorities')

                    if asymmetric is False:
                        pfc.pop('asymmetric')
                    if watchdog_action == 'drop':
                        pfc.pop('watchdog_action')
                    if priorities:
                        priority_pop_list = []
                        for priority in priorities:
                            enable = priority.get('enable')

                            if enable is False:
                                priority_idx = priorities.index(priority)
                                priority_pop_list.insert(0, priority_idx)

                        for priority_idx in priority_pop_list:
                            priorities.pop(priority_idx)

                        if not priorities:
                            pfc.pop('priorities')
                    if not pfc:
                        intf.pop('pfc')

                cable_length = intf.get('cable_length')
                if cable_length == '40m':
                    intf.pop('cable_length')

                if 'name' in intf and (len(intf) == 1 or intf['name'] == 'CPU'):
                    intf_idx = data.index(intf)
                    intf_pop_list.insert(0, intf_idx)

            for intf_idx in intf_pop_list:
                data.pop(intf_idx)

    def sort_lists_in_config(self, config):
        if config:
            config.sort(key=lambda x: x['name'])
            for intf in config:
                if 'queues' in intf and intf['queues']:
                    intf['queues'].sort(key=lambda x: x['id'])
                if 'pfc' in intf and intf['pfc'] and 'priorities' in intf['pfc'] and intf['pfc']['priorities']:
                    intf['pfc']['priorities'].sort(key=lambda x: x['dot1p'])

    def post_process_generated_config(self, configs):
        for conf in configs:
            if 'queues' in conf and not conf['queues']:
                conf.pop('queues')
