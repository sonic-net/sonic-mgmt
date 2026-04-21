#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The sonic_ospfv3 class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    update_states,
    get_diff,
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    get_new_config,
    get_formatted_config_diff,
    __DELETE_CONFIG,
    __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF
)
from ansible.module_utils.connection import ConnectionError

PATCH = 'patch'
DELETE = 'delete'
DIRECTION = 'IMPORT'

OSPF_PATH = ('/data/openconfig-network-instance:network-instances/network-instance={vrf_name}'
             '/protocols/protocol=OSPF3,ospfv3/ospfv3')

TEST_KEYS = [
    {'config': {'vrf_name': ''}},
    {'helper': {'advertise_router_id': ''}},
    {'redistribute': {'protocol': ''}}
]

TEST_KEYS_overridden_diff = [
    {'config': {'vrf_name': '', '__delete_op': __DELETE_CONFIG}},
    {'helper': {'advertise_router_id': '', '__delete_op': __DELETE_CONFIG}},
    {'redistribute': {'protocol': '', '__delete_op': __DELETE_CONFIG}},
    {'graceful_restart': {'helper': '', '__delete_op': __DELETE_CONFIG}}
]

TEST_KEYS_diff = [
    {'config': {'vrf_name': '', '__delete_op': __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'helper': {'advertise_router_id': '', '__delete_op': __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'redistribute': {'protocol': '', '__delete_op': __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'graceful_restart': {'helper': '', '__delete_op': __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF}}
]


PROTOCOL_MAP = {
    'bgp': 'BGP',
    'kernel': 'KERNEL',
    'connected': 'DIRECTLY_CONNECTED',
    'static': 'STATIC',
    'default_route': 'DEFAULT_ROUTE'
}

REDISTRIBUTE_DELETE_PATH = '/global/openconfig-ospfv3-ext:route-distribution-policies/distribute-list={},{}'
OSPF_HELPER_PATH = '/global/graceful-restart/openconfig-ospfv3-ext:helpers/helper'
OSPF_ATTRIBUTES = {
    'auto_cost_reference_bandwidth': '/global/config/openconfig-ospfv3-ext:auto-cost-reference-bandwidth',
    'distance': {
        'all': '/global/openconfig-ospfv3-ext:distance/config/all',
        'external': '/global/openconfig-ospfv3-ext:distance/config/external',
        'inter_area': '/global/openconfig-ospfv3-ext:distance/config/inter-area',
        'intra_area': '/global/openconfig-ospfv3-ext:distance/config/intra-area'
    },
    'graceful_restart': {
        'grace_period': '/global/graceful-restart/config/openconfig-ospfv3-ext:grace-period',
        'enable': '/global/graceful-restart/config/enabled',
        'helper': {
            'enable': '/global/graceful-restart/config/helper-only',
            'planned_only': '/global/graceful-restart/config/openconfig-ospfv3-ext:planned-only',
            'strict_lsa_checking': '/global/graceful-restart/config/openconfig-ospfv3-ext:strict-lsa-checking',
            'supported_grace_time': '/global/graceful-restart/config/openconfig-ospfv3-ext:supported-grace-time',
            'advertise_router_id': '/global/graceful-restart/openconfig-ospfv3-ext:helpers/helper={}'
        }
    },
    'log_adjacency_changes': '/global/config/openconfig-ospfv3-ext:log-adjacency-state-changes',
    'maximum_paths': '/global/config/openconfig-ospfv3-ext:maximum-paths',
    'redistribute': {
        'always': '/global/openconfig-ospfv3-ext:route-distribution-policies/distribute-list={},{}/config/always',
        'protocol': '/global/openconfig-ospfv3-ext:route-distribution-policies/distribute-list={},{}',
        'metric': '/global/openconfig-ospfv3-ext:route-distribution-policies/distribute-list={},{}/config/metric',
        'metric_type': '/global/openconfig-ospfv3-ext:route-distribution-policies/distribute-list={},{}/config/metric-type',
        'route_map': '/global/openconfig-ospfv3-ext:route-distribution-policies/distribute-list={},{}/config/route-map'
    },
    'router_id': '/global/config/router-id',
    'timers': {
        'lsa_min_arrival': '/global/openconfig-ospfv3-ext:timers/lsa-generation/config/minimum-arrival',
        'throttle_spf': {
            'initial_hold_time': '/global/openconfig-ospfv3-ext:timers/spf/config/initial-delay',
            'maximum_hold_time': '/global/openconfig-ospfv3-ext:timers/spf/config/maximum-delay',
            'delay_time': '/global/openconfig-ospfv3-ext:timers/spf/config/throttle-delay'
        }
    },
    'write_multiplier': '/global/config/openconfig-ospfv3-ext:write-multiplier',
}


class Ospfv3(ConfigBase):
    """
    The sonic_ospfv3 class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'ospfv3',
    ]

    def __init__(self, module):
        super(Ospfv3, self).__init__(module)

    def get_ospfv3_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        ospfv3_facts = facts['ansible_network_resources'].get('ospfv3')
        if not ospfv3_facts:
            return []
        return ospfv3_facts

    def execute_module(self):
        """ Execute the module
        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        existing_ospfv3_facts = self.get_ospfv3_facts()
        commands, requests = self.set_config(existing_ospfv3_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_ospfv3_facts = self.get_ospfv3_facts()

        result['before'] = existing_ospfv3_facts
        if result['changed']:
            result['after'] = changed_ospfv3_facts

        new_config = changed_ospfv3_facts
        old_config = existing_ospfv3_facts
        if self._module.check_mode:
            result.pop('after', None)
            existing_ospfv3_facts = remove_empties_from_list(existing_ospfv3_facts)
            is_overridden = False
            for cmd in commands:
                if cmd['state'] == 'overridden':
                    is_overridden = True
                    break
            if is_overridden:
                new_config = get_new_config(commands, existing_ospfv3_facts, TEST_KEYS_overridden_diff)
            else:
                new_config = get_new_config(commands, existing_ospfv3_facts, TEST_KEYS_diff)
            new_config = remove_empties_from_list(new_config)
            result['after(generated)'] = new_config
            self.sort_lists_in_config(new_config)

        if self._module._diff:
            result['diff'] = get_formatted_config_diff(old_config, new_config, self._module._verbosity)

        result['warnings'] = warnings
        return result

    def set_config(self, existing_ospfv3_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_ospfv3_facts
        want = remove_empties_from_list(want)
        new_want, new_have = self.validate_and_normalize_config(want, have)
        self.sort_lists_in_config(new_want)
        self.sort_lists_in_config(new_have)
        resp = self.set_state(new_want, new_have)
        return to_list(resp)

    def validate_and_normalize_config(self, want, have):
        """ Validate the configuration"""
        new_want = deepcopy(want)
        new_have = deepcopy(have)

        if new_want:
            for cmd in new_want:
                have_cmd = next((cfg for cfg in new_have if cfg['vrf_name'] == cmd['vrf_name']), None)
                state = self._module.params['state']

                graceful_restart = cmd.get('graceful_restart')
                if state != 'deleted':
                    if graceful_restart:
                        if graceful_restart.get('enable') is None:
                            cmd['graceful_restart']['enable'] = True
                        if graceful_restart.get('helper') is not None:
                            if graceful_restart['helper'].get('enable') is None:
                                cmd['graceful_restart']['helper']['enable'] = True
                else:
                    if have_cmd:
                        have_graceful_restart = have_cmd.get('graceful_restart')
                        if graceful_restart:
                            if "enable" in graceful_restart and 'grace_period' not in graceful_restart:
                                if have_graceful_restart and 'grace_period' in have_graceful_restart:
                                    cmd['graceful_restart']['grace_period'] = have_graceful_restart['grace_period']

        return new_want, new_have

    def set_state(self, want, have):
        """ Select the appropriate function based on the state provided
        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, requests = [], []
        state = self._module.params['state']
        if state == 'overridden':
            commands, requests = self._state_overridden(want, have)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have)
        return commands, requests

    def _state_replaced(self, want, have):
        """ The command generator when state is replaced
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, requests = [], []
        add_config, del_config = self._get_replaced_config(want, have)
        if del_config:
            del_commands, del_requests = self.get_delete_ospfv3_commands_requests(del_config, have, True)
            if len(del_requests) > 0:
                requests.extend(del_requests)
                commands.extend(update_states(del_commands, 'deleted'))
        if add_config:
            mod_requests = self.get_create_ospfv3_requests(add_config)
            if len(mod_requests) > 0:
                requests.extend(mod_requests)
                commands.extend(update_states(add_config, 'replaced'))
        return commands, requests

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, requests = [], []
        diff = get_diff(want, have, TEST_KEYS)
        diff2 = get_diff(have, want, TEST_KEYS)
        if diff or diff2:
            del_commands, del_requests = self.get_delete_ospfv3_commands_requests(have, have, True)
            if len(del_requests) > 0:
                requests.extend(del_requests)
                commands.extend(update_states(have, 'deleted'))
            mod_requests = self.get_create_ospfv3_requests(want)
            if len(mod_requests) > 0:
                requests.extend(mod_requests)
                commands.extend(update_states(want, 'overridden'))
        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged
        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = get_diff(want, have, TEST_KEYS)
        requests = self.get_create_ospfv3_requests(commands)

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
        commands, requests = [], []
        is_delete_all = False

        if not want:
            new_want = have
            is_delete_all = True
        else:
            self.sort_lists_in_config(want)
            self.sort_lists_in_config(have)
            new_want = deepcopy(want)
            new_have = deepcopy(have)
            new_have = remove_empties_from_list(new_have)
            new_want = remove_empties_from_list(new_want)
        commands, requests = self.get_delete_ospfv3_commands_requests(new_want, have, is_delete_all)

        if commands and len(requests) > 0:
            commands = update_states(commands, 'deleted')
        else:
            commands = []
        return commands, requests

    def _get_replaced_config(self, want, have):
        add_config, del_config = [], []
        for conf in want:
            is_change = False
            vrf_name = conf.get('vrf_name')
            have_conf = next((cfg for cfg in have if cfg['vrf_name'] == vrf_name), None)
            if not have_conf:
                add_config.append(conf)
            else:
                for attr in OSPF_ATTRIBUTES:
                    if attr in have_conf:
                        if attr not in conf:
                            is_change = True
                            break
                        else:
                            if attr == 'redistribute':
                                for redis_list in conf.get(attr, []):
                                    protocol = redis_list.get('protocol')
                                    have_redis = next((redis for redis in have_conf.get(attr, []) if redis['protocol'] == protocol), None)
                                    if not have_redis or (have_redis and have_redis != redis_list):
                                        is_change = True
                                        break
                            elif attr != 'vrf_name':
                                if have_conf[attr] != conf[attr]:
                                    is_change = True
                                    break
                    elif attr in conf:
                        is_change = True
                        break
                if is_change:
                    add_config.append(conf)
                    del_config.append(have_conf)
        return add_config, del_config

    def get_create_ospfv3_requests(self, commands):
        requests = []

        for cmd in commands:
            vrf_name = cmd.get('vrf_name')
            sub_commands = deepcopy(cmd)
            sub_commands.pop('vrf_name')
            payload = {}
            self._get_create_payload_from_dict(sub_commands, OSPF_ATTRIBUTES, payload)
            if payload:
                requests.append({'path': OSPF_PATH.format(vrf_name=vrf_name), 'method': PATCH, 'data': {'openconfig-network-instance:ospfv3': payload}})
        return requests

    def _get_create_payload_from_dict(self, command, ospf_dict, payload):
        for attr in ospf_dict:
            if attr in command and command[attr] is not None:
                if not isinstance(ospf_dict[attr], dict):
                    path = ospf_dict[attr]
                    request_body = path.split('/')
                    last_body = request_body[-1]
                    payload_iter = payload
                    for body in request_body[1:-1]:
                        payload_iter.setdefault(body, {})
                        payload_iter = payload_iter[body]

                    if attr == 'advertise_router_id':
                        if command['advertise_router_id']:
                            payload_iter.setdefault('helper', [])
                            for ip in command['advertise_router_id']:
                                payload_iter['helper'].append({'neighbour-id': ip, 'config': {'neighbour-id': ip}})

                    elif attr == 'log_adjacency_changes':
                        payload_iter[last_body] = 'openconfig-ospfv3-ext:' + command[attr].upper()

                    else:
                        if attr == 'grace_period':
                            command['enable'] = True
                            payload_iter['enabled'] = True
                        payload_iter[last_body] = command[attr]

                elif attr == 'redistribute':
                    self._get_create_redistribute_payload(command[attr], ospf_dict[attr], payload)

                else:
                    self._get_create_payload_from_dict(command[attr], ospf_dict[attr], payload)

    def _get_create_redistribute_payload(self, command, ospf_dict, payload):
        protocol = 'DEFAULT_ROUTE'
        for redistribute_list in command:
            if 'protocol' in redistribute_list:
                payload.setdefault('global', {})
                payload['global'].setdefault('openconfig-ospfv3-ext:route-distribution-policies', {})
                payload['global']['openconfig-ospfv3-ext:route-distribution-policies'].setdefault('distribute-list', [])
                protocol = PROTOCOL_MAP[redistribute_list['protocol']]
                distribute_payload = {'protocol': protocol, 'direction': DIRECTION}
                if len(redistribute_list) == 1:
                    payload['global']['openconfig-ospfv3-ext:route-distribution-policies']['distribute-list'].append(distribute_payload)
                else:
                    for item in redistribute_list:
                        if item not in ('protocol', 'metric_type'):
                            if item == 'always' and protocol != 'DEFAULT_ROUTE':
                                continue
                            config_type = ospf_dict[item].split('/')[-1]
                            distribute_payload.setdefault('config', {})
                            distribute_payload['config'][config_type] = redistribute_list[item]
                        elif item == 'metric_type':
                            distribute_payload.setdefault('config', {})
                            metric_type = 'TYPE_1' if redistribute_list[item] == 1 else 'TYPE_2'
                            distribute_payload['config']['openconfig-ospfv3-ext:metric-type'] = metric_type
                    payload['global']['openconfig-ospfv3-ext:route-distribution-policies']['distribute-list'].append(distribute_payload)

    def get_delete_ospfv3_commands_requests(self, want, have, is_delete_all):
        commands, requests = [], []
        for cmd in want:
            del_cmd, request = {}, {}
            vrf_name = cmd.get('vrf_name')
            sub_commands = deepcopy(cmd)
            sub_commands.pop('vrf_name')
            url = OSPF_PATH.format(vrf_name=vrf_name)
            if is_delete_all:
                commands.append({'vrf_name': vrf_name})
                requests.append({'path': url + '/global', 'method': DELETE})
            elif sub_commands == {}:
                have_cmd = next((cfg for cfg in have if cfg['vrf_name'] == vrf_name), None)
                if have_cmd:
                    commands.append({'vrf_name': vrf_name})
                    requests.append({'path': url + '/global', 'method': DELETE})
            else:
                have_cmd = next((cfg for cfg in have if cfg['vrf_name'] == vrf_name), None)
                if have_cmd:
                    del_cmd, request = self._get_delete_commands_requests_path_from_dict(sub_commands, have_cmd, OSPF_ATTRIBUTES, url)
                    if del_cmd:
                        del_cmd['vrf_name'] = vrf_name
                        commands.append(del_cmd)
                        requests.extend(request)
        return commands, requests

    def _get_delete_commands_requests_path_from_dict(self, want, have, ospf_dict, ospf_path):
        commands, requests = {}, []
        for attr in ospf_dict:
            del_attr, request = {}, {}
            if attr in want and attr in have:
                if not isinstance(ospf_dict[attr], dict):
                    if attr == 'advertise_router_id':
                        adv_attr = []
                        for ip in want['advertise_router_id']:
                            if ip in have['advertise_router_id']:
                                adv_attr.append(ip)
                                url = '%s%s=%s' % (ospf_path, OSPF_HELPER_PATH, ip)
                                requests.append({'path': url, 'method': 'DELETE'})
                        if adv_attr:
                            commands['advertise_router_id'] = adv_attr
                    elif None not in [want.get(attr), have.get(attr)] and want[attr] == have[attr]:
                        commands[attr] = want[attr]
                        requests.append({'path': ospf_path + ospf_dict[attr], 'method': 'DELETE'})
                elif attr == 'redistribute':
                    del_attr, request = self._get_delete_redistribute_commands_requests(
                        want[attr], have[attr], ospf_dict[attr], ospf_path
                    )
                    if del_attr:
                        commands['redistribute'] = del_attr
                        requests.extend(request)
                else:
                    del_attr, request = self._get_delete_commands_requests_path_from_dict(
                        want[attr], have[attr], ospf_dict[attr], ospf_path
                    )
                    if del_attr:
                        commands[attr] = del_attr
                        requests.extend(request)
        return commands, requests

    def _get_delete_redistribute_commands_requests(self, want, have, ospf_dict, ospf_path):
        commands, requests = [], []
        for redistribute_list in want:
            protocol = redistribute_list['protocol']
            have_redistribute_list = next((cfg for cfg in have if cfg['protocol'] == redistribute_list['protocol']), None)
            if have_redistribute_list:
                if protocol != 'default_route':
                    url = ospf_path + ospf_dict['protocol']
                    commands.append({'protocol': protocol})
                    requests.append({'path': url.format(PROTOCOL_MAP[protocol], DIRECTION), 'method': DELETE})
                else:
                    if len(redistribute_list) == 1:
                        url = ospf_path + ospf_dict['protocol']
                        commands.append({'protocol': protocol})
                        requests.append({'path': url.format(PROTOCOL_MAP[protocol], DIRECTION), 'method': DELETE})
                    else:
                        for item in redistribute_list:
                            redis_cmd = {}
                            if item != 'protocol' and item in have_redistribute_list and redistribute_list[item] == have_redistribute_list[item]:
                                url = ospf_path + ospf_dict[item]
                                redis_cmd[item] = have_redistribute_list[item]
                                requests.append({'path': url.format(PROTOCOL_MAP[protocol], DIRECTION), 'method': DELETE})
                            if redis_cmd:
                                redis_cmd['protocol'] = protocol
                                commands.append(redis_cmd)
        return commands, requests

    def sort_lists_in_config(self, config):
        if config:
            config.sort(key=lambda x: x['vrf_name'])
            for cfg in config:
                if cfg.get('redistribute', None):
                    cfg['redistribute'].sort(key=lambda x: x['protocol'])
                if cfg.get('graceful_restart', None):
                    if cfg['graceful_restart'].get('helper', None):
                        if cfg['graceful_restart']['helper'].get('advertise_router_id', []):
                            cfg['graceful_restart']['helper']['advertise_router_id'].sort()
