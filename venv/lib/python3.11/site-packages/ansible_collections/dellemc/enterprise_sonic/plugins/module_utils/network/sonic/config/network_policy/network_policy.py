#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_network_policy class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy
from ansible.module_utils.connection import ConnectionError
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    remove_empties_from_list,
    update_states
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF,
    get_new_config,
    get_formatted_config_diff
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    edit_config,
    to_request
)

NETWORK_POLICY_PATH = 'data/openconfig-network-policy-ext:network-policies'
PATCH = 'patch'
DELETE = 'delete'
TEST_KEYS = [
    {'config': {'number': ''}},
    {'applications': {'app_type': ''}}
]
delete_all = False
is_replaced = False


def __derive_network_policy_delete_op(key_set, command, exist_conf):
    if delete_all or is_replaced:
        new_conf = []
        return True, new_conf
    done, new_conf = __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, exist_conf)
    return done, new_conf


TEST_KEYS_generate_config = [
    {'config': {'number': '', '__delete_op': __derive_network_policy_delete_op}},
    {'applications': {'app_type': '', '__delete_op': __derive_network_policy_delete_op}}
]


class Network_policy(ConfigBase):
    """
    The sonic_network_policy class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'network_policy',
    ]

    def __init__(self, module):
        super(Network_policy, self).__init__(module)

    def get_network_policy_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        network_policy_facts = facts['ansible_network_resources'].get('network_policy')
        if not network_policy_facts:
            return []
        return network_policy_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        commands = []

        existing_network_policy_facts = self.get_network_policy_facts()
        commands, requests = self.set_config(existing_network_policy_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        result['before'] = existing_network_policy_facts
        old_config = existing_network_policy_facts
        if self._module.check_mode:
            new_config = remove_empties_from_list(get_new_config(commands, existing_network_policy_facts, TEST_KEYS_generate_config))
            self.sort_lists_in_config(new_config)
            result['after(generated)'] = new_config
        else:
            new_config = self.get_network_policy_facts()
            if result['changed']:
                result['after'] = new_config
        if self._module._diff:
            self.sort_lists_in_config(new_config)
            self.sort_lists_in_config(old_config)
            result['diff'] = get_formatted_config_diff(old_config, new_config, self._module._verbosity)

        return result

    def set_config(self, existing_network_policy_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = remove_empties_from_list(self._module.params['config'])
        have = existing_network_policy_facts
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
        commands, requests = [], []
        state = self._module.params['state']
        diff = get_diff(want, have, TEST_KEYS)

        if state == 'merged':
            commands, requests = self._state_merged(diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have, diff)
        elif state == 'overridden':
            commands, requests = self._state_overridden(want, have, diff)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have, diff)
        return commands, requests

    def _state_merged(self, diff):
        """
        The command generator when state is merged
        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        requests = self.get_modify_network_policy_request(commands)

        if commands and len(requests) > 0:
            commands = update_states(commands, 'merged')
        else:
            commands = []

        return commands, requests

    def _state_replaced(self, want, have, diff):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, mod_commands = [], []
        global is_replaced
        is_replaced = False
        replaced_config, requests = self.get_replaced_config(want, have)

        if replaced_config:
            is_replaced = True
            commands.extend(update_states(replaced_config, 'deleted'))
            mod_commands = want
        else:
            mod_commands = diff

        if mod_commands:
            mod_request = self.get_modify_network_policy_request(mod_commands)

            if mod_request:
                requests.append(mod_request)
                commands.extend(update_states(mod_commands, 'replaced'))

        return commands, requests

    def _state_overridden(self, want, have, diff):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, requests = [], []
        mod_commands, mod_request = None, None
        global delete_all
        delete_all = False
        del_commands = get_diff(have, want, TEST_KEYS)

        if del_commands:
            delete_all = True
            del_requests = self.get_delete_network_policy_requests(del_commands, delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(have, 'deleted'))
            mod_commands = want
            mod_request = self.get_modify_network_policy_request(mod_commands)
        elif diff:
            mod_commands = diff
            mod_request = self.get_modify_network_policy_request(mod_commands)

        if mod_request:
            requests.append(mod_request)
            commands.extend(update_states(mod_commands, 'overridden'))

        return commands, requests

    def _state_deleted(self, want, have, diff):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        global delete_all
        delete_all = False
        requests = []

        if not want:
            commands = deepcopy(have)
            delete_all = True
        else:
            commands = get_diff(want, diff, TEST_KEYS)

        if commands:
            requests = self.get_delete_network_policy_requests(commands, delete_all)
            if len(requests) > 0:
                commands = update_states(commands, 'deleted')
        else:
            commands = []

        return commands, requests

    def get_modify_network_policy_request(self, commands):
        request = None
        bool_dict = {True: False, False: True}

        if commands:
            policy_list = []
            for policy in commands:
                policy_dict = {}
                number = policy.get('number')
                applications = policy.get('applications')

                if number:
                    policy_dict.update({'number': number, 'config': {'number': number}})
                if applications:
                    app_list = []
                    for app in applications:
                        app_dict = {}
                        app_type = app.get('app_type')
                        dot1p = app.get('dot1p')
                        vlan_id = app.get('vlan_id')
                        untagged = app.get('untagged')
                        priority = app.get('priority')
                        dscp = app.get('dscp')

                        if app_type:
                            app_type = app_type.upper().replace('-', '_')
                            app_dict.update({'type': app_type, 'config': {'type': app_type}})
                        if dot1p:
                            app_dict['config']['vlan-id'] = 0
                        if vlan_id:
                            app_dict['config']['vlan-id'] = vlan_id
                        if untagged is not None:
                            app_dict['config']['tagged'] = bool_dict[untagged]
                        if priority is not None:
                            app_dict['config']['priority'] = priority
                        if dscp is not None:
                            app_dict['config']['dscp'] = dscp
                        if app_dict:
                            app_list.append(app_dict)
                    if app_list:
                        policy_dict['applications'] = {'application': app_list}
                if policy_dict:
                    policy_list.append(policy_dict)
            if policy_list:
                payload = {'openconfig-network-policy-ext:network-policies': {'network-policy': policy_list}}
                request = {'path': NETWORK_POLICY_PATH, 'method': PATCH, 'data': payload}

        return request

    def get_delete_network_policy_requests(self, commands, delete_all):
        requests = []

        if not commands:
            return requests
        if delete_all:
            requests.append({'path': NETWORK_POLICY_PATH, 'method': DELETE})
            return requests

        for policy in commands:
            number = policy.get('number')
            applications = policy.get('applications')

            if number and not applications:
                requests.append(self.get_delete_network_policy_request(number))
            elif applications:
                for app in applications:
                    app_type = app.get('app_type')
                    dot1p = app.get('dot1p')
                    vlan_id = app.get('vlan_id')
                    untagged = app.get('untagged')
                    priority = app.get('priority')
                    dscp = app.get('dscp')

                    if app_type and len(app) == 1:
                        requests.append(self.get_delete_network_policy_request(number, app_type))
                        continue
                    if dot1p or vlan_id:
                        requests.append(self.get_delete_network_policy_request(number, app_type, 'vlan-id'))
                    if untagged is not None:
                        requests.append(self.get_delete_network_policy_request(number, app_type, 'tagged'))
                    if priority is not None:
                        requests.append(self.get_delete_network_policy_request(number, app_type, 'priority'))
                    if dscp is not None:
                        requests.append(self.get_delete_network_policy_request(number, app_type, 'dscp'))

        return requests

    @staticmethod
    def get_delete_network_policy_request(number, app_type=None, attr=None):
        url = '%s/network-policy=%s' % (NETWORK_POLICY_PATH, number)
        if app_type:
            url += '/applications/application=%s' % (app_type.upper().replace('-', '_'))
        if attr:
            url += '/config/%s' % (attr)
        return {'path': url, 'method': DELETE}

    def get_replaced_config(self, want, have):
        config_list, requests = [], []
        self.sort_lists_in_config(want)
        self.sort_lists_in_config(have)

        if not want or not have:
            return config_list, requests

        policy_dict = {policy.get('number'): policy for policy in have}
        for policy in want:
            number = policy.get('number')
            cfg_policy = policy_dict.get(number)

            if not cfg_policy:
                continue
            if policy != cfg_policy:
                requests.append(self.get_delete_network_policy_request(number))
                config_list.append(cfg_policy)

        return config_list, requests

    @staticmethod
    def sort_lists_in_config(config):
        if config:
            config.sort(key=lambda x: x['number'])
            for policy in config:
                if policy.get('applications'):
                    policy['applications'].sort(key=lambda x: x['app_type'])
