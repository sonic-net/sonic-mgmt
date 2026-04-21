#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_drop_counter class
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

is_delete_all = False
DROP_COUNTER_PATH = 'data/sonic-debugcounter:sonic-debugcounter'
PATCH = 'patch'
DELETE = 'delete'
TEST_KEYS = [
    {'config': {'name': ''}},
]


def __derive_drop_counter_delete_op(key_set, command, exist_conf):
    if is_delete_all:
        new_conf = []
        return True, new_conf

    # Handle deletion of default values
    if command.get('enable'):
        exist_conf['enable'] = False
        command.pop('enable')
    done, new_conf = __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, exist_conf)
    return done, new_conf


TEST_KEYS_generate_config = [
    {'config': {'name': '', '__delete_op': __derive_drop_counter_delete_op}}
]


class Drop_counter(ConfigBase):
    """
    The sonic_drop_counter class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'drop_counter',
    ]

    def __init__(self, module):
        super(Drop_counter, self).__init__(module)

    def get_drop_counter_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        drop_counter_facts = facts['ansible_network_resources'].get('drop_counter')
        if not drop_counter_facts:
            return []
        return drop_counter_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        commands = []

        existing_drop_counter_facts = self.get_drop_counter_facts()
        commands, requests = self.set_config(existing_drop_counter_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        result['before'] = existing_drop_counter_facts
        old_config = existing_drop_counter_facts
        if self._module.check_mode:
            new_config = remove_empties_from_list(get_new_config(commands, existing_drop_counter_facts, TEST_KEYS_generate_config))
            self.sort_lists_in_config(new_config)
            result['after(generated)'] = new_config
        else:
            new_config = self.get_drop_counter_facts()
            if result['changed']:
                result['after'] = new_config
        if self._module._diff:
            self.sort_lists_in_config(new_config)
            self.sort_lists_in_config(old_config)
            result['diff'] = get_formatted_config_diff(old_config, new_config, self._module._verbosity)

        return result

    def set_config(self, existing_drop_counter_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = remove_empties_from_list(self._module.params['config'])
        have = existing_drop_counter_facts
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
        requests = self.get_modify_drop_counter_request(commands)

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
        replaced_config, requests = self.get_replaced_config(want, have)

        if replaced_config:
            commands.extend(update_states(replaced_config, 'deleted'))
            mod_commands = want
        else:
            mod_commands = diff

        if mod_commands:
            mod_request = self.get_modify_drop_counter_request(mod_commands)

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
        global is_delete_all
        is_delete_all = False
        commands, requests = [], []
        mod_commands, mod_request = None, None
        del_commands = get_diff(have, want, TEST_KEYS)
        self.remove_default_entries(del_commands)

        if del_commands:
            is_delete_all = True
            del_requests = self.get_delete_drop_counter_requests(del_commands, is_delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(have, 'deleted'))
            mod_commands = want
            mod_request = self.get_modify_drop_counter_request(mod_commands)
        elif diff:
            mod_commands = diff
            mod_request = self.get_modify_drop_counter_request(mod_commands)

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
        global is_delete_all
        is_delete_all = False
        requests = []

        if not want:
            commands = deepcopy(have)
            is_delete_all = True
        else:
            commands = get_diff(want, diff, TEST_KEYS)
            self.remove_default_entries(commands)

        if commands:
            requests = self.get_delete_drop_counter_requests(commands, is_delete_all)
            if len(requests) > 0:
                commands = update_states(commands, 'deleted')
        else:
            commands = []

        return commands, requests

    def get_modify_drop_counter_request(self, commands):
        """This method returns a patch request generated from commands"""
        request = None
        enum_dict = {False: 'disable', True: 'enable'}

        if commands:
            counter_list = []
            for counter in commands:
                counter_dict = {}
                name = counter.get('name')
                alias = counter.get('alias')
                counter_description = counter.get('counter_description')
                counter_type = counter.get('counter_type')
                enable = counter.get('enable')
                group = counter.get('group')
                mirror = counter.get('mirror')
                reasons = counter.get('reasons')

                if name:
                    counter_dict['name'] = name
                if alias:
                    counter_dict['alias'] = alias
                if counter_description:
                    counter_dict['desc'] = counter_description
                if counter_type:
                    counter_dict['type'] = counter_type
                if enable is not None:
                    counter_dict['status'] = enum_dict[enable]
                if group:
                    counter_dict['group'] = group
                if mirror:
                    counter_dict['mirror'] = mirror
                if reasons:
                    counter_dict['reasons'] = reasons
                if counter_dict:
                    counter_list.append(counter_dict)
            if counter_list:
                payload = {'sonic-debugcounter:sonic-debugcounter': {'DEBUG_COUNTER': {'DEBUG_COUNTER_LIST': counter_list}}}
                request = {'path': DROP_COUNTER_PATH, 'method': PATCH, 'data': payload}

        return request

    def get_delete_drop_counter_requests(self, commands, is_delete_all):
        """This method returns a list of delete requests generated from commands"""
        requests = []

        if not commands:
            return requests
        if is_delete_all:
            requests.append(self.get_delete_drop_counter_request())
            return requests

        for counter in commands:
            name = counter.get('name')
            if len(counter) == 1:
                requests.append(self.get_delete_drop_counter_request(name))
                continue

            alias = counter.get('alias')
            counter_description = counter.get('counter_description')
            counter_type = counter.get('counter_type')
            enable = counter.get('enable')
            group = counter.get('group')
            mirror = counter.get('mirror')
            reasons = counter.get('reasons')

            if alias:
                requests.append(self.get_delete_drop_counter_request(name, 'alias'))
            if counter_description:
                requests.append(self.get_delete_drop_counter_request(name, 'desc'))
            if counter_type:
                requests.append(self.get_delete_drop_counter_request(name, 'type'))
            if enable is not None:
                requests.append(self.get_delete_drop_counter_request(name, 'status'))
            if group:
                requests.append(self.get_delete_drop_counter_request(name, 'group'))
            if mirror:
                requests.append(self.get_delete_drop_counter_request(name, 'mirror'))
            if reasons:
                for reason in reasons:
                    attr = 'reasons=' + reason
                    requests.append(self.get_delete_drop_counter_request(name, attr))

        return requests

    @staticmethod
    def get_delete_drop_counter_request(name=None, attr=None):
        """This method formulates the URL and returns a delete request"""
        url = DROP_COUNTER_PATH
        if name:
            url += '/DEBUG_COUNTER/DEBUG_COUNTER_LIST=%s' % (name)
        if attr:
            url += '/%s' % (attr)
        return {'path': url, 'method': DELETE}

    def get_replaced_config(self, want, have):
        """This method returns the drop counter configuration to be deleted and the respective delete requests"""
        config_list, requests = [], []
        cp_want = deepcopy(want)
        cp_have = deepcopy(have)
        self.remove_default_entries(cp_want)
        self.remove_default_entries(cp_have)
        self.sort_lists_in_config(cp_want)
        self.sort_lists_in_config(cp_have)

        if not cp_want or not cp_have:
            return config_list, requests

        counter_dict = {counter.get('name'): counter for counter in cp_have}
        for counter in cp_want:
            name = counter.get('name')
            cfg_counter = counter_dict.get(name)

            if not cfg_counter:
                continue
            if counter != cfg_counter:
                requests.append(self.get_delete_drop_counter_request(counter['name']))
                config_list.append(cfg_counter)

        return config_list, requests

    @staticmethod
    def sort_lists_in_config(config):
        """This method sorts the lists in the drop counter configuration"""
        if config:
            config.sort(key=lambda x: x['name'])
            for counter in config:
                if counter.get('reasons'):
                    counter['reasons'].sort()

    def remove_default_entries(self, config):
        """This method removes default entries from the drop counter configuration"""
        if config:
            pop_list = []
            for idx, counter in enumerate(config):
                if counter.get('enable') is False:
                    counter.pop('enable')
                    if len(counter) == 1:
                        pop_list.insert(0, idx)
            for idx in pop_list:
                config.pop(idx)
