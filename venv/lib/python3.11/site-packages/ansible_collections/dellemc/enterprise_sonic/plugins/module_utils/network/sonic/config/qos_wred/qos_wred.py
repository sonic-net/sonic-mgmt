#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_qos_wred class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from copy import deepcopy
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible.module_utils.connection import ConnectionError
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    remove_empties_from_list,
    update_states
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_CONFIG_IF_NO_SUBCONFIG,
    get_new_config,
    get_formatted_config_diff
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)


QOS_WRED_PATH = '/data/openconfig-qos:qos/wred-profiles/wred-profile'
PATCH = 'patch'
DELETE = 'delete'
TEST_KEYS = [
    {'config': {'name': ''}}
]
TEST_KEYS_formatted_diff = [
    {'config': {'name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}}
]


class Qos_wred(ConfigBase):
    """
    The sonic_qos_wred class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'qos_wred',
    ]

    def __init__(self, module):
        super(Qos_wred, self).__init__(module)

    def get_qos_wred_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        qos_wred_facts = facts['ansible_network_resources'].get('qos_wred')
        if not qos_wred_facts:
            return []
        return qos_wred_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = []
        commands = []

        existing_qos_wred_facts = self.get_qos_wred_facts()
        commands, requests = self.set_config(existing_qos_wred_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_qos_wred_facts = self.get_qos_wred_facts()

        result['before'] = existing_qos_wred_facts
        if result['changed']:
            result['after'] = changed_qos_wred_facts

        new_config = changed_qos_wred_facts
        old_config = existing_qos_wred_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_qos_wred_facts,
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

    def set_config(self, existing_qos_wred_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = remove_empties_from_list(self._module.params['config'])
        have = remove_empties_from_list(existing_qos_wred_facts)
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
        mod_commands = []
        requests = []
        replaced_config = self.get_replaced_config(want, have)

        if replaced_config:
            self.sort_lists_in_config(replaced_config)
            self.sort_lists_in_config(have)
            is_delete_all = replaced_config == have
            del_requests = self.get_delete_qos_wred_requests(replaced_config, have, is_delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(replaced_config, 'deleted'))
            mod_commands = want
        else:
            mod_commands = diff

        if mod_commands:
            mod_request = self.get_modify_qos_wred_request(mod_commands)

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
            del_requests = self.get_delete_qos_wred_requests(have, None, is_delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(have, 'deleted'))
            have = []

        if not have and want:
            mod_commands = want
            mod_request = self.get_modify_qos_wred_request(mod_commands)

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
        requests = self.get_modify_qos_wred_request(commands)

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

        requests = self.get_delete_qos_wred_requests(commands, have, is_delete_all)

        if commands and len(requests) > 0:
            commands = update_states(commands, 'deleted')
        else:
            commands = []
        return commands, requests

    def get_modify_qos_wred_request(self, commands):
        request = None
        lookup_dict = {'green': 'ECN_GREEN'}

        if commands:
            wred_list = []
            for wred in commands:
                config_dict = {}
                name = wred.get('name')
                ecn = wred.get('ecn')
                green = wred.get('green')
                if green:
                    enable = green.get('enable')
                    min_threshold = green.get('min_threshold')
                    max_threshold = green.get('max_threshold')
                    drop_probability = green.get('drop_probability')

                    if enable is not None:
                        config_dict['wred-green-enable'] = enable
                    if min_threshold:
                        config_dict['green-min-threshold'] = str(min_threshold)
                    if max_threshold:
                        config_dict['green-max-threshold'] = str(max_threshold)
                    if drop_probability is not None:
                        config_dict['green-drop-probability'] = str(drop_probability)
                if ecn:
                    config_dict['ecn'] = lookup_dict[ecn]
                if name:
                    config_dict['name'] = name
                    wred_list.append({'name': name, 'config': config_dict})
            if wred_list:
                payload = {'openconfig-qos:wred-profile': wred_list}
                request = {'path': QOS_WRED_PATH, 'method': PATCH, 'data': payload}

        return request

    def get_delete_qos_wred_requests(self, commands, have, is_delete_all):
        requests = []

        if not commands:
            return requests

        if is_delete_all:
            requests.append({'path': QOS_WRED_PATH, 'method': DELETE})
            return requests

        config_list = []
        for wred in commands:
            name = wred.get('name')
            ecn = wred.get('ecn')
            green = wred.get('green')
            for cfg_wred in have:
                cfg_name = cfg_wred.get('name')
                cfg_ecn = cfg_wred.get('ecn')
                cfg_green = cfg_wred.get('green')

                if name == cfg_name:
                    wred_dict = {}
                    if ecn and ecn == cfg_ecn:
                        requests.append(self.get_delete_wred_cfg_attr(name, 'ecn'))
                        wred_dict.update({'name': name, 'ecn': ecn})
                    if green:
                        enable = green.get('enable')
                        min_threshold = green.get('min_threshold')
                        max_threshold = green.get('max_threshold')
                        drop_probability = green.get('drop_probability')

                        if cfg_green:
                            green_dict = {}
                            cfg_enable = cfg_green.get('enable')
                            cfg_min_threshold = cfg_green.get('min_threshold')
                            cfg_max_threshold = cfg_green.get('max_threshold')
                            cfg_drop_probability = cfg_green.get('drop_probability')

                            if enable is not None and enable == cfg_enable:
                                requests.append(self.get_delete_wred_cfg_attr(name, 'wred-green-enable'))
                                green_dict['enable'] = enable
                            if min_threshold and min_threshold == cfg_min_threshold:
                                requests.append(self.get_delete_wred_cfg_attr(name, 'green-min-threshold'))
                                green_dict['min_threshold'] = min_threshold
                            if max_threshold and max_threshold == cfg_max_threshold:
                                requests.append(self.get_delete_wred_cfg_attr(name, 'green-max-threshold'))
                                green_dict['max_threshold'] = max_threshold
                            if drop_probability is not None and drop_probability == cfg_drop_probability:
                                requests.append(self.get_delete_wred_cfg_attr(name, 'green-drop-probability'))
                                green_dict['drop_probability'] = drop_probability
                            if green_dict:
                                wred_dict.update({'name': name, 'green': green_dict})
                    # Deletion my WRED profile name
                    if not ecn and not green:
                        url = '%s=%s' % (QOS_WRED_PATH, name)
                        requests.append({'path': url, 'method': DELETE})
                        wred_dict['name'] = name
                    if wred_dict:
                        config_list.append(wred_dict)
                    break

        commands = config_list
        return requests

    def sort_lists_in_config(self, config):
        if config:
            config.sort(key=lambda x: x['name'])

    def get_delete_wred_cfg_attr(self, name, attr):
        url = '%s=%s/config/%s' % (QOS_WRED_PATH, name, attr)
        request = {'path': url, 'method': DELETE}

        return request

    def get_replaced_config(self, want, have):
        config_list = []

        for wred in want:
            name = wred.get('name')
            for cfg_wred in have:
                cfg_name = cfg_wred.get('name')
                if name == cfg_name:
                    if wred != cfg_wred:
                        config_list.append({'name': cfg_name})

        return config_list
