#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_qos_pfc class
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
    get_replaced_config,
    remove_empties,
    update_states
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    get_new_config,
    get_formatted_config_diff
)


QOS_PFC_PATH = '/data/openconfig-qos:qos/pfc-watchdog'
PATCH = 'patch'
DELETE = 'delete'


class Qos_pfc(ConfigBase):
    """
    The sonic_qos_pfc class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'qos_pfc',
    ]

    def __init__(self, module):
        super(Qos_pfc, self).__init__(module)

    def get_qos_pfc_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        qos_pfc_facts = facts['ansible_network_resources'].get('qos_pfc')
        if not qos_pfc_facts:
            return {}
        return qos_pfc_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = []
        commands = []

        existing_qos_pfc_facts = self.get_qos_pfc_facts()
        commands, requests = self.set_config(existing_qos_pfc_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_qos_pfc_facts = self.get_qos_pfc_facts()

        result['before'] = existing_qos_pfc_facts
        if result['changed']:
            result['after'] = changed_qos_pfc_facts

        new_config = changed_qos_pfc_facts
        old_config = existing_qos_pfc_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_qos_pfc_facts)
            result['after(generated)'] = new_config
        if self._module._diff:
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)

        result['warnings'] = warnings
        return result

    def set_config(self, existing_qos_pfc_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = remove_empties(self._module.params['config'])
        have = existing_qos_pfc_facts
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
        replaced_config = get_replaced_config(want, have)

        mod_commands = []
        if replaced_config:
            is_delete_all = replaced_config == have
            del_requests = self.get_delete_qos_pfc_requests(replaced_config, have, is_delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(replaced_config, 'deleted'))
            mod_commands = want
        else:
            mod_commands = diff

        if mod_commands:
            mod_request = self.get_modify_qos_pfc_request(mod_commands)

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

        if have and have != want:
            is_delete_all = True
            del_requests = self.get_delete_qos_pfc_requests(have, None, is_delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(have, 'deleted'))
            have = []

        if not have and want:
            mod_commands = want
            mod_request = self.get_modify_qos_pfc_request(mod_commands)

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
        requests = self.get_modify_qos_pfc_request(commands)

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

        self.remove_default_entries(want)
        if not want:
            commands = deepcopy(have)
            is_delete_all = True
        else:
            commands = deepcopy(want)

        self.remove_default_entries(commands)
        requests = self.get_delete_qos_pfc_requests(commands, have, is_delete_all)

        if commands and len(requests) > 0:
            commands = update_states(commands, 'deleted')
        else:
            commands = []

        return commands, requests

    def get_modify_qos_pfc_request(self, commands):
        request = None

        if commands:
            pfc_dict = {}
            counter_poll_dict = {True: 'ENABLE', False: 'DISABLE'}
            counter_poll = commands.get('counter_poll')
            poll_interval = commands.get('poll_interval')

            if counter_poll is not None:
                pfc_dict['flex'] = {'config': {'counter-poll': counter_poll_dict[counter_poll]}}
            if poll_interval:
                pfc_dict['poll'] = {'config': {'poll-interval': poll_interval}}
            if pfc_dict:
                payload = {'openconfig-qos:pfc-watchdog': pfc_dict}
                request = {'path': QOS_PFC_PATH, 'method': PATCH, 'data': payload}

        return request

    def get_delete_qos_pfc_requests(self, commands, have, is_delete_all):
        requests = []

        if not commands:
            return requests

        counter_poll_url = '%s/flex/config/counter-poll' % (QOS_PFC_PATH)
        poll_interval_url = '%s/poll/config/poll-interval' % (QOS_PFC_PATH)
        counter_poll = commands.get('counter_poll')
        poll_interval = commands.get('poll_interval')

        if is_delete_all:
            if counter_poll is not True:
                payload = {'openconfig-qos:counter-poll': 'ENABLE'}
                requests.append({'path': counter_poll_url, 'method': PATCH, 'data': payload})
            requests.append({'path': poll_interval_url, 'method': DELETE})
            return requests

        cfg_counter_poll = have.get('counter_poll')
        cfg_poll_interval = have.get('poll_interval')
        if counter_poll is not None:
            if counter_poll is False and cfg_counter_poll is False:
                payload = {'openconfig-qos:counter-poll': 'ENABLE'}
                requests.append({'path': counter_poll_url, 'method': PATCH})
            else:
                commands.pop('counter_poll')
        if poll_interval:
            if poll_interval == cfg_poll_interval:
                requests.append({'path': poll_interval_url, 'method': DELETE})
            else:
                commands.pop('poll_interval')

        return requests

    def remove_default_entries(self, data):
        if data and data.get('counter_poll') is True:
            data.pop('counter_poll')
