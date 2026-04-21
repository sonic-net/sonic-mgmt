#
# -*- coding: utf-8 -*-
# Copyright 2023 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_login_lockout class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    update_states
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

PATCH = 'patch'
DELETE = 'delete'


class Login_lockout(ConfigBase):
    """
    The sonic_login_lockout class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'login_lockout',
    ]

    login_lockout_path = 'data/openconfig-system:system/openconfig-system-ext:login/lockout/config'
    login_lockout_config_path = {
        'period': login_lockout_path + '/lockout-period',
        'max_retries': login_lockout_path + '/max-retry',
        'console_exempt': login_lockout_path + '/console-exempt',
    }
    default_config_dict = {"console_exempt": False, "period": 0, "max_retries": 3}

    def __init__(self, module):
        super(Login_lockout, self).__init__(module)

    def get_login_lockout_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        login_lockout_facts = facts['ansible_network_resources'].get('login_lockout')
        if not login_lockout_facts:
            return []
        return login_lockout_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        commands = list()

        existing_login_lockout_facts = self.get_login_lockout_facts()

        commands, requests = self.set_config(existing_login_lockout_facts)
        if commands:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_login_lockout_facts = self.get_login_lockout_facts()

        result['before'] = existing_login_lockout_facts

        if result['changed']:
            result['after'] = changed_login_lockout_facts
        result['warnings'] = warnings

        return result

    def set_config(self, existing_login_lockout_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']

        have = existing_login_lockout_facts

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
        state = self._module.params['state']
        diff = get_diff(want, have)
        if state == 'deleted':
            commands, requests = self._state_deleted(want, have, diff)
        elif state == 'merged':
            commands, requests = self._state_merged(diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced_overridden(want, have, diff)
        elif state == 'overridden':
            commands, requests = self._state_replaced_overridden(want, have, diff)
        return commands, requests

    def _state_replaced_overridden(self, want, have, diff):
        """ The command generator when state is replaced or overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []
        delete = {}
        state = self._module.params['state']

        for key in have:
            if key in want:
                if want[key] == have[key]:
                    continue
            if key not in diff and have[key] != self.default_config_dict[key]:
                delete[key] = have[key]
        if delete:
            commands = update_states(delete, 'deleted')
            requests.extend(self.get_delete_specific_login_lockout_param_requests(delete))
        if diff:
            commands.extend(update_states(diff, state))
            requests.extend(self.get_modify_specific_login_lockout_param_requests(diff))

        return commands, requests

    def _state_merged(self, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = []
        requests = []

        if diff:
            requests = self.get_modify_specific_login_lockout_param_requests(diff)
            if len(requests) > 0:
                commands = update_states(diff, 'merged')

        return commands, requests

    def _state_deleted(self, want, have, diff):
        """ The command generator when state is deleted
        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        commands = []
        requests = []
        delete = {}

        if not want:
            delete = have.copy()
            delete = {key: value for key, value in delete.items() if key not in self.default_config_dict or self.default_config_dict[key] != value}
            commands = delete
            requests.extend(self.get_delete_specific_login_lockout_param_requests(commands))
        else:
            delete = get_diff(want, diff)
            delete = {key: value for key, value in delete.items() if key not in self.default_config_dict or self.default_config_dict[key] != value}
            commands = delete
            requests.extend(self.get_delete_specific_login_lockout_param_requests(commands))

        if len(requests) == 0:
            commands = []

        if commands:
            commands = update_states(commands, "deleted")

        return commands, requests

    def get_modify_specific_login_lockout_param_requests(self, command):
        """Get requests to modify specific Login Lockout configurations
        based on the command specified
        """
        requests = []
        config_dict = {}

        if not command:
            return requests

        if 'console_exempt' in command and command['console_exempt'] is not None:
            config_dict['console-exempt'] = command['console_exempt']

        if 'period' in command and command['period'] is not None:
            config_dict['lockout-period'] = int(command['period'])

        if 'max_retries' in command and command['max_retries'] is not None:
            config_dict['max-retry'] = int(command['max_retries'])

        payload = {"openconfig-system-ext:config": config_dict}

        requests.append({'path': self.login_lockout_path, 'method': PATCH, 'data': payload})

        return requests

    def get_delete_specific_login_lockout_param_requests(self, command):
        """Get requests to delete specific Login Lockout configurations
        based on the command specified
        """
        requests = []

        if not command:
            return requests

        if 'period' in command:
            url = self.login_lockout_config_path['period']
            requests.append({'path': url, 'method': DELETE})

        if 'console_exempt' in command:
            url = self.login_lockout_config_path['console_exempt']
            requests.append({'path': url, 'method': DELETE})

        if 'max_retries' in command:
            url = self.login_lockout_config_path['max_retries']
            requests.append({'path': url, 'method': DELETE})

        return requests
