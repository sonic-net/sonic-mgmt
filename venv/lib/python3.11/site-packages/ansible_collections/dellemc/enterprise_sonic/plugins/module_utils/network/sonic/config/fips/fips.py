#
# -*- coding: utf-8 -*-
# Copyright 2022 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_fips class
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


class Fips(ConfigBase):
    """
    The sonic_fips class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'fips',
    ]

    fips_config_path = 'data/openconfig-fips:fips/config'
    fips_mode_path = {
        'enable': fips_config_path + '/fips-mode'
    }

    def __init__(self, module):
        super(Fips, self).__init__(module)

    def get_fips_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        fips_facts = facts['ansible_network_resources'].get('fips')
        if not fips_facts:
            return []
        return fips_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        commands = list()

        existing_fips_facts = self.get_fips_facts()
        commands, requests = self.set_config(existing_fips_facts)
        if commands:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_fips_facts = self.get_fips_facts()

        result['before'] = existing_fips_facts
        if result['changed']:
            result['after'] = changed_fips_facts

        result['warnings'] = warnings
        return result

    def set_config(self, existing_fips_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_fips_facts
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
        commands = []
        requests = []
        return commands, requests

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []
        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        diff = get_diff(want, have)
        commands = diff
        requests = []
        requests.extend(self.modify_specific_fips_param_requests(commands))
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
        if not want:
            commands = have
        else:
            diff = get_diff(want, have)
            commands = get_diff(want, diff)
        requests = []

        if commands and 'enable' in commands and commands['enable'] is True:
            requests.extend(self.delete_fips_param_requests())

        if len(requests) == 0:
            commands = []

        if commands and 'enable' in commands and commands['enable'] is False:
            return commands, requests

        if commands:
            commands = update_states(commands, "deleted")

        return commands, requests

    def modify_specific_fips_param_requests(self, command):
        """Requests to modify specific FIPS mode configurations
        """
        requests = []

        if not command:
            return requests

        if 'enable' in command and command['enable'] is not None:
            payload = {'openconfig-fips:fips-mode': command['enable']}
            url = self.fips_mode_path['enable']
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        return requests

    def delete_fips_param_requests(self):
        """Requests to delete FIPS mode configurations in the chassis
        """
        requests = []
        requests.append({'path': self.fips_config_path, 'method': DELETE})

        return requests
