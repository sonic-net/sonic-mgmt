#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_ssh class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    get_new_config,
    get_formatted_config_diff
)
from ansible.module_utils.connection import ConnectionError

PATCH = 'patch'
DELETE = 'delete'


class Ssh(ConfigBase):
    """
    The sonic_ssh class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'ssh',
    ]

    ssh_client_config_path = 'data/openconfig-system:system/openconfig-system-ext:ssh-client/config'
    ssh_client_algo_config_path = {
        'ciphers': ssh_client_config_path + '/ciphers',
        'kexalgorithms': ssh_client_config_path + '/kexalgorithms',
        'macs': ssh_client_config_path + '/macs'
    }

    def __init__(self, module):
        super(Ssh, self).__init__(module)

    def get_ssh_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        ssh_facts = facts['ansible_network_resources'].get('ssh')
        if not ssh_facts:
            return {}
        return ssh_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        commands = list()

        existing_ssh_facts = self.get_ssh_facts()
        commands, requests = self.set_config(existing_ssh_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_ssh_facts = self.get_ssh_facts()

        result['before'] = existing_ssh_facts
        if result['changed']:
            result['after'] = changed_ssh_facts

        new_config = changed_ssh_facts
        old_config = existing_ssh_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_ssh_facts)
            result['after(generated)'] = new_config
        if self._module._diff:
            result['diff'] = get_formatted_config_diff(old_config, new_config, self._module._verbosity)

        result['warnings'] = warnings
        return result

    def set_config(self, existing_ssh_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_ssh_facts
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
            commands, requests = self._state_replaced_overridden(want, have)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have)
        elif state == 'replaced':
            commands, requests = self._state_replaced_overridden(want, have)
        return commands, requests

    def _state_replaced_overridden(self, want, have):
        """ The command generator when state is replaced or overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []

        client_want = {}
        client_have = {}
        if want and want.get('client', None):
            client_want['client'] = want['client']
        if have and have.get('client', None):
            client_have['client'] = have['client']
        commands, requests = self.handle_ssh_client_replaced_overridden(client_want, client_have)

        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = []
        requests = []

        client_want = {}
        client_have = {}
        if want and want.get('client', None):
            client_want['client'] = want['client']
        if have and have.get('client', None):
            client_have['client'] = have['client']
        client_commands, client_requests = self.handle_ssh_client_merged(client_want, client_have)
        requests.extend(client_requests)

        if client_commands and len(requests) > 0:
            commands = update_states(client_commands, 'merged')

        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        commands = []
        requests = []

        client_want = {}
        client_have = {}
        if want and want.get('client', None):
            client_want['client'] = want['client']
        if have and have.get('client', None):
            client_have['client'] = have['client']
        client_commands, client_requests = self.handle_ssh_client_deleted(client_want, client_have)
        requests.extend(client_requests)

        if client_commands and len(requests) > 0:
            commands = update_states(client_commands, "deleted")

        return commands, requests

    def handle_ssh_client_replaced_overridden(self, want, have):
        """Requests and commands necessary to migrate the current configuration
           to the desired configuration
        """
        commands = []
        requests = []
        state = self._module.params['state']

        if want:
            diff = get_diff(have, want)
            commands = diff
        if commands:
            requests = self.delete_specific_ssh_client_params(commands)
            commands = update_states(commands, "deleted")
        else:
            commands = []

        diff = get_diff(want, have)
        if diff:
            mod_commands = diff
            mod_requests = self.modify_specific_ssh_client_params(mod_commands)
            if mod_commands and len(mod_requests) > 0:
                mod_commands = update_states(mod_commands, state)
                commands.extend(mod_commands)
                requests.extend(mod_requests)

        return commands, requests

    def handle_ssh_client_merged(self, want, have):
        """Requests and commands necessary to merge the provided into
           the current configuration
        """
        commands = []
        requests = []

        diff = get_diff(want, have)
        commands = diff
        requests.extend(self.modify_specific_ssh_client_params(commands))

        return commands, requests

    def handle_ssh_client_deleted(self, want, have):
        """Requests and commands necessary to remove the current configuration
           of the provided objects
        """
        commands = []
        requests = []

        delete_all = False
        if not want:
            commands = have
            delete_all = True
        else:
            commands = self.get_matched_commands(want, have)

        if commands:
            if delete_all:
                requests = self.delete_all_ssh_client_params()
            else:
                requests = self.delete_specific_ssh_client_params(commands)

        return commands, requests

    def modify_specific_ssh_client_params(self, commands):
        """Requests to modify specific SSH client algorithm configurations
        """
        requests = []
        command = commands.get('client')

        if not command:
            return requests

        if 'cipher' in command and command['cipher'] is not None:
            payload = {'openconfig-system-ext:ciphers': command['cipher']}
            url = self.ssh_client_algo_config_path['ciphers']
            requests.append({'path': url, 'method': PATCH, 'data': payload})
        if 'kex' in command and command['kex'] is not None:
            payload = {'openconfig-system-ext:kexalgorithms': command['kex']}
            url = self.ssh_client_algo_config_path['kexalgorithms']
            requests.append({'path': url, 'method': PATCH, 'data': payload})
        if 'mac' in command and command['mac'] is not None:
            payload = {'openconfig-system-ext:macs': command['mac']}
            url = self.ssh_client_algo_config_path['macs']
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        return requests

    def get_matched_commands(self, want, have):
        """Matched commands from the input and available configurations
        """
        commands = {}
        match = {}
        if want.get('client') and have.get('client'):
            if want['client'].get('cipher') is not None and have['client'].get('cipher') is not None:
                cipher = set(want['client'].get('cipher').split(','))
                cfg_cipher = set(have['client'].get('cipher').split(','))
                if cipher == cfg_cipher:
                    match['cipher'] = ','.join(cipher)
            if want['client'].get('kex') is not None and have['client'].get('kex') is not None:
                kex = set(want['client'].get('kex').split(','))
                cfg_kex = set(have['client'].get('kex').split(','))
                if kex == cfg_kex:
                    match['kex'] = ','.join(kex)
            if want['client'].get('mac') is not None and have['client'].get('mac') is not None:
                mac = set(want['client'].get('mac').split(','))
                cfg_mac = set(have['client'].get('mac').split(','))
                if mac == cfg_mac:
                    match['mac'] = ','.join(mac)
            if match:
                commands['client'] = match

        return commands

    def delete_all_ssh_client_params(self):
        """Requests to delete SSH client algorithm configurations on the chassis
        """
        requests = []
        requests.append({'path': self.ssh_client_config_path, 'method': DELETE})

        return requests

    def delete_specific_ssh_client_params(self, commands):
        """Requests to delete specific SSH client algorithm configurations on the chassis
        """
        requests = []
        command = commands.get('client')

        if not command:
            return requests

        if 'cipher' in command and command['cipher'] is not None:
            requests.append({'path': self.ssh_client_algo_config_path['ciphers'], 'method': DELETE})
        if 'kex' in command and command['kex'] is not None:
            requests.append({'path': self.ssh_client_algo_config_path['kexalgorithms'], 'method': DELETE})
        if 'mac' in command and command['mac'] is not None:
            requests.append({'path': self.ssh_client_algo_config_path['macs'], 'method': DELETE})

        return requests
