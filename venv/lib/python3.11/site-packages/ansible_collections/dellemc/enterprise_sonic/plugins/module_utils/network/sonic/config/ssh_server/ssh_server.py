#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_ssh_server class
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
    update_states,
    remove_empties
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
import time

PATCH = 'patch'
DELETE = 'delete'

delete_all = False

default_config = {
    "publickey_authentication": True,
    "ciphers": "aes128-ctr,aes192-ctr,aes256-ctr,chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
    "hostkeyalgorithms": "rsa-sha2-256,rsa-sha2-512,ssh-rsa",
    "kexalgorithms": ("curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,"
                      "ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,"
                      "diffie-hellman-group18-sha512,diffie-hellman-group14-sha256"),
    "macs": "umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512"
}


def __server_globals_delete_op(key_set, command, exist_conf):
    if delete_all:
        return True, {}

    new_conf = exist_conf

    # default handling
    if command.get('ciphers'):
        new_conf['ciphers'] = default_config['ciphers']
    if command.get('macs'):
        new_conf['macs'] = default_config['macs']
    if command.get('kexalgorithms'):
        new_conf['kexalgorithms'] = default_config['kexalgorithms']
    if command.get('hostkeyalgorithms'):
        new_conf['hostkeyalgorithms'] = default_config['hostkeyalgorithms']
    if 'publickey_authentication' in command:
        new_conf['publickey_authentication'] = default_config['publickey_authentication']

    # non-default handling
    if 'max_auth_retries' in command:
        new_conf.pop('max_auth_retries', None)
    if 'disable_forwarding' in command:
        new_conf.pop('disable_forwarding', None)
    if 'permit_root_login' in command:
        new_conf.pop('permit_root_login', None)
    if 'permit_user_environment' in command:
        new_conf.pop('permit_user_environment', None)
    if 'permit_user_rc' in command:
        new_conf.pop('permit_user_rc', None)
    if 'x11_forwarding' in command:
        new_conf.pop('x11_forwarding', None)

    return True, new_conf


TEST_KEYS_generate_config = [
    {'server_globals': {'__delete_op': __server_globals_delete_op}}
]


class Ssh_server(ConfigBase):
    """
    The sonic_ssh_server class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'ssh_server',
    ]

    ssh_server_globals_config_path = 'data/openconfig-system:system/ssh-server/openconfig-system-ext:ssh-server-globals/config'
    ssh_server_globals_param_config_path = {
        'password_authentication': ssh_server_globals_config_path + '/password-authentication',
        'publickey_authentication': ssh_server_globals_config_path + '/publickey-authentication',
        'max_auth_retries': ssh_server_globals_config_path + '/max-auth-retries',
        'disable_forwarding': ssh_server_globals_config_path + '/disable-forwarding',
        'permit_root_login': ssh_server_globals_config_path + '/permit-root-login',
        'permit_user_environment': ssh_server_globals_config_path + '/permit-user-environment',
        'permit_user_rc': ssh_server_globals_config_path + '/permit-user-rc',
        'x11_forwarding': ssh_server_globals_config_path + '/x11-forwarding',
        'ciphers': ssh_server_globals_config_path + '/ciphers',
        'kexalgorithms': ssh_server_globals_config_path + '/kexalgorithms',
        'macs': ssh_server_globals_config_path + '/macs',
        'hostkeyalgorithms': ssh_server_globals_config_path + '/hostkeyalgorithms',
    }

    command_param_request_map = {
        'password_authentication': 'password-authentication',
        'publickey_authentication': 'publickey-authentication',
        'max_auth_retries': 'max-auth-retries',
        'disable_forwarding': 'disable-forwarding',
        'permit_root_login': 'permit-root-login',
        'permit_user_environment': 'permit-user-environment',
        'permit_user_rc': 'permit-user-rc',
        'x11_forwarding': 'x11-forwarding',
        'ciphers': 'ciphers',
        'kexalgorithms': 'kexalgorithms',
        'macs': 'macs',
        'hostkeyalgorithms': 'hostkeyalgorithms',
    }

    def __init__(self, module):
        super(Ssh_server, self).__init__(module)

    def get_ssh_server_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        ssh_server_facts = facts['ansible_network_resources'].get('ssh_server')
        if not ssh_server_facts:
            return {}
        return ssh_server_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        commands = []

        existing_ssh_server_facts = self.get_ssh_server_facts()
        commands, requests = self.set_config(existing_ssh_server_facts)

        # Splitting the requests in mulitple calls, as ssh server global param updates will
        # result in ssh server restart. If the next call is done immediately
        # the request may fail based on the ssh server status.

        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    for request in requests:
                        edit_config(self._module, to_request(self._module, request))
                        time.sleep(4)
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_ssh_server_facts = self.get_ssh_server_facts()

        result['before'] = existing_ssh_server_facts
        if result['changed']:
            result['after'] = changed_ssh_server_facts

        new_config = changed_ssh_server_facts
        old_config = existing_ssh_server_facts
        if self._module.check_mode:

            result.pop('after', None)
            new_config = get_new_config(commands, existing_ssh_server_facts,
                                        TEST_KEYS_generate_config)

            result['after(generated)'] = new_config
        if self._module._diff:
            result['diff'] = get_formatted_config_diff(old_config, new_config, self._module._verbosity)

        return result

    def set_config(self, existing_ssh_server_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = remove_empties(self._module.params['config'])
        have = existing_ssh_server_facts
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

        commands, requests = self.handle_ssh_server_replaced_overridden(want, have)

        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = []
        requests = []

        server_commands, server_requests = self.handle_ssh_server_merged(want, have)
        requests.extend(server_requests)

        if server_commands and len(requests) > 0:
            commands = update_states(server_commands, 'merged')

        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        commands = []
        requests = []

        server_commands, server_requests = self.handle_ssh_server_deleted(want, have)
        requests.extend(server_requests)

        if server_commands and len(requests) > 0:
            commands = update_states(server_commands, "deleted")

        return commands, requests

    def handle_ssh_server_replaced_overridden(self, want, have):
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
            requests = self.delete_specific_ssh_server_params(commands)
            if not requests:
                commands = []
            else:
                commands = update_states(commands, "deleted")
        else:
            commands = []

        diff = get_diff(want, have)
        if diff:
            mod_commands = diff
            mod_requests = self.modify_specific_ssh_server_params(mod_commands)
            if mod_commands and len(mod_requests) > 0:
                mod_commands = update_states(mod_commands, state)
                commands.extend(mod_commands)
                requests.extend(mod_requests)

        return commands, requests

    def handle_ssh_server_merged(self, want, have):
        """Requests and commands necessary to merge the provided into
           the current configuration
        """
        commands = []
        requests = []

        diff = get_diff(want, have)
        commands = diff
        requests.extend(self.modify_specific_ssh_server_params(commands))

        return commands, requests

    def handle_ssh_server_deleted(self, want, have):
        """Requests and commands necessary to remove the current configuration
           of the provided objects
        """
        commands = []
        requests = []

        global delete_all
        delete_all = False
        if not want:
            commands = have
            delete_all = True
        else:
            diff = get_diff(want, have)
            commands = get_diff(want, diff)

        if commands:
            if delete_all:
                requests = self.delete_all_ssh_server_params()
            else:
                requests = self.delete_specific_ssh_server_params(commands)
        return commands, requests

    def modify_specific_ssh_server_params(self, commands):
        """Requests to modify specific SSH server configurations
        """
        requests = []
        command = commands.get('server_globals')

        if not command:
            return requests
        payload = {}
        for key in ['password_authentication', 'publickey_authentication',
                    'permit_root_login', 'permit_user_environment',
                    'disable_forwarding', 'max_auth_retries',
                    'permit_user_rc', 'x11_forwarding',
                    'ciphers', 'kexalgorithms', 'macs', 'hostkeyalgorithms']:
            if key in command and command[key] is not None:
                payload[f'{self.command_param_request_map[key]}'] = command[key]
            total_payload = {'openconfig-system-ext:config': payload}
        url = self.ssh_server_globals_config_path
        requests.append({'path': url, 'method': PATCH, 'data': total_payload})
        return requests

    def delete_all_ssh_server_params(self):
        """Requests to delete SSH server configurations on the chassis
        """
        requests = []
        requests.append({'path': self.ssh_server_globals_config_path, 'method': DELETE})

        return requests

    def delete_specific_ssh_server_params(self, commands):
        """Requests to delete specific SSH server configurations on the chassis
        """
        requests = []
        command = commands.get('server_globals')
        params = ['password_authentication', 'publickey_authentication',
                  'max_auth_retries', 'permit_root_login',
                  'permit_user_environment', 'disable_forwarding',
                  'permit_user_rc', 'x11_forwarding',
                  'ciphers', 'kexalgorithms', 'macs', 'hostkeyalgorithms']

        if not command:
            return requests

        for param in params:
            if param in command and command[param] is not None:
                if param not in default_config or command[param] != default_config[param]:
                    requests.append({'path': self.ssh_server_globals_param_config_path[param], 'method': DELETE})
                else:
                    command.pop(param)

        return requests
