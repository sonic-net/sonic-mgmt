#
# -*- coding: utf-8 -*-
# Copyright 2022 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_ntp class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    get_replaced_config,
    update_states,
    normalize_interface_name_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_CONFIG_IF_NO_SUBCONFIG,
    __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF,
    get_new_config,
    get_formatted_config_diff
)

from ansible.module_utils.connection import ConnectionError

PATCH = 'PATCH'
DELETE = 'DELETE'

TEST_KEYS = [
    {"servers": {"address": ""}},
    {"ntp_keys": {"key_id": ""}}
]
TEST_KEYS_formatted_diff = [
    {'config': {'__delete_op': __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF}},
    {"servers": {"address": "", '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {"ntp_keys": {"key_id": "", '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}}
]


class Ntp(ConfigBase):
    """
    The sonic_ntp class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'ntp',
    ]

    def __init__(self, module):
        super(Ntp, self).__init__(module)

    def get_ntp_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        ntp_facts = facts['ansible_network_resources'].get('ntp')

        if not ntp_facts:
            return []
        return ntp_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        commands = list()
        requests = list()

        existing_ntp_facts = self.get_ntp_facts()

        commands, requests = self.set_config(existing_ntp_facts)

        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_ntp_facts = self.get_ntp_facts()

        result['before'] = existing_ntp_facts
        if result['changed']:
            result['after'] = changed_ntp_facts

        new_config = changed_ntp_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_ntp_facts,
                                        TEST_KEYS_formatted_diff)
            result['after(generated)'] = new_config

        if self._module._diff:
            result['diff'] = get_formatted_config_diff(existing_ntp_facts,
                                                       new_config,
                                                       self._module._verbosity)
        result['warnings'] = warnings
        return result

    def set_config(self, existing_ntp_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        if want is None:
            want = {}

        have = existing_ntp_facts

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

        self.validate_want(want, state)
        self.preprocess_want(want, state)

        if state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have)
        elif state == 'overridden':
            commands, requests = self._state_overridden(want, have)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have)

        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :param want: the additive configuration as a dictionary
        :param have: the current configuration as a dictionary
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        diff = get_diff(want, have, TEST_KEYS)

        commands = diff
        requests = []

        self.preprocess_merge_commands(commands, want)
        if commands:
            requests = self.get_merge_requests(commands, have)

        if len(requests) > 0:
            commands = update_states(commands, "merged")
        else:
            commands = []

        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :param want: the objects from which the configuration should be removed
        :param have: the current configuration as a dictionary
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        diff = get_diff(want, have, TEST_KEYS)

        want_none = {'enable_ntp_auth': None, 'ntp_keys': None,
                     'servers': None, 'source_interfaces': [],
                     'trusted_keys': None, 'vrf': None}
        want_any = get_diff(want, want_none, TEST_KEYS)
        # if want_any is none, then delete all NTP configurations

        delete_all = False
        if not want_any:
            commands = have
            delete_all = True
        else:
            if not diff:
                commands = want_any
            else:
                commands = get_diff(want_any, diff, TEST_KEYS)

        requests = []
        if commands:
            requests = self.get_delete_requests(commands, delete_all)

        if len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []

        return commands, requests

    def _state_replaced(self, want, have):
        """ The command generator when state is replaced

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :param diff: the difference between want and have
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []
        replaced_config = get_replaced_config(want, have, TEST_KEYS)

        add_commands = []
        if replaced_config:
            self.sort_lists_in_config(replaced_config)
            self.sort_lists_in_config(have)
            delete_all = (replaced_config == have)
            del_requests = self.get_delete_requests(replaced_config, delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(replaced_config, "deleted"))

            add_commands = want
        else:
            diff = get_diff(want, have, TEST_KEYS)
            add_commands = diff

        if add_commands:
            self.preprocess_merge_commands(add_commands, want)
            add_requests = self.get_merge_requests(add_commands, have)

            if len(add_requests) > 0:
                requests.extend(add_requests)
                commands.extend(update_states(add_commands, "replaced"))

        return commands, requests

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :param diff: the difference between want and have
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        self.sort_lists_in_config(want)
        self.sort_lists_in_config(have)

        commands = []
        requests = []

        if have and have != want:
            delete_all = True
            del_requests = self.get_delete_requests(have, delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(have, "deleted"))
            have = []

        if not have and want:
            add_commands = want
            add_requests = self.get_merge_requests(add_commands, have)

            if len(add_requests) > 0:
                requests.extend(add_requests)
                commands.extend(update_states(add_commands, "overridden"))

        return commands, requests

    def validate_want(self, want, state):

        if state == 'deleted':
            if 'servers' in want and want['servers'] is not None:
                for server in want['servers']:
                    key_id_config = server.get('key_id', None)
                    minpoll_config = server.get('minpoll', None)
                    maxpoll_config = server.get('maxpoll', None)
                    prefer_config = server.get('prefer', None)
                    if key_id_config or minpoll_config or maxpoll_config or \
                       prefer_config is not None:
                        err_msg = "NTP server parameter(s) can not be deleted."
                        self._module.fail_json(msg=err_msg, code=405)

            if 'ntp_keys' in want and want['ntp_keys'] is not None:
                for ntp_key in want['ntp_keys']:
                    encrypted_config = ntp_key.get('encrypted', None)
                    key_type_config = ntp_key.get('key_type', None)
                    key_value_config = ntp_key.get('key_value', None)
                    if encrypted_config or key_type_config or key_value_config:
                        err_msg = "NTP ntp_key parameter(s) can not be deleted."
                        self._module.fail_json(msg=err_msg, code=405)

    def preprocess_want(self, want, state):

        if 'source_interfaces' in want:
            want['source_interfaces'] = normalize_interface_name_list(want['source_interfaces'], self._module)

        if state == 'deleted':
            enable_auth_want = want.get('enable_ntp_auth', None)
            if enable_auth_want is not None:
                want['enable_ntp_auth'] = True

        elif state == 'merged':
            if 'servers' in want and want['servers'] is not None:
                for server in want['servers']:
                    if 'key_id' in server and not server['key_id']:
                        server.pop('key_id')
                    if 'minpoll' in server and not server['minpoll']:
                        server.pop('minpoll')
                    if 'maxpoll' in server and not server['maxpoll']:
                        server.pop('maxpoll')
                    if 'prefer' in server and server['prefer'] is None:
                        server.pop('prefer')

        if state == 'replaced' or state == 'overridden':
            enable_auth_want = want.get('enable_ntp_auth', None)
            if enable_auth_want is None:
                want['enable_ntp_auth'] = False
            if 'servers' in want and want['servers'] is not None:
                for server in want['servers']:
                    if 'prefer' in server and server['prefer'] is None:
                        server['prefer'] = False

    def search_servers(self, svr_address, servers):

        found_server = dict()
        if servers is not None:
            for server in servers:
                if server['address'] == svr_address:
                    found_server = server
        return found_server

    def preprocess_merge_commands(self, commands, want):

        if 'servers' in commands and commands['servers'] is not None:
            for server in commands['servers']:
                if 'minpoll' in server and 'maxpoll' not in server:
                    want_server = dict()
                    if 'servers' in want:
                        want_server = self.search_servers(server['address'], want['servers'])

                    if want_server:
                        server['maxpoll'] = want_server['maxpoll']
                    else:
                        err_msg = "Internal error with NTP server maxpoll configuration."
                        self._module.fail_json(msg=err_msg, code=500)

                if 'maxpoll' in server and 'minpoll' not in server:
                    want_server = dict()
                    if 'servers' in want:
                        want_server = self.search_servers(server['address'], want['servers'])

                    if want_server:
                        server['minpoll'] = want_server['minpoll']
                    else:
                        err_msg = "Internal error with NTP server minpoll configuration."
                        self._module.fail_json(msg=err_msg, code=500)

    def get_merge_requests(self, configs, have):

        requests = []

        enable_auth_config = configs.get('enable_ntp_auth', None)
        if enable_auth_config is not None:
            enable_auth_request = self.get_create_enable_ntp_auth_requests(enable_auth_config, have)
            if enable_auth_request:
                requests.extend(enable_auth_request)

        src_intf_config = configs.get('source_interfaces', None)
        if src_intf_config:
            src_intf_request = self.get_create_source_interface_requests(src_intf_config, have)
            if src_intf_request:
                requests.extend(src_intf_request)

        keys_config = configs.get('ntp_keys', None)
        if keys_config:
            keys_request = self.get_create_keys_requests(keys_config, have)
            if keys_request:
                requests.extend(keys_request)

        servers_config = configs.get('servers', None)
        if servers_config:
            servers_request = self.get_create_servers_requests(servers_config, have)
            if servers_request:
                requests.extend(servers_request)

        trusted_key_config = configs.get('trusted_keys', None)
        if trusted_key_config:
            trusted_key_request = self.get_create_trusted_key_requests(trusted_key_config, have)
            if trusted_key_request:
                requests.extend(trusted_key_request)

        vrf_config = configs.get('vrf', None)
        if vrf_config:
            vrf_request = self.get_create_vrf_requests(vrf_config, have)
            if vrf_request:
                requests.extend(vrf_request)

        return requests

    def get_delete_requests(self, configs, delete_all):

        requests = []

        if delete_all:
            all_ntp_request = self.get_delete_all_ntp_requests(configs)
            if all_ntp_request:
                requests.extend(all_ntp_request)
            return requests

        src_intf_config = configs.get('source_interfaces', None)
        if src_intf_config:
            src_intf_request = self.get_delete_source_interface_requests(src_intf_config)
            if src_intf_request:
                requests.extend(src_intf_request)

        servers_config = configs.get('servers', None)
        if servers_config:
            servers_request = self.get_delete_servers_requests(servers_config)
            if servers_request:
                requests.extend(servers_request)

        trusted_key_config = configs.get('trusted_keys', None)
        if trusted_key_config:
            trusted_key_request = self.get_delete_trusted_key_requests(trusted_key_config)
            if trusted_key_request:
                requests.extend(trusted_key_request)

        keys_config = configs.get('ntp_keys', None)
        if keys_config:
            keys_request = self.get_delete_keys_requests(keys_config)
            if keys_request:
                requests.extend(keys_request)

        enable_auth_config = configs.get('enable_ntp_auth', None)
        if enable_auth_config is not None:
            enable_auth_request = self.get_delete_enable_ntp_auth_requests(enable_auth_config)
            if enable_auth_request:
                requests.extend(enable_auth_request)

        vrf_config = configs.get('vrf', None)
        if vrf_config:
            vrf_request = self.get_delete_vrf_requests(vrf_config)
            if vrf_request:
                requests.extend(vrf_request)

        return requests

    def get_create_source_interface_requests(self, configs, have):

        requests = []

        # Create URL and payload
        method = PATCH
        url = 'data/openconfig-system:system/ntp/config/source-interface'
        payload = {"openconfig-system:source-interface": configs}
        request = {"path": url, "method": method, "data": payload}
        requests.append(request)

        return requests

    def get_create_servers_requests(self, configs, have):

        requests = []

        # Create URL and payload
        method = PATCH
        url = 'data/openconfig-system:system/ntp/servers'
        server_configs = []
        for config in configs:
            if 'key_id' in config:
                config['key-id'] = config['key_id']
                config.pop('key_id')
            server_addr = config['address']
            server_config = {"address": server_addr, "config": config}
            server_configs.append(server_config)

        payload = {"openconfig-system:servers": {"server": server_configs}}
        request = {"path": url, "method": method, "data": payload}
        requests.append(request)

        return requests

    def get_create_vrf_requests(self, configs, have):

        requests = []

        # Create URL and payload
        method = PATCH
        url = 'data/openconfig-system:system/ntp/config/network-instance'
        payload = {"openconfig-system:network-instance": configs}
        request = {"path": url, "method": method, "data": payload}
        requests.append(request)

        return requests

    def get_create_enable_ntp_auth_requests(self, configs, have):

        requests = []

        # Create URL and payload
        method = PATCH
        url = 'data/openconfig-system:system/ntp/config/enable-ntp-auth'
        payload = {"openconfig-system:enable-ntp-auth": configs}
        request = {"path": url, "method": method, "data": payload}
        requests.append(request)

        return requests

    def get_create_trusted_key_requests(self, configs, have):

        requests = []

        # Create URL and payload
        method = PATCH
        url = 'data/openconfig-system:system/ntp/config/trusted-key'
        payload = {"openconfig-system:trusted-key": configs}
        request = {"path": url, "method": method, "data": payload}
        requests.append(request)

        return requests

    def get_create_keys_requests(self, configs, have):

        requests = []

        # Create URL and payload
        method = PATCH
        url = 'data/openconfig-system:system/ntp/ntp-keys'
        key_configs = []
        for config in configs:
            key_id = config['key_id']
            if 'key_id' in config:
                config['key-id'] = config['key_id']
                config.pop('key_id')
            if 'key_type' in config:
                config['key-type'] = config['key_type']
                config.pop('key_type')
            if 'key_value' in config:
                config['key-value'] = config['key_value']
                config.pop('key_value')

            key_config = {"key-id": key_id, "config": config}
            key_configs.append(key_config)

        payload = {"openconfig-system:ntp-keys": {"ntp-key": key_configs}}
        request = {"path": url, "method": method, "data": payload}
        requests.append(request)

        return requests

    def get_delete_all_ntp_requests(self, configs):

        requests = []

        # Create URL and payload
        method = DELETE

        src_intf_config = configs.get('source_interfaces', None)
        vrf_config = configs.get('vrf', None)
        enable_auth_config = configs.get('enable_ntp_auth', None)
        trusted_key_config = configs.get('trusted_keys', None)

        if src_intf_config or vrf_config or \
           trusted_key_config or enable_auth_config is not None:
            url = 'data/openconfig-system:system/ntp'
            request = {"path": url, "method": method}
            requests.append(request)

        servers_config = configs.get('servers', None)
        if servers_config:
            url = 'data/openconfig-system:system/ntp/servers'
            request = {"path": url, "method": method}
            requests.append(request)

        keys_config = configs.get('ntp_keys', None)
        if keys_config:
            url = 'data/openconfig-system:system/ntp/ntp-keys'
            request = {"path": url, "method": method}
            requests.append(request)

        return requests

    def get_delete_source_interface_requests(self, configs):

        requests = []

        # Create URL and payload
        method = DELETE
        for config in configs:
            url = 'data/openconfig-system:system/ntp/config/source-interface={0}'.format(config)
            request = {"path": url, "method": method}
            requests.append(request)

        return requests

    def get_delete_servers_requests(self, configs):

        requests = []

        # Create URL and payload
        method = DELETE
        for config in configs:
            server_addr = config['address']
            url = 'data/openconfig-system:system/ntp/servers/server={0}'.format(server_addr)
            request = {"path": url, "method": method}
            requests.append(request)

        return requests

    def get_delete_vrf_requests(self, configs):

        requests = []

        # Create URL and payload
        method = DELETE
        url = 'data/openconfig-system:system/ntp/config/network-instance'
        request = {"path": url, "method": method}
        requests.append(request)

        return requests

    def get_delete_enable_ntp_auth_requests(self, configs):

        requests = []

        # Create URL and payload
        method = DELETE
        url = 'data/openconfig-system:system/ntp/config/enable-ntp-auth'
        request = {"path": url, "method": method}
        requests.append(request)

        return requests

    def get_delete_trusted_key_requests(self, configs):

        requests = []

        # Create URL and payload
        method = DELETE
        for config in configs:
            url = 'data/openconfig-system:system/ntp/config/trusted-key={0}'.format(config)
            request = {"path": url, "method": method}
            requests.append(request)

        return requests

    def get_delete_keys_requests(self, configs):

        requests = []

        # Create URL and payload
        method = DELETE
        key_configs = []
        for config in configs:
            key_id = config['key_id']
            url = 'data/openconfig-system:system/ntp/ntp-keys/ntp-key={0}'.format(key_id)
            request = {"path": url, "method": method}
            requests.append(request)

        return requests

    def get_server_address(self, ntp_server):
        return ntp_server.get('address')

    def get_ntp_key_id(self, ntp_key):
        return ntp_key.get('key_id')

    def sort_lists_in_config(self, config):

        if 'source_interfaces' in config and config['source_interfaces'] is not None:
            config['source_interfaces'].sort()
        if 'servers' in config and config['servers'] is not None:
            config['servers'].sort(key=self.get_server_address)
        if 'trusted_keys' in config and config['trusted_keys'] is not None:
            config['trusted_keys'].sort()
        if 'ntp_keys' in config and config['ntp_keys'] is not None:
            config['ntp_keys'].sort(key=self.get_ntp_key_id)
