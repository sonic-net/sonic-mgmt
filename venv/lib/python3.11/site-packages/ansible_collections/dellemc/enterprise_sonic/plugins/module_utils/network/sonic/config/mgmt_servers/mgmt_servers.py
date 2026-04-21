#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_mgmt_servers class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    remove_empties,
    update_states
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    edit_config,
    to_request
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    get_new_config,
    get_formatted_config_diff
)

SYS_PATH = '/data/openconfig-system:system'
PATCH = 'patch'
DELETE = 'delete'
default_cipher_suite = {'ecdhe-ecdsa-with-aes-256-gcm-SHA384', 'ecdhe-ecdsa-with-chacha20-poly1305-SHA256', 'ecdhe-ecdsa-with-aes-128-gcm-SHA256'}


def __derive_rest_delete_op(key_set, command, exist_conf):
    new_conf = exist_conf
    api_timeout = command.get('api_timeout')
    client_auth = command.get('client_auth')
    log_level = command.get('log_level')
    port = command.get('port')
    read_timeout = command.get('read_timeout')
    req_limit = command.get('req_limit')
    security_profile = command.get('security_profile')
    shutdown = command.get('shutdown')
    vrf = command.get('vrf')
    cipher_suite = command.get('cipher_suite')
    cfg_api_timeout = new_conf.get('api_timeout')
    cfg_client_auth = new_conf.get('client_auth')
    cfg_log_level = new_conf.get('log_level')
    cfg_port = new_conf.get('port')
    cfg_read_timeout = new_conf.get('read_timeout')
    cfg_req_limit = new_conf.get('req_limit')
    cfg_security_profile = new_conf.get('security_profile')
    cfg_shutdown = new_conf.get('shutdown')
    cfg_vrf = new_conf.get('vrf')
    cfg_cipher_suite = new_conf.get('cipher_suite')

    if api_timeout is not None and api_timeout == cfg_api_timeout and api_timeout != 900:
        new_conf['api_timeout'] = 900
    if client_auth and client_auth == cfg_client_auth and client_auth != 'password,jwt':
        new_conf['client_auth'] = 'password,jwt'
    if log_level is not None and log_level == cfg_log_level and log_level != 0:
        new_conf['log_level'] = 0
    if port is not None and port == cfg_port and port != 443:
        new_conf['port'] = 443
    if read_timeout is not None and read_timeout == cfg_read_timeout and read_timeout != 15:
        new_conf['read_timeout'] = 15
    if req_limit is not None and req_limit == cfg_req_limit:
        new_conf.pop('req_limit')
    if security_profile and security_profile == cfg_security_profile:
        new_conf.pop('security_profile')
    if shutdown is not None and shutdown == cfg_shutdown:
        new_conf.pop('shutdown')
    if vrf and vrf == cfg_vrf:
        new_conf.pop('vrf')
    if cipher_suite and cfg_cipher_suite:
        cipher_suite_set = set(cipher_suite.split(','))
        cfg_cipher_suite_set = set(cfg_cipher_suite.split(','))
        if cipher_suite_set == cfg_cipher_suite_set and default_cipher_suite != cipher_suite_set:
            new_conf['cipher_suite'] = ','.join(default_cipher_suite)

    return True, new_conf


def __derive_telemetry_delete_op(key_set, command, exist_conf):
    new_conf = exist_conf
    api_timeout = command.get('api_timeout')
    client_auth = command.get('client_auth')
    jwt_refresh = command.get('jwt_refresh')
    jwt_valid = command.get('jwt_valid')
    log_level = command.get('log_level')
    port = command.get('port')
    security_profile = command.get('security_profile')
    vrf = command.get('vrf')
    cfg_api_timeout = new_conf.get('api_timeout')
    cfg_client_auth = new_conf.get('client_auth')
    cfg_jwt_refresh = new_conf.get('jwt_refresh')
    cfg_jwt_valid = new_conf.get('jwt_valid')
    cfg_log_level = new_conf.get('log_level')
    cfg_port = new_conf.get('port')
    cfg_security_profile = new_conf.get('security_profile')
    cfg_vrf = new_conf.get('vrf')

    if api_timeout is not None and api_timeout == cfg_api_timeout and api_timeout != 0:
        new_conf['api_timeout'] = 0
    if client_auth and client_auth == cfg_client_auth and client_auth != 'password,jwt':
        new_conf['client_auth'] = 'password,jwt'
    if jwt_refresh is not None and jwt_refresh == cfg_jwt_refresh and jwt_refresh != 900:
        new_conf['jwt_refresh'] = 900
    if jwt_valid is not None and jwt_valid == cfg_jwt_valid and jwt_valid != 3600:
        new_conf['jwt_valid'] = 3600
    if log_level is not None and log_level == cfg_log_level and log_level != 0:
        new_conf['log_level'] = 0
    if port is not None and port == cfg_port and port != 8080:
        new_conf['port'] = 8080
    if security_profile and security_profile == cfg_security_profile:
        new_conf.pop('security_profile')
    if vrf and vrf == cfg_vrf:
        new_conf.pop('vrf')
    return True, new_conf


TEST_KEYS_generate_config = [
    {'rest': {'__delete_op': __derive_rest_delete_op}},
    {'telemetry': {'__delete_op': __derive_telemetry_delete_op}}
]


class Mgmt_servers(ConfigBase):
    """
    The sonic_mgmt_servers class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'mgmt_servers',
    ]

    def __init__(self, module):
        super(Mgmt_servers, self).__init__(module)

    def get_mgmt_servers_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        mgmt_servers_facts = facts['ansible_network_resources'].get('mgmt_servers')
        if not mgmt_servers_facts:
            return {}
        return mgmt_servers_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = []
        commands = []

        existing_mgmt_servers_facts = self.get_mgmt_servers_facts()
        commands, requests = self.set_config(existing_mgmt_servers_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_mgmt_servers_facts = self.get_mgmt_servers_facts()

        result['before'] = existing_mgmt_servers_facts
        if result['changed']:
            result['after'] = changed_mgmt_servers_facts

        new_config = changed_mgmt_servers_facts
        old_config = existing_mgmt_servers_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_mgmt_servers_facts, TEST_KEYS_generate_config)
            result['after(generated)'] = new_config
        if self._module._diff:
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)
        result['warnings'] = warnings
        return result

    def set_config(self, existing_mgmt_servers_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = remove_empties(self._module.params['config'])
        have = existing_mgmt_servers_facts
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

        if state == 'merged':
            commands, requests = self._state_merged(diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have, diff)
        elif state == 'overridden':
            commands, requests = self._state_overridden(want, have)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        return commands, requests

    def _state_merged(self, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        requests = self.get_modify_mgmt_servers_request(commands)

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
        commands = []
        mod_commands = []
        replaced_config, requests = self.get_replaced_config(want, have)

        if replaced_config:
            commands.extend(update_states(replaced_config, 'deleted'))
            mod_commands = want
        else:
            mod_commands = diff

        if mod_commands:
            mod_request = self.get_modify_mgmt_servers_request(mod_commands)

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

        new_have = deepcopy(have)
        if new_have and new_have != want:
            is_delete_all = True
            self.remove_default_entries(new_have)
            del_requests = self.get_delete_mgmt_servers_requests(new_have, new_have, is_delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(new_have, 'deleted'))
            new_have = []

        if not new_have and want:
            mod_commands = want
            mod_request = self.get_modify_mgmt_servers_request(mod_commands)

            if mod_request:
                requests.append(mod_request)
                commands.extend(update_states(mod_commands, 'overridden'))

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

        self.remove_default_entries(commands)
        requests = self.get_delete_mgmt_servers_requests(commands, have, is_delete_all)

        if commands and len(requests) > 0:
            commands = update_states(commands, 'deleted')
        else:
            commands = []

        return commands, requests

    def get_modify_mgmt_servers_request(self, commands):
        request = None

        if commands:
            sys_dict = {}
            rest = deepcopy(commands.get('rest'))
            telemetry = commands.get('telemetry')

            if rest:
                # Change from Ansible naming to OC naming
                if rest.get('shutdown') is not None:
                    rest['openconfig-system-mgmt-servers:disable'] = rest.get('shutdown')
                    rest.pop('shutdown')
                if rest.get('cipher_suite') is not None:
                    rest['cipher-suite'] = rest.get('cipher_suite')
                    rest.pop('cipher_suite')
                sys_dict['rest-server'] = {'config': rest}
            if telemetry:
                sys_dict['telemetry-server'] = {'config': telemetry}
            if sys_dict:
                payload = {'openconfig-system:system': sys_dict}
                request = {'path': SYS_PATH, 'method': PATCH, 'data': payload}

        return request

    def get_delete_mgmt_servers_requests(self, commands, have, is_delete_all):
        requests = []

        if not commands or not have:
            return requests
        if is_delete_all:
            requests.append(self.get_delete_request('rest-server', None))
            requests.append(self.get_delete_request('telemetry-server', None))
            return requests

        config_dict = {}
        # REST server deletion handling
        rest = commands.get('rest')
        if rest:
            api_timeout = rest.get('api_timeout')
            client_auth = rest.get('client_auth')
            log_level = rest.get('log_level')
            port = rest.get('port')
            read_timeout = rest.get('read_timeout')
            req_limit = rest.get('req_limit')
            security_profile = rest.get('security_profile')
            shutdown = rest.get('shutdown')
            vrf = rest.get('vrf')
            cipher_suite = rest.get('cipher_suite')

            cfg_rest = have.get('rest')
            if cfg_rest:
                rest_dict = {}
                cfg_api_timeout = cfg_rest.get('api_timeout')
                cfg_client_auth = cfg_rest.get('client_auth')
                cfg_log_level = cfg_rest.get('log_level')
                cfg_port = cfg_rest.get('port')
                cfg_read_timeout = cfg_rest.get('read_timeout')
                cfg_req_limit = cfg_rest.get('req_limit')
                cfg_security_profile = cfg_rest.get('security_profile')
                cfg_shutdown = cfg_rest.get('shutdown')
                cfg_vrf = cfg_rest.get('vrf')
                cfg_cipher_suite = cfg_rest.get('cipher_suite')

                if api_timeout is not None and api_timeout == cfg_api_timeout:
                    requests.append(self.get_delete_request('rest-server', 'api_timeout'))
                    rest_dict['api_timeout'] = api_timeout
                if client_auth and client_auth == cfg_client_auth:
                    requests.append(self.get_delete_request('rest-server', 'client_auth'))
                    rest_dict['client_auth'] = client_auth
                if log_level is not None and log_level == cfg_log_level:
                    requests.append(self.get_delete_request('rest-server', 'log_level'))
                    rest_dict['log_level'] = log_level
                if port is not None and port == cfg_port:
                    requests.append(self.get_delete_request('rest-server', 'port'))
                    rest_dict['port'] = port
                if read_timeout is not None and read_timeout == cfg_read_timeout:
                    requests.append(self.get_delete_request('rest-server', 'read_timeout'))
                    rest_dict['read_timeout'] = read_timeout
                if req_limit is not None and req_limit == cfg_req_limit:
                    requests.append(self.get_delete_request('rest-server', 'req_limit'))
                    rest_dict['req_limit'] = req_limit
                if security_profile and security_profile == cfg_security_profile:
                    requests.append(self.get_delete_request('rest-server', 'security_profile'))
                    rest_dict['security_profile'] = security_profile
                if shutdown is not None and shutdown == cfg_shutdown:
                    requests.append(self.get_delete_request('rest-server', 'openconfig-system-mgmt-servers:disable'))
                    rest_dict['shutdown'] = shutdown
                if vrf and vrf == cfg_vrf:
                    requests.append(self.get_delete_request('rest-server', 'vrf'))
                    rest_dict['vrf'] = vrf
                if cipher_suite and cfg_cipher_suite:
                    cipher_suite_set = set(cipher_suite.split(','))
                    cfg_cipher_suite_set = set(cfg_cipher_suite.split(','))
                    if cipher_suite_set == cfg_cipher_suite_set:
                        requests.append(self.get_delete_request('rest-server', 'cipher-suite'))
                        rest_dict['cipher_suite'] = cipher_suite
                if rest_dict:
                    config_dict['rest'] = rest_dict

        # Telemetry server deletion handling
        telemetry = commands.get('telemetry')
        if telemetry:
            api_timeout = telemetry.get('api_timeout')
            client_auth = telemetry.get('client_auth')
            jwt_refresh = telemetry.get('jwt_refresh')
            jwt_valid = telemetry.get('jwt_valid')
            log_level = telemetry.get('log_level')
            port = telemetry.get('port')
            security_profile = telemetry.get('security_profile')
            vrf = telemetry.get('vrf')

            cfg_telemetry = have.get('telemetry')
            if cfg_telemetry:
                telemetry_dict = {}
                cfg_api_timeout = cfg_telemetry.get('api_timeout')
                cfg_client_auth = cfg_telemetry.get('client_auth')
                cfg_jwt_refresh = cfg_telemetry.get('jwt_refresh')
                cfg_jwt_valid = cfg_telemetry.get('jwt_valid')
                cfg_log_level = cfg_telemetry.get('log_level')
                cfg_port = cfg_telemetry.get('port')
                cfg_security_profile = cfg_telemetry.get('security_profile')
                cfg_vrf = cfg_telemetry.get('vrf')

                if api_timeout is not None and api_timeout == cfg_api_timeout:
                    requests.append(self.get_delete_request('telemetry-server', 'api_timeout'))
                    telemetry_dict['api_timeout'] = api_timeout
                if client_auth and client_auth == cfg_client_auth:
                    requests.append(self.get_delete_request('telemetry-server', 'client_auth'))
                    telemetry_dict['client_auth'] = client_auth
                if jwt_refresh is not None and jwt_refresh == cfg_jwt_refresh:
                    requests.append(self.get_delete_request('telemetry-server', 'jwt_refresh'))
                    telemetry_dict['jwt_refresh'] = jwt_refresh
                if jwt_valid is not None and jwt_valid == cfg_jwt_valid:
                    requests.append(self.get_delete_request('telemetry-server', 'jwt_valid'))
                    telemetry_dict['jwt_valid'] = jwt_valid
                if log_level is not None and log_level == cfg_log_level:
                    requests.append(self.get_delete_request('telemetry-server', 'log_level'))
                    telemetry_dict['log_level'] = log_level
                if port is not None and port == cfg_port:
                    requests.append(self.get_delete_request('telemetry-server', 'port'))
                    telemetry_dict['port'] = port
                if security_profile and security_profile == cfg_security_profile:
                    requests.append(self.get_delete_request('telemetry-server', 'security_profile'))
                    telemetry_dict['security_profile'] = security_profile
                if vrf and vrf == cfg_vrf:
                    requests.append(self.get_delete_request('telemetry-server', 'vrf'))
                    telemetry_dict['security_profile'] = vrf
                if telemetry:
                    config_dict['telemetry'] = telemetry

        commands = config_dict
        return requests

    def get_delete_request(self, server, attr):
        url = '%s/%s' % (SYS_PATH, server)

        if attr:
            url += '/config/%s' % (attr)
        request = {'path': url, 'method': DELETE}
        return request

    def remove_default_entries(self, data):
        rest = data.get('rest')
        telemetry = data.get('telemetry')

        if rest:
            if rest.get('api_timeout') == 900:
                data['rest'].pop('api_timeout')
            if rest.get('client_auth') == 'password,jwt':
                data['rest'].pop('client_auth')
            if rest.get('log_level') == 0:
                data['rest'].pop('log_level')
            if rest.get('port') == 443:
                data['rest'].pop('port')
            if rest.get('read_timeout') == 15:
                data['rest'].pop('read_timeout')
            if rest.get('cipher_suite') is not None:
                cipher_suite = set(rest.get('cipher_suite').split(','))
                if default_cipher_suite == cipher_suite:
                    data['rest'].pop('cipher_suite')
            if not rest:
                data.pop('rest')
        if telemetry:
            if telemetry.get('api_timeout') == 0:
                data['telemetry'].pop('api_timeout')
            if telemetry.get('client_auth') == 'password,jwt':
                data['telemetry'].pop('client_auth')
            if telemetry.get('jwt_refresh') == 900:
                data['telemetry'].pop('jwt_refresh')
            if telemetry.get('jwt_valid') == 3600:
                data['telemetry'].pop('jwt_valid')
            if telemetry.get('log_level') == 0:
                data['telemetry'].pop('log_level')
            if telemetry.get('port') == 8080:
                data['telemetry'].pop('port')
            if not telemetry:
                data.pop('telemetry')

    def get_replaced_config(self, want, have):
        config_dict = {}
        requests = []
        rest = want.get('rest')
        telemetry = want.get('telemetry')
        cfg_rest = have.get('rest')
        cfg_telemetry = have.get('telemetry')

        if rest and cfg_rest and rest != cfg_rest:
            config_dict['rest'] = cfg_rest
            requests.append(self.get_delete_request('rest-server', None))
        if telemetry and cfg_telemetry and telemetry != cfg_telemetry:
            config_dict['telemetry'] = cfg_telemetry
            requests.append(self.get_delete_request('telemetry-server', None))

        return config_dict, requests
