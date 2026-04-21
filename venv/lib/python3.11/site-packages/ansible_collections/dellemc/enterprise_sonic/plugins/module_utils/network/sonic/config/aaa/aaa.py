#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_aaa class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

from time import sleep

from copy import deepcopy
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
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


AAA_AUTHENTICATION_PATH = '/data/openconfig-system:system/aaa/authentication/config'
AAA_AUTHORIZATION_PATH = '/data/openconfig-system:system/aaa/authorization'
AAA_NAME_SERVICE_PATH = '/data/openconfig-system:system/aaa/openconfig-aaa-ext:name-service/config'
PATCH = 'patch'
DELETE = 'delete'


class Aaa(ConfigBase):
    """
    The sonic_aaa class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'aaa',
    ]

    def __init__(self, module):
        super(Aaa, self).__init__(module)

    def get_aaa_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        aaa_facts = facts['ansible_network_resources'].get('aaa')
        if not aaa_facts:
            return {}
        return aaa_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = []
        commands = []
        existing_aaa_facts = self.get_aaa_facts()

        commands, requests = self.set_config(existing_aaa_facts)

        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                    # Wait for AAA config updates to be applied to PAM modules
                    sleep(4)
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_aaa_facts = self.get_aaa_facts()

        result['before'] = existing_aaa_facts
        if result['changed']:
            result['after'] = changed_aaa_facts

        new_config = changed_aaa_facts
        old_config = existing_aaa_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_aaa_facts)
            self.post_process_generated_config(new_config)
            result['after(generated)'] = new_config
        if self._module._diff:
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)
        result['warnings'] = warnings
        return result

    def set_config(self, existing_aaa_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = remove_empties(self._module.params['config'])
        have = existing_aaa_facts
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
        diff = self.get_diff_aaa(want, have)

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
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        requests = self.get_modify_aaa_requests(commands)

        if commands and len(requests) > 0:
            commands = update_states(commands, 'merged')
        else:
            commands = []

        return commands, requests

    def _state_replaced(self, want, have, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = []
        mod_commands = None
        requests = []
        new_have = deepcopy(have)
        replaced_config = self.get_replaced_config(want, new_have)

        if replaced_config:
            is_delete_all = replaced_config == new_have
            del_requests = self.get_delete_aaa_requests(replaced_config, is_delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(replaced_config, 'deleted'))
            mod_commands = want
        else:
            mod_commands = diff

        if mod_commands:
            mod_requests = self.get_modify_aaa_requests(mod_commands)
            if mod_requests:
                requests.extend(mod_requests)
                commands.extend(update_states(mod_commands, 'replaced'))

        return commands, requests

    def _state_overridden(self, want, have, diff):
        """ The command generator when state is overridden
        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :param diff: the difference between want and have
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []
        mod_commands = None
        mod_requests = None
        del_commands = self.get_diff_aaa(have, want)
        self.remove_default_entries(del_commands)

        if not del_commands and diff:
            mod_commands = diff
            mod_requests = self.get_modify_aaa_requests(mod_commands)

        if del_commands:
            is_delete_all = True
            del_requests = self.get_delete_aaa_requests(del_commands, is_delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(have, 'deleted'))
            mod_commands = want
            mod_requests = self.get_modify_aaa_requests(mod_commands)

        if mod_requests:
            requests.extend(mod_requests)
            commands.extend(update_states(mod_commands, 'overridden'))

        return commands, requests

    def _state_deleted(self, want, have, diff):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        is_delete_all = False
        requests = []

        if not want:
            commands = deepcopy(have)
            is_delete_all = True
        else:
            commands = self.get_diff_aaa(want, diff)

        self.remove_default_entries(commands)
        if commands:
            requests = self.get_delete_aaa_requests(commands, is_delete_all)
            if len(requests) > 0:
                commands = update_states(commands, 'deleted')
        else:
            commands = []

        return commands, requests

    def get_modify_aaa_requests(self, commands):
        requests = []
        mfa_dict = {False: 'disable', True: 'enable'}

        if commands:
            # Authentication modification handling
            authentication = commands.get('authentication')
            if authentication:
                authentication_cfg_dict = {}
                auth_method = authentication.get('auth_method')
                console_auth_local = authentication.get('console_auth_local')
                failthrough = authentication.get('failthrough')
                mfa_auth_method = authentication.get('mfa_auth_method')
                login_mfa_console = authentication.get('login_mfa_console')

                if auth_method:
                    authentication_cfg_dict['authentication-method'] = auth_method
                if console_auth_local is not None:
                    authentication_cfg_dict['console-authentication-local'] = console_auth_local
                if failthrough is not None:
                    authentication_cfg_dict['failthrough'] = str(failthrough)
                if mfa_auth_method:
                    authentication_cfg_dict['openconfig-mfa:mfa-authentication-method'] = mfa_auth_method
                if login_mfa_console is not None:
                    authentication_cfg_dict['openconfig-mfa:login-mfa-console'] = mfa_dict[login_mfa_console]
                if authentication_cfg_dict:
                    payload = {'openconfig-system:config': authentication_cfg_dict}
                    requests.append({'path': AAA_AUTHENTICATION_PATH, 'method': PATCH, 'data': payload})

            # Authorization modification handling
            authorization = commands.get('authorization')
            if authorization:
                authorization_dict = {}
                commands_auth_method = authorization.get('commands_auth_method')
                login_auth_method = authorization.get('login_auth_method')

                if commands_auth_method:
                    authorization_dict['openconfig-aaa-tacacsplus-ext:commands'] = {'config': {'authorization-method': commands_auth_method}}
                if login_auth_method:
                    authorization_dict['openconfig-aaa-ext:login'] = {'config': {'authorization-method': login_auth_method}}
                if authorization_dict:
                    payload = {'openconfig-system:authorization': authorization_dict}
                    requests.append({'path': AAA_AUTHORIZATION_PATH, 'method': PATCH, 'data': payload})

            # Name-service modification handling
            name_service = commands.get('name_service')
            if name_service:
                name_service_cfg_dict = {}
                group = name_service.get('group')
                netgroup = name_service.get('netgroup')
                passwd = name_service.get('passwd')
                shadow = name_service.get('shadow')
                sudoers = name_service.get('sudoers')

                if group:
                    name_service_cfg_dict['group-method'] = group
                if netgroup:
                    name_service_cfg_dict['netgroup-method'] = netgroup
                if passwd:
                    name_service_cfg_dict['passwd-method'] = passwd
                if shadow:
                    name_service_cfg_dict['shadow-method'] = shadow
                if sudoers:
                    name_service_cfg_dict['sudoers-method'] = sudoers
                if name_service_cfg_dict:
                    payload = {'openconfig-aaa-ext:config': name_service_cfg_dict}
                    requests.append({'path': AAA_NAME_SERVICE_PATH, 'method': PATCH, 'data': payload})

        return requests

    def get_delete_aaa_requests(self, commands, is_delete_all):
        requests = []

        if not commands:
            return requests

        if is_delete_all:
            requests.append(self.get_delete_request(AAA_AUTHENTICATION_PATH, None))
            requests.append(self.get_delete_request(AAA_AUTHORIZATION_PATH, None))
            requests.append(self.get_delete_request(AAA_NAME_SERVICE_PATH, None))
            return requests

        # Authentication deletion handling
        authentication = commands.get('authentication')
        if authentication:
            auth_method = authentication.get('auth_method')
            console_auth_local = authentication.get('console_auth_local')
            failthrough = authentication.get('failthrough')
            mfa_auth_method = authentication.get('mfa_auth_method')
            login_mfa_console = authentication.get('login_mfa_console')

            # Current SONiC behavior doesn't support single list item deletion
            if auth_method:
                requests.append(self.get_delete_request(AAA_AUTHENTICATION_PATH, 'authentication-method'))
            # Default is false
            if console_auth_local:
                requests.append(self.get_delete_request(AAA_AUTHENTICATION_PATH, 'console-authentication-local'))
            if failthrough is not None:
                requests.append(self.get_delete_request(AAA_AUTHENTICATION_PATH, 'failthrough'))
            if mfa_auth_method:
                requests.append(self.get_delete_request(AAA_AUTHENTICATION_PATH, 'openconfig-mfa:mfa-authentication-method'))
            if login_mfa_console is not None:
                requests.append(self.get_delete_request(AAA_AUTHENTICATION_PATH, 'openconfig-mfa:login-mfa-console'))

        # Authorization deletion handling
        authorization = commands.get('authorization')
        if authorization:
            commands_auth_method = authorization.get('commands_auth_method')
            login_auth_method = authorization.get('login_auth_method')

            # Current SONiC behavior doesn't support single list item deletion
            if commands_auth_method:
                requests.append(self.get_delete_request(AAA_AUTHORIZATION_PATH,
                                                        'openconfig-aaa-tacacsplus-ext:commands/config/authorization-method'))
            if login_auth_method:
                requests.append(self.get_delete_request(AAA_AUTHORIZATION_PATH, 'openconfig-aaa-ext:login/config/authorization-method'))

        # Name-service deletion handling
        name_service = commands.get('name_service')
        if name_service:
            group = name_service.get('group')
            netgroup = name_service.get('netgroup')
            passwd = name_service.get('passwd')
            shadow = name_service.get('shadow')
            sudoers = name_service.get('sudoers')

            # Current SONiC behavior doesn't support single list item deletion
            if group:
                requests.append(self.get_delete_request(AAA_NAME_SERVICE_PATH, 'group-method'))
            if netgroup:
                requests.append(self.get_delete_request(AAA_NAME_SERVICE_PATH, 'netgroup-method'))
            if passwd:
                requests.append(self.get_delete_request(AAA_NAME_SERVICE_PATH, 'passwd-method'))
            if shadow:
                requests.append(self.get_delete_request(AAA_NAME_SERVICE_PATH, 'shadow-method'))
            if sudoers:
                requests.append(self.get_delete_request(AAA_NAME_SERVICE_PATH, 'sudoers-method'))

        return requests

    def get_delete_request(self, url, attr):
        if attr:
            url += '/%s' % (attr)
        request = {'path': url, 'method': DELETE}
        return request

    def get_diff_aaa(self, base_cfg, compare_cfg):
        """AAA module requires custom diff method due to overwriting of list in SONiC"""
        if not compare_cfg:
            return base_cfg

        cfg_dict = {}
        # Authentication diff handling
        authentication = base_cfg.get('authentication')
        if authentication:
            auth_method = authentication.get('auth_method')
            console_auth_local = authentication.get('console_auth_local')
            failthrough = authentication.get('failthrough')
            mfa_auth_method = authentication.get('mfa_auth_method')
            login_mfa_console = authentication.get('login_mfa_console')

            compare_authentication = compare_cfg.get('authentication')
            if compare_authentication:
                authentication_dict = {}
                compare_auth_method = compare_authentication.get('auth_method')
                compare_console_auth_local = compare_authentication.get('console_auth_local')
                compare_failthrough = compare_authentication.get('failthrough')
                compare_mfa_auth_method = compare_authentication.get('mfa_auth_method')
                compare_login_mfa_console = compare_authentication.get('login_mfa_console')

                if auth_method and auth_method != compare_auth_method:
                    authentication_dict['auth_method'] = auth_method
                if console_auth_local is not None and console_auth_local != compare_console_auth_local:
                    authentication_dict['console_auth_local'] = console_auth_local
                if failthrough is not None and failthrough != compare_failthrough:
                    authentication_dict['failthrough'] = failthrough
                if mfa_auth_method and mfa_auth_method != compare_mfa_auth_method:
                    authentication_dict['mfa_auth_method'] = mfa_auth_method
                if login_mfa_console is not None and login_mfa_console != compare_login_mfa_console:
                    authentication_dict['login_mfa_console'] = login_mfa_console
                if authentication_dict:
                    cfg_dict['authentication'] = authentication_dict
            else:
                cfg_dict['authentication'] = authentication

        # Authorization diff handling
        authorization = base_cfg.get('authorization')
        if authorization:
            commands_auth_method = authorization.get('commands_auth_method')
            login_auth_method = authorization.get('login_auth_method')

            compare_authorization = compare_cfg.get('authorization')
            if compare_authorization:
                authorization_dict = {}
                compare_commands_auth_method = compare_authorization.get('commands_auth_method')
                compare_login_auth_method = compare_authorization.get('login_auth_method')

                if commands_auth_method and commands_auth_method != compare_commands_auth_method:
                    authorization_dict['commands_auth_method'] = commands_auth_method
                if login_auth_method and login_auth_method != compare_login_auth_method:
                    authorization_dict['login_auth_method'] = login_auth_method
                if authorization_dict:
                    cfg_dict['authorization'] = authorization_dict
            else:
                cfg_dict['authorization'] = authorization

        # Name-service diff handling
        name_service = base_cfg.get('name_service')
        if name_service:
            group = name_service.get('group')
            netgroup = name_service.get('netgroup')
            passwd = name_service.get('passwd')
            shadow = name_service.get('shadow')
            sudoers = name_service.get('sudoers')

            compare_name_service = compare_cfg.get('name_service')
            if compare_name_service:
                name_service_dict = {}
                compare_group = compare_name_service.get('group')
                compare_netgroup = compare_name_service.get('netgroup')
                compare_passwd = compare_name_service.get('passwd')
                compare_shadow = compare_name_service.get('shadow')
                compare_sudoers = compare_name_service.get('sudoers')

                if group and group != compare_group:
                    name_service_dict['group'] = group
                if netgroup and netgroup != compare_netgroup:
                    name_service_dict['netgroup'] = netgroup
                if passwd and passwd != compare_passwd:
                    name_service_dict['passwd'] = passwd
                if shadow and shadow != compare_shadow:
                    name_service_dict['shadow'] = shadow
                if sudoers and sudoers != compare_sudoers:
                    name_service_dict['sudoers'] = sudoers
                if name_service_dict:
                    cfg_dict['name_service'] = name_service_dict
            else:
                cfg_dict['name_service'] = name_service

        return cfg_dict

    def get_replaced_config(self, want, have):
        config_dict = {}
        self.remove_default_entries(have)
        authentication = want.get('authentication')
        authorization = want.get('authorization')
        name_service = want.get('name_service')
        cfg_authentication = have.get('authentication')
        cfg_authorization = have.get('authorization')
        cfg_name_service = have.get('name_service')

        if authentication and cfg_authentication and authentication != cfg_authentication:
            config_dict['authentication'] = cfg_authentication
        if authorization and cfg_authorization and authorization != cfg_authorization:
            config_dict['authorization'] = cfg_authorization
        if name_service and cfg_name_service and name_service != cfg_name_service:
            config_dict['name_service'] = cfg_name_service

        return config_dict

    def post_process_generated_config(self, data):
        if data:
            authentication = data.get('authentication')
            authorization = data.get('authorization')
            name_service = data.get('name_service')

            if authentication:
                if 'auth_method' in authentication and not authentication['auth_method']:
                    data['authentication'].pop('auth_method')
                default_entries = {'console_auth_local': False, 'failthrough': False, 'login_mfa_console': False}
                for option, value in default_entries.items():
                    authentication.setdefault(option, value)
                if authentication == default_entries:
                    data.pop('authentication')

            if authorization:
                if 'commands_auth_method' in authorization and not authorization['commands_auth_method']:
                    data['authorization'].pop('commands_auth_method')
                if 'login_auth_method' in authorization and not authorization['login_auth_method']:
                    data['authorization'].pop('login_auth_method')
                if not data['authorization']:
                    data.pop('authorization')
            if name_service:
                for method in ('group', 'netgroup', 'passwd', 'shadow', 'sudoers'):
                    if method in name_service and not name_service[method]:
                        data['name_service'].pop(method)
                    if not data['name_service']:
                        data.pop('name_service')

    def remove_default_entries(self, data):
        if data:
            authentication = data.get('authentication')
            if authentication:
                if authentication.get('console_auth_local') is False:
                    authentication.pop('console_auth_local')
                if authentication.get('login_mfa_console') is False:
                    authentication.pop('login_mfa_console')
                if not authentication:
                    data.pop('authentication')
