#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_users class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type
import json

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
    update_states,
    get_diff,
    remove_empties,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_CONFIG_IF_NO_SUBCONFIG,
    get_new_config,
    get_formatted_config_diff
)
from ansible.module_utils.connection import ConnectionError

PATCH = 'patch'
DELETE = 'delete'
TEST_KEYS_formatted_diff = [
    {'config': {'name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
]


class Users(ConfigBase):
    """
    The sonic_users class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'users',
    ]

    def __init__(self, module):
        super(Users, self).__init__(module)

    def get_users_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        users_facts = facts['ansible_network_resources'].get('users')
        if not users_facts:
            return []
        return users_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        existing_users_facts = self.get_users_facts()
        commands, requests = self.set_config(existing_users_facts)
        auth_error = False
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    try:
                        json_obj = json.loads(str(exc).replace("'", '"'))
                        if json_obj and isinstance(json_obj, dict) and 401 == json_obj['code']:
                            auth_error = True
                            warnings.append("Unable to get after configs as password got changed for current user")
                        else:
                            self._module.fail_json(msg=str(exc), code=exc.code)
                    except Exception as err:
                        self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_users_facts = []
        if not auth_error:
            changed_users_facts = self.get_users_facts()

        result['before'] = existing_users_facts
        if result['changed']:
            result['after'] = changed_users_facts

        new_config = changed_users_facts
        old_config = existing_users_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_users_facts,
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

    def set_config(self, existing_users_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_users_facts
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
        if not want:
            want = []

        # Handle "role" and "ssh_key" options.
        new_want = [{'name': conf['name'], 'role': conf['role'], 'ssh_key': conf['ssh_key']}
                    if 'ssh_key' in conf and conf['ssh_key'] else {'name': conf['name'], 'role': conf['role']} for conf in want]

        new_diff = get_diff(new_want, have)

        diff = []
        for cfg in new_diff:
            match = next((w_cfg for w_cfg in want if w_cfg['name'] == cfg['name']), None)
            if match:
                diff.append(match)

        # Handle "password" and "update_password" options
        for cfg in want:
            if cfg['password'] and cfg['update_password'] == 'always':
                d_match = next((d_cfg for d_cfg in diff if d_cfg['name'] == cfg['name']), None)
                if d_match is None:
                    diff.append(cfg)

        if state == 'overridden':
            commands, requests = self._state_overridden(want, have, diff)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have, diff)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have, diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have, diff)
        return commands, requests

    def _state_merged(self, want, have, diff):
        """ The command generator when state is merged

        :param want: the additive configuration as a dictionary
        :param obj_in_have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        self.validate_new_users(want, have)

        commands = diff
        requests = self.get_modify_users_requests(commands, have)
        if commands and len(requests) > 0:
            commands = update_states(commands, "merged")
        else:
            commands = []

        return commands, requests

    def _state_deleted(self, want, have, diff):
        """ The command generator when state is deleted

        :param want: the objects from which the configuration should be removed
        :param obj_in_have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        # if want is none, then delete all the users except admin
        if not want:
            commands = have
        else:
            commands = want

        requests = self.get_delete_users_requests(commands, have)

        if commands and len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []

        return commands, requests

    def _state_replaced(self, want, have, diff):
        """ The command generator when state is merged

        :param want: the additive configuration as a dictionary
        :param obj_in_have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to replace the current configuration
                  wit the provided configuration
        """
        self.validate_new_users(want, have)

        commands = diff
        requests = self.get_modify_users_requests(commands, have)
        if commands and len(requests) > 0:
            commands = update_states(commands, "replaced")
        else:
            commands = []

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
        self.sort_lists_in_config(want)
        self.sort_lists_in_config(have)

        new_want = [{'name': conf['name'], 'role': conf['role'], 'ssh_key': conf['ssh_key']}
                    if 'ssh_key' in conf and conf['ssh_key'] else {'name': conf['name'], 'role': conf['role']} for conf in want]

        new_have = []
        for conf in have:
            # Exclude admin user from new_have if it isn't present in new_want
            if conf['name'] == 'admin' and not any(cfg['name'] == 'admin' for cfg in new_want):
                continue
            else:
                if 'ssh_key' in conf:
                    new_have.append({'name': conf['name'], 'role': conf['role'], 'ssh_key': conf['ssh_key']})
                else:
                    new_have.append({'name': conf['name'], 'role': conf['role']})

        if diff or new_want != new_have:
            # Delete all users except admin
            del_requests = self.get_delete_users_requests(have, have)
            requests.extend(del_requests)
            commands.extend(update_states(have, "deleted"))
            have = []

            # Merge want configuration
            mod_commands = want
            mod_requests = self.get_modify_users_requests(mod_commands, have)

            if mod_commands and len(mod_requests) > 0:
                requests.extend(mod_requests)
                commands.extend(update_states(mod_commands, "overridden"))

        return commands, requests

    def get_pwd(self, pw):
        clear_pwd = hashed_pwd = ""
        pwd = pw.replace("\\", "")
        if pwd[:3] == '$6$':
            hashed_pwd = pwd
        else:
            clear_pwd = pwd
        return clear_pwd, hashed_pwd

    def get_single_user_payload(self, name, role, password, update_pass, ssh_key, match):
        user_cfg = {'username': name}
        if not ssh_key:
            if not role and match:
                role = match['role']

            if not password and match:
                password = match['password']

            if role:
                user_cfg['role'] = role

            if password:
                clear_pwd, hashed_pwd = self.get_pwd(password)
                user_cfg['password'] = clear_pwd
                user_cfg['password-hashed'] = hashed_pwd
        else:
            if role or password:
                err_msg = "ssh_key can not be configured at the same time as other options."
                self._module.fail_json(msg=err_msg, code=513)
            user_cfg['ssh-key'] = ssh_key

        pay_load = {'openconfig-system:user': [{'username': name, 'config': user_cfg}]}
        return pay_load

    def get_modify_single_user_request(self, conf, match):
        request = None
        name = conf.get('name', None)
        role = conf.get('role', None)
        ssh_key = conf.get('ssh_key', None)
        password = conf.get('password', None)
        update_pass = conf.get('update_password', None)
        if role or (password and update_pass == 'always') or ssh_key:
            url = 'data/openconfig-system:system/aaa/authentication/users/user=%s' % (name)
            payload = self.get_single_user_payload(name, role, password, update_pass, ssh_key, match)
            request = {'path': url, 'method': PATCH, 'data': payload}
        return request

    def get_modify_users_requests(self, commands, have):
        requests = []
        if not commands:
            return requests

        for conf in commands:
            match = next((cfg for cfg in have if cfg['name'] == conf['name']), None)
            req = self.get_modify_single_user_request(conf, match)
            if req:
                requests.append(req)
        return requests

    def get_new_users(self, want, have):
        new_users = []
        for user in want:
            if not next((h_user for h_user in have if h_user['name'] == user['name']), None):
                new_users.append(user)
        return new_users

    def validate_new_users(self, want, have):
        new_users = self.get_new_users(want, have)
        invalid_users = []
        invalid_users_params = []
        for user in new_users:
            params = []
            if not user['role']:
                params.append('role')
            if not user['password']:
                params.append('password')
            if user.get('ssh_key'):
                invalid_users_params.append({user['name']: 'ssh_key'})
            if params:
                invalid_users.append({user['name']: params})

        if invalid_users or invalid_users_params:
            err_msg = "Missing parameter(s) for new users! " + str(invalid_users)
            err_msg += "\nInvalid parameter(s) for new users! " + str(invalid_users_params)
            self._module.fail_json(msg=err_msg, code=513)

    def get_delete_users_requests(self, commands, have):
        requests = []
        if not commands:
            return requests

        # Skip the admin user in 'deleted' state. we cannot delete all users
        admin_usr = None
        admin_usr_ssh_key_update = False

        for conf in commands:
            conf = remove_empties(conf)
            match = next((cfg for cfg in have if cfg['name'] == conf['name']), None)
            if match:
                if 'ssh_key' in conf and ('role' not in conf or conf['role'] is None):
                    delete_key = False
                    ssh_key_conf = conf.get('ssh_key')
                    ssh_key_match = match.get('ssh_key')

                    if ssh_key_conf is None:
                        if 'ssh_key' in match:
                            delete_key = True
                    elif ssh_key_conf == ssh_key_match:
                        delete_key = True

                    if delete_key:
                        url = 'data/openconfig-system:system/aaa/authentication/users/user=%s/config/ssh-key' % (conf['name'])
                        requests.append({'path': url, 'method': DELETE})

                    if conf['name'] == 'admin':
                        admin_usr_ssh_key_update = True
                    continue
            # Skip the admin user in 'deleted' state. we cannot delete all users
            if conf['name'] == 'admin':
                admin_usr = conf
                continue
            if match:
                url = 'data/openconfig-system:system/aaa/authentication/users/user=%s' % (conf['name'])
                requests.append({'path': url, 'method': DELETE})

        if admin_usr and not admin_usr_ssh_key_update:
            commands.remove(admin_usr)
        return requests

    def sort_lists_in_config(self, config):
        if config:
            config.sort(key=lambda x: x['name'])
