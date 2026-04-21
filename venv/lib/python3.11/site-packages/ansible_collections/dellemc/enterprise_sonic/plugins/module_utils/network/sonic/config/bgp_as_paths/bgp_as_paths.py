#
# -*- coding: utf-8 -*-
# Copyright 2020 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_bgp_as_paths class
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
    search_obj_in_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    update_states,
    get_diff,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF,
    __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF,
    get_new_config,
    get_formatted_config_diff
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.sort_config_util import (
    sort_config,
    remove_void_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

try:
    from urllib.parse import urlencode
except Exception:
    from urllib import urlencode

is_delete_all = False
TEST_KEYS_sort_config = [
    {'config': {'__test_keys': ('name',)}},
]


def __derive_bgp_as_paths_delete_op(key_set, command, exist_conf):
    if is_delete_all:
        new_conf = []
        return True, new_conf

    done, new_conf = __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, exist_conf)
    if done:
        return done, new_conf
    else:
        return __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, new_conf)


TEST_KEYS_generate_config = [
    {'config': {'name': '', '__delete_op': __derive_bgp_as_paths_delete_op}}
]


class Bgp_as_paths(ConfigBase):
    """
    The sonic_bgp_as_paths class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'bgp_as_paths',
    ]

    def __init__(self, module):
        super(Bgp_as_paths, self).__init__(module)

    def get_bgp_as_paths_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        bgp_as_paths_facts = facts['ansible_network_resources'].get('bgp_as_paths')
        if not bgp_as_paths_facts:
            return []
        return bgp_as_paths_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        commands = list()

        existing_bgp_as_paths_facts = self.get_bgp_as_paths_facts()
        commands, requests = self.set_config(existing_bgp_as_paths_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_bgp_as_paths_facts = self.get_bgp_as_paths_facts()

        result['before'] = existing_bgp_as_paths_facts
        if result['changed']:
            result['after'] = changed_bgp_as_paths_facts

        new_config = changed_bgp_as_paths_facts
        old_config = existing_bgp_as_paths_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_bgp_as_paths_facts,
                                        TEST_KEYS_generate_config)
            new_config = remove_void_config(new_config, TEST_KEYS_sort_config)
            result['after(generated)'] = new_config

        if self._module._diff:
            new_config = sort_config(new_config)
            old_config = sort_config(old_config)
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)
        result['warnings'] = warnings
        return result

    def set_config(self, existing_bgp_as_paths_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_bgp_as_paths_facts
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
        if state == 'overridden':
            commands, requests = self._state_overridden(want, have)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            diff = get_diff(want, have)
            commands, requests = self._state_merged(want, have, diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have)
        return commands, requests

    def _state_replaced(self, want, have):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        add_commands = []
        del_commands = []
        commands = []
        requests = []

        for cmd in want:
            # Set action to deny if not specfied for as-path-list
            if cmd.get('permit') is None:
                cmd['permit'] = False

            match = search_obj_in_list(cmd['name'], have, 'name')
            # Replace existing as-path-list
            if match:
                # Delete entire as-path-list if no members are specified
                if not cmd.get('members'):
                    del_commands.append(match)
                    requests.append(self.get_delete_single_as_path_request(cmd['name']))
                else:
                    if cmd['permit'] != match['permit']:
                        # If action is changed, delete the entire as-path list
                        # and add the given configuration
                        del_commands.append(match)
                        requests.append(self.get_delete_single_as_path_request(cmd['name']))
                        add_commands.append(cmd)
                        requests.append(self.get_new_add_request(cmd))
                    else:
                        want_members_set = set(cmd['members'])
                        have_members_set = set(match['members'])
                        members_to_delete = list(have_members_set.difference(want_members_set))
                        members_to_add = list(want_members_set.difference(have_members_set))
                        if members_to_delete:
                            del_commands.append({'name': cmd['name'], 'permit': cmd['permit'], 'members': members_to_delete})
                            if len(members_to_delete) == len(match['members']):
                                requests.append(self.get_delete_single_as_path_request(cmd['name']))
                            else:
                                requests.append(self.get_delete_single_as_path_member_request(cmd['name'], members_to_delete))

                        if members_to_add:
                            add_commands.append({'name': cmd['name'], 'permit': cmd['permit'], 'members': members_to_add})
                            requests.append(self.get_new_add_request({'name': cmd['name'], 'permit': cmd['permit'], 'members': members_to_add}))
            else:
                if cmd.get('members'):
                    add_commands.append(cmd)
                    requests.append(self.get_new_add_request(cmd))

        if del_commands:
            commands = update_states(del_commands, 'deleted')

        if add_commands:
            commands.extend(update_states(add_commands, 'replaced'))

        return commands, requests

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        add_commands = []
        del_commands = []
        commands = []
        requests = []

        # Delete as-path-lists that are not specified
        for cfg in have:
            if not search_obj_in_list(cfg['name'], want, 'name'):
                del_commands.append(cfg)
                requests.append(self.get_delete_single_as_path_request(cfg['name']))

        for cmd in want:
            # Set action to deny if not specfied for as-path-list
            if cmd.get('permit') is None:
                cmd['permit'] = False

            match = search_obj_in_list(cmd['name'], have, 'name')
            # Override existing as-path-list
            if match:
                # Delete entire as-path-list if no members are specified
                if not cmd.get('members'):
                    del_commands.append(match)
                    requests.append(self.get_delete_single_as_path_request(cmd['name']))
                else:
                    if cmd['permit'] != match['permit']:
                        # If action is changed, delete the entire as-path list
                        # and add the given configuration
                        del_commands.append(match)
                        requests.append(self.get_delete_single_as_path_request(cmd['name']))
                        add_commands.append(cmd)
                        requests.append(self.get_new_add_request(cmd))
                    else:
                        want_members_set = set(cmd['members'])
                        have_members_set = set(match['members'])
                        members_to_delete = list(have_members_set.difference(want_members_set))
                        members_to_add = list(want_members_set.difference(have_members_set))
                        if members_to_delete:
                            del_commands.append({'name': cmd['name'], 'permit': cmd['permit'], 'members': members_to_delete})
                            if len(members_to_delete) == len(match['members']):
                                requests.append(self.get_delete_single_as_path_request(cmd['name']))
                            else:
                                requests.append(self.get_delete_single_as_path_member_request(cmd['name'], members_to_delete))

                        if members_to_add:
                            add_commands.append({'name': cmd['name'], 'permit': cmd['permit'], 'members': members_to_add})
                            requests.append(self.get_new_add_request({'name': cmd['name'], 'permit': cmd['permit'], 'members': members_to_add}))
            else:
                if cmd.get('members'):
                    add_commands.append(cmd)
                    requests.append(self.get_new_add_request(cmd))

        if del_commands:
            commands = update_states(del_commands, 'deleted')

        if add_commands:
            commands.extend(update_states(add_commands, 'overridden'))

        return commands, requests

    def _state_merged(self, want, have, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        for cmd in commands:
            match = next((item for item in have if item['name'] == cmd['name']), None)
            if match:
                # Use existing action if not specified
                if cmd.get('permit') is None:
                    cmd['permit'] = match['permit']
                elif cmd['permit'] != match['permit']:
                    action = 'permit' if match['permit'] else 'deny'
                    self._module.fail_json(msg='Cannot override existing action {0} of {1}'.format(action, cmd['name']))
            # Set action to deny if not specfied for a new as-path-list
            elif cmd.get('permit') is None:
                cmd['permit'] = False

        requests = self.get_modify_as_path_list_requests(commands, have)
        if commands and len(requests) > 0:
            commands = update_states(commands, "merged")
        else:
            commands = []

        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        # To Delete a single member
        # data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/as-path-sets/as-path-set=xyz/config/as-path-set-member=11
        # This will delete the as path and its all members
        # data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/as-path-sets/as-path-set=xyz
        # This will delete ALL as path completely
        # data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/as-path-sets

        global is_delete_all
        is_delete_all = False
        # if want is none, then delete ALL
        if not want:
            commands = have
            is_delete_all = True
        else:
            commands = want

        requests = self.get_delete_as_path_requests(commands, have, is_delete_all)

        if commands and len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []

        return commands, requests

    def get_new_add_request(self, conf):
        request = None
        members = conf.get('members', None)
        permit = conf.get('permit', None)
        permit_str = ""
        if permit:
            permit_str = "PERMIT"
        else:
            permit_str = "DENY"
        if members:
            url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/as-path-sets"
            method = "PATCH"
            cfg = {'as-path-set-name': conf['name'], 'as-path-set-member': members, 'openconfig-bgp-policy-ext:action': permit_str}
            as_path_set = {'as-path-set-name': conf['name'], 'config': cfg}
            payload = {'openconfig-bgp-policy:as-path-sets': {'as-path-set': [as_path_set]}}
            request = {"path": url, "method": method, "data": payload}
        return request

    def get_delete_all_as_path_requests(self, commands):
        url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/as-path-sets"
        method = "DELETE"
        requests = []
        if commands:
            request = {"path": url, "method": method}
            requests.append(request)
        return requests

    def get_delete_single_as_path_member_request(self, name, members):
        url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:"
        url = url + "bgp-defined-sets/as-path-sets/as-path-set={name}/config/{members_param}"
        method = "DELETE"
        members_params = {'as-path-set-member': ','.join(members)}
        members_str = urlencode(members_params)
        request = {"path": url.format(name=name, members_param=members_str), "method": method}
        return request

    def get_delete_single_as_path_request(self, name):
        url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/as-path-sets/as-path-set={}"
        method = "DELETE"
        request = {"path": url.format(name), "method": method}
        return request

    def get_delete_as_path_requests(self, commands, have, is_delete_all):
        requests = []
        if is_delete_all:
            requests = self.get_delete_all_as_path_requests(commands)
        else:
            for cmd in commands:
                name = cmd['name']
                members = cmd['members']
                permit = cmd['permit']
                match = next((item for item in have if item['name'] == cmd['name']), None)
                if match:
                    if members:
                        if match.get('members'):
                            del_members = set(match['members']).intersection(set(members))
                            if del_members:
                                if len(del_members) == len(match['members']):
                                    requests.append(self.get_delete_single_as_path_request(name))
                                else:
                                    requests.append(self.get_delete_single_as_path_member_request(name, del_members))
                    else:
                        requests.append(self.get_delete_single_as_path_request(name))

        return requests

    def get_modify_as_path_list_requests(self, commands, have):
        requests = []
        if not commands:
            return requests

        for conf in commands:
            new_req = self.get_new_add_request(conf)
            if new_req:
                requests.append(new_req)
        return requests

    def sort_lists_in_config(self, configs):
        if configs:
            configs.sort(key=lambda x: x['name'])
