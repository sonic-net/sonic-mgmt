#
# -*- coding: utf-8 -*-
# Copyright 2023 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_bgp_communities class
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
    remove_empties_from_list
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


def __derive_bgp_communities_delete_op(key_set, command, exist_conf):
    if is_delete_all:
        new_conf = []
        return True, new_conf
    done, new_conf = __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, exist_conf)
    if done:
        return done, new_conf
    else:
        return __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, new_conf)


TEST_KEYS_generate_config = [
    {'config': {'name': '', '__delete_op': __derive_bgp_communities_delete_op}}
]


class Bgp_communities(ConfigBase):
    """
    The sonic_bgp_communities class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'bgp_communities',
    ]

    standard_communities_map = {
        'no_peer': 'NOPEER',
        'no_export': 'NO_EXPORT',
        'no_advertise': 'NO_ADVERTISE',
        'local_as': 'NO_EXPORT_SUBCONFED'
    }

    def __init__(self, module):
        super(Bgp_communities, self).__init__(module)

    def get_bgp_communities_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        bgp_communities_facts = facts['ansible_network_resources'].get('bgp_communities')
        if not bgp_communities_facts:
            return []
        return bgp_communities_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        commands = list()

        existing_bgp_communities_facts = self.get_bgp_communities_facts()
        commands, requests = self.set_config(existing_bgp_communities_facts)

        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_bgp_communities_facts = self.get_bgp_communities_facts()

        result['before'] = existing_bgp_communities_facts
        if result['changed']:
            result['after'] = changed_bgp_communities_facts

        new_config = changed_bgp_communities_facts
        old_config = existing_bgp_communities_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_bgp_communities_facts,
                                        TEST_KEYS_generate_config)
            new_config = self.post_process_generated_config(new_config)
            old_config = remove_empties_from_list(old_config)
            result['after(generated)'] = new_config

        if self._module._diff:
            new_config = sort_config(new_config, TEST_KEYS_sort_config)
            old_config = sort_config(old_config, TEST_KEYS_sort_config)
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)
        result['warnings'] = warnings
        return result

    def set_config(self, existing_bgp_communities_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_bgp_communities_facts
        if want:
            want = self.validate_and_normalize_config(want, have)

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

        commands, requests = self.get_replaced_overridden_config(want, have, "replaced")

        return commands, requests

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []

        commands, requests = self.get_replaced_overridden_config(want, have, "overridden")

        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        requests = []
        commands = get_diff(want, have)

        for conf in commands:
            have_conf = search_obj_in_list(conf['name'], have, 'name')
            if have_conf:
                del_attrs = []
                # Matching values will not be available in diff.
                # Hence, updating the required fields in diff with the values from have.
                for attr in ('type', 'permit', 'match'):
                    if conf.get(attr) is None:
                        conf[attr] = have_conf.get(attr)
                if conf['type'] == "standard":
                    for attr in self.standard_communities_map:
                        if attr in have_conf:
                            # Delete options that are disabled in want
                            if conf.get(attr) is False and have_conf[attr]:
                                del_attrs.append(self.standard_communities_map[attr])
                            elif attr not in conf:
                                conf[attr] = have_conf[attr]
                    if 'members' not in conf and have_conf.get('members') and have_conf['members'].get('aann'):
                        conf['members'] = {'aann': have_conf['members']['aann']}
                else:
                    if 'members' not in conf and have_conf.get('members') and have_conf['members'].get('regex'):
                        conf['members'] = {'regex': have_conf['members']['regex']}

                if del_attrs:
                    requests.extend(self.get_delete_single_bgp_community_member_requests(conf['name'], del_attrs))

            new_req = self.get_new_add_request(conf)
            if new_req:
                requests.append(new_req)

        if len(requests) > 0:
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
        # Delete a community
        # https://100.94.81.19/restconf/data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/community-sets/community-set=extest
        # Delete all members but not community
        # https://100.94.81.19/restconf/data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/community-sets/community-set=extest/config/community-member
        # Dete a memeber from the expanded community
        # https://100.94.81.19/restconf/data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/community-sets/community-set=extest/config/community-member=REGEX%3A100.100
        # Delete ALL Bgp_communities and its members
        # https://100.94.81.19/restconf/data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/community-sets
        global is_delete_all
        is_delete_all = False
        # if want is none, then delete ALL
        if not want:
            commands = have
            is_delete_all = True
        else:
            commands = want

        requests = self.get_delete_bgp_communities(commands, have, is_delete_all)

        if commands and len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []

        return commands, requests

    def get_delete_single_bgp_community_member_requests(self, name, members):
        requests = []
        url = ("data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:"
               "bgp-defined-sets/community-sets/community-set={name}/config/{members_param}")
        method = "DELETE"
        for member in members:
            members_params = {'community-member': member}
            members_str = urlencode(members_params)
            request = {"path": url.format(name=name, members_param=members_str), "method": method}
            requests.append(request)
        return requests

    def get_delete_single_bgp_community_request(self, name):
        url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/community-sets/community-set={}"
        method = "DELETE"
        request = {"path": url.format(name), "method": method}
        return request

    def get_delete_all_bgp_communities(self, commands):
        url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/community-sets"
        method = "DELETE"
        requests = []
        if commands:
            request = {"path": url, "method": method}
            requests.append(request)
        return requests

    def get_delete_bgp_communities(self, commands, have, is_delete_all):
        requests = []
        if is_delete_all:
            requests = self.get_delete_all_bgp_communities(commands)
        else:
            for cmd in commands:
                name = cmd['name']
                members = cmd.get('members', None)
                del_options = []
                del_community_list = False

                for item in have:
                    if item['name'] == name:
                        # Delete community-list if only name is specified
                        if len(cmd.keys()) == 1:
                            requests.append(self.get_delete_single_bgp_community_request(name))
                            break

                        if cmd == item:
                            requests.append(self.get_delete_single_bgp_community_request(name))
                            break

                        member_type = 'aann' if cmd['type'] == 'standard' else 'regex'
                        if cmd['type'] == "standard":
                            have_attr = False
                            for attr in self.standard_communities_map:
                                if cmd.get(attr) and item.get(attr) and cmd[attr] == item[attr]:
                                    del_options.append(self.standard_communities_map[attr])
                                elif item.get(attr):
                                    have_attr = True

                        if members:
                            if member_type in members:
                                have_members = set(item['members'][member_type]) if item.get('members') and item['members'].get(member_type) else set()
                                if members.get(member_type):
                                    del_members = set(members[member_type]).intersection(have_members)
                                    if del_members:
                                        if cmd['type'] == "standard":
                                            del_options.extend(list(del_members))
                                        else:
                                            del_options = ['REGEX:' + member for member in del_members]
                                else:
                                    # In case of 'standard' type, if 'members' -> 'aann' is empty
                                    # 1) Delete the whole community-list, if other attributes are also to be deleted (or) not present.
                                    # 2) Delete all 'aann' members otherwise.
                                    # In case of 'expanded' type, if 'members' -> 'regex' is empty then delete the whole community-list.
                                    if cmd['type'] == "standard":
                                        if not have_attr:
                                            del_community_list = True
                                        else:
                                            del_options.extend(list(have_members))
                                    else:
                                        del_community_list = True

                        if del_community_list:
                            requests.append(self.get_delete_single_bgp_community_request(name))
                        elif del_options:
                            requests.extend(self.get_delete_single_bgp_community_member_requests(name, del_options))

                        break

        return requests

    def get_new_add_request(self, conf):
        url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/community-sets"
        method = "PATCH"
        community_members = []

        if conf['type'] == 'standard':
            for attr in self.standard_communities_map:
                if attr in conf and conf[attr]:
                    community_members.append(self.standard_communities_map[attr])
            if 'members' in conf and conf['members'] and conf['members'].get('aann', []):
                for i in conf['members']['aann']:
                    community_members.extend([str(i)])
        elif conf['type'] == 'expanded':
            if 'members' in conf and conf['members'] and conf['members'].get('regex', []):
                for i in conf['members']['regex']:
                    community_members.extend(["REGEX:" + str(i)])

        if not community_members:
            self._module.fail_json(msg='Cannot create {0} community-list {1} without community attributes'.format(conf['type'], conf['name']))

        payload = {
            'openconfig-bgp-policy:community-sets': {
                'community-set': [
                    {
                        'community-set-name': conf['name'],
                        'config': {
                            'community-set-name': conf['name'],
                            'community-member': community_members,
                            'openconfig-bgp-policy-ext:action': 'PERMIT' if conf['permit'] else 'DENY',
                            'match-set-options': conf['match']
                        }
                    }
                ]
            }
        }
        return {"path": url, "method": method, "data": payload}

    def get_replaced_overridden_config(self, want, have, cur_state):
        commands, requests = [], []

        commands_del, requests_del = [], []
        commands_add, requests_add = [], []

        for conf in want:
            name = conf['name']
            have_conf = search_obj_in_list(name, have, 'name')
            if have_conf:
                is_add = is_delete = False
                add_command, del_command = {'name': name}, {'name': name}
                del_attrs_members = []
                member_type = 'regex'
                for attr in ('type', 'permit', 'match'):
                    add_command[attr] = conf[attr]
                    del_command[attr] = have_conf[attr]
                    if conf[attr] != have_conf[attr]:
                        commands_del.append(have_conf)
                        commands_add.append(conf)
                        requests_del.append(self.get_delete_single_bgp_community_request(name))
                        requests_add.append(self.get_new_add_request(conf))
                        is_delete = True
                        break

                if is_delete:
                    continue

                if conf['type'] == 'standard':
                    member_type = 'aann'
                    for attr in self.standard_communities_map:
                        if conf.get(attr) and not have_conf.get(attr):
                            add_command[attr] = conf[attr]
                            is_add = True
                        elif not conf.get(attr) and have_conf.get(attr):
                            del_attrs_members.append(self.standard_communities_map[attr])
                            del_command[attr] = have_conf[attr]
                            is_delete = True

                have_members = set(have_conf['members'][member_type]) if have_conf.get('members') and have_conf['members'].get(member_type) else set()
                want_members = set(conf['members'][member_type]) if conf.get('members') and conf['members'].get(member_type) else set()
                add_members = want_members - have_members
                del_members = have_members - want_members
                if add_members:
                    add_command['members'] = {member_type: list(add_members)}
                    is_add = True
                if del_members:
                    del_command['members'] = {member_type: list(del_members)}
                    del_attrs_members.extend(del_command['members'][member_type])
                    is_delete = True

                if is_delete:
                    commands_del.append(del_command)
                    if is_add:
                        commands_add.append(add_command)
                    requests_del.append(self.get_delete_single_bgp_community_request(name))
                    requests_add.append(self.get_new_add_request(conf))
                elif is_add:
                    commands_add.append(add_command)
                    requests_add.append(self.get_new_add_request(add_command))
            else:
                commands_add.append(conf)
                requests_add.append(self.get_new_add_request(conf))

        if cur_state == "overridden":
            for have_conf in have:
                in_want = next((conf for conf in want if conf['name'] == have_conf['name']), None)
                if not in_want:
                    commands_del.append(have_conf)
                    requests_del.append(self.get_delete_single_bgp_community_request(have_conf['name']))

        if len(requests_del) > 0:
            commands.extend(update_states(commands_del, "deleted"))
            requests.extend(requests_del)

        if len(requests_add) > 0:
            commands.extend(update_states(commands_add, cur_state))
            requests.extend(requests_add)

        return commands, requests

    @staticmethod
    def set_default_values(conf):
        if conf.get('type') is None:
            conf['type'] = 'standard'
        if conf.get('permit') is None:
            conf['permit'] = False
        if conf.get('match') is None:
            conf['match'] = 'ANY'

    def validate_and_normalize_config(self, want, have):
        state = self._module.params['state']
        if state != 'deleted':
            updated_want = remove_empties_from_list(want)
        else:
            updated_want = want

        for conf in updated_want:
            # Empty values for suboptions of member (aann/regex) is supported.
            # Hence, remove_empties is not used for deleted state.
            delete_name_only = False
            if state == 'deleted':
                for key, value in list(conf.items()):
                    if value is None:
                        del conf[key]
                if len(conf.keys()) == 1:
                    delete_name_only = True

            if state in ('replaced', 'overridden'):
                self.set_default_values(conf)
            elif state == 'merged' or (state == 'deleted' and not delete_name_only):
                have_conf = search_obj_in_list(conf['name'], have, 'name')
                if have_conf:
                    for attr in ('type', 'permit', 'match'):
                        if conf.get(attr) is None:
                            conf[attr] = have_conf.get(attr)
                if state == 'merged':
                    self.set_default_values(conf)

            if not delete_name_only:
                members = conf.get('members')
                if conf.get('type') == 'standard':
                    if members:
                        if members.get('regex'):
                            self._module.fail_json(msg='members -> regex is not applicable for standard community-list {0}'.format(conf['name']))
                        if members.get('aann'):
                            members['aann'].sort()
                else:
                    for attr in self.standard_communities_map:
                        if conf.get(attr) is not None:
                            self._module.fail_json(msg='{0} is not applicable for expanded community-list {1}'.format(attr, conf['name']))
                    if members:
                        if members.get('aann'):
                            self._module.fail_json(msg='members -> aann is not applicable for expanded community-list {0}'.format(conf['name']))
                        if members.get('regex'):
                            members['regex'].sort()

        return updated_want

    def post_process_generated_config(self, configs):
        confs = remove_void_config(configs, TEST_KEYS_sort_config)
        if confs:
            for conf in confs[:]:
                if not conf.get('match', None):
                    conf['match'] = 'ANY'
                if not conf.get('type', None):
                    conf['type'] = 'standard'
        return confs
