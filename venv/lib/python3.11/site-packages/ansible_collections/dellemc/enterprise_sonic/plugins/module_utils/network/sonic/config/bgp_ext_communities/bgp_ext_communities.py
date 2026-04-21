#
# -*- coding: utf-8 -*-
# Copyright 2023 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_bgp_ext_communities class
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
    update_states,
    get_diff,
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import to_request
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
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
import json
from ansible.module_utils._text import to_native
from ansible.module_utils.connection import ConnectionError
import traceback
try:
    import jinja2
    HAS_LIB = True
except Exception as e:
    HAS_LIB = False
    ERR_MSG = to_native(e)
    LIB_IMP_ERR = traceback.format_exc()

try:
    from urllib.parse import urlencode
except Exception:
    from urllib import urlencode

is_delete_all = False
TEST_KEYS_sort_config = [
    {'config': {'__test_keys': ('name',)}},
]


def __derive_bgp_ext_communities_delete_op(key_set, command, exist_conf):
    if is_delete_all:
        new_conf = []
        return True, new_conf
    done, new_conf = __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, exist_conf)
    if done:
        return done, new_conf
    else:
        return __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, new_conf)


TEST_KEYS_generate_config = [
    {'config': {'name': '', '__delete_op': __derive_bgp_ext_communities_delete_op}}
]


class Bgp_ext_communities(ConfigBase):
    """
    The sonic_bgp_ext_communities class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'bgp_ext_communities',
    ]

    standard_communities_map = {
        "route_origin": "route-origin",
        "route_target": "route-target"
    }

    def __init__(self, module):
        super(Bgp_ext_communities, self).__init__(module)

    def get_bgp_ext_communities_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        bgp_ext_communities_facts = facts['ansible_network_resources'].get('bgp_ext_communities')
        if not bgp_ext_communities_facts:
            return []
        return bgp_ext_communities_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        commands = list()

        existing_bgp_ext_communities_facts = self.get_bgp_ext_communities_facts()
        commands, requests = self.set_config(existing_bgp_ext_communities_facts)

        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_bgp_ext_communities_facts = self.get_bgp_ext_communities_facts()

        result['before'] = existing_bgp_ext_communities_facts
        if result['changed']:
            result['after'] = changed_bgp_ext_communities_facts

        new_config = changed_bgp_ext_communities_facts
        old_config = existing_bgp_ext_communities_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_bgp_ext_communities_facts,
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

    def set_config(self, existing_bgp_ext_communities_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        if want:
            for conf in want:
                cmd_type = conf.get("type", None)
                if cmd_type and conf.get("match", None):
                    conf['match'] = conf['match'].lower()
                if cmd_type and conf.get("members", {}):
                    if cmd_type == "expanded":
                        if conf['members'].get("regex", []):
                            conf['members']['regex'].sort()
                    else:
                        if conf['members'].get("route_origin", []):
                            conf['members']['route_origin'].sort()
                        if conf['members'].get("route_target", []):
                            conf['members']['route_target'].sort()

        have = existing_bgp_ext_communities_facts
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
        new_want = self.validate_type(want)
        diff = get_diff(new_want, have)
        if state == 'overridden':
            commands, requests = self._state_overridden(want, have)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
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

    def _state_merged(self, want, have, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = diff
        requests = self.get_modify_bgp_ext_community_requests(commands, have, "merged")
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
        global is_delete_all
        is_delete_all = False
        # if want is none, then delete ALL
        if not want:
            commands = have
            is_delete_all = True
        else:
            commands = want

        requests = self.get_delete_bgp_ext_communities(commands, have, is_delete_all)

        if commands and len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []

        return commands, requests

    def get_delete_single_bgp_ext_community_member_requests(self, name, members):
        requests = []
        for member in members:
            url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:"
            url = url + "bgp-defined-sets/ext-community-sets/ext-community-set={name}/config/{members_param}"
            method = "DELETE"
            members_params = {'ext-community-member': member}
            members_str = urlencode(members_params)
            request = {"path": url.format(name=name, members_param=members_str), "method": method}
            requests.append(request)
        return requests

    def get_delete_single_bgp_ext_community_requests(self, name):
        url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/ext-community-sets/ext-community-set={}"
        method = "DELETE"
        request = {"path": url.format(name), "method": method}
        return request

    def get_delete_all_bgp_ext_communities(self, commands):
        url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/ext-community-sets"
        method = "DELETE"
        requests = []
        if commands:
            request = {"path": url, "method": method}
            requests.append(request)
        return requests

    def get_delete_bgp_ext_communities(self, commands, have, is_delete_all):
        requests = []
        if is_delete_all:
            requests = self.get_delete_all_bgp_ext_communities(commands)
        else:
            for cmd in commands:
                name = cmd['name']
                cmd_type = cmd['type']
                members = cmd.get('members', None)
                diff_members = []

                for item in have:
                    if item["name"] == name:
                        if 'permit' not in cmd or cmd['permit'] is None:
                            cmd['permit'] = item['permit']
                        if cmd == item:
                            requests.append(self.get_delete_single_bgp_ext_community_requests(name))
                            break

                        if members:
                            if cmd_type == "expanded":
                                if members.get('regex', []):
                                    for member_want in members['regex']:
                                        if item.get("members", None) and item['members'].get('regex', []):
                                            if str(member_want) in item['members']['regex']:
                                                diff_members.append("REGEX:" + str(member_want))
                                else:
                                    requests.append(self.get_delete_single_bgp_ext_community_requests(name))
                            else:
                                no_members = True
                                for attr in self.standard_communities_map:
                                    if members.get(attr, []):
                                        no_members = False
                                        for member_want in members[attr]:
                                            if item.get("members", None) and item['members'].get(attr, []):
                                                if str(member_want) in item['members'][attr]:
                                                    diff_members.append(self.standard_communities_map[attr] + ":" + str(member_want))
                                if no_members:
                                    requests.append(self.get_delete_single_bgp_ext_community_requests(name))
                        else:
                            requests.append(self.get_delete_single_bgp_ext_community_requests(name))

                        break

                if diff_members:
                    requests.extend(self.get_delete_single_bgp_ext_community_member_requests(name, diff_members))

        return requests

    def get_new_add_request(self, conf):

        url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/ext-community-sets"
        method = "PATCH"
        community_members = []
        community_action = ""

        if 'match' not in conf:
            conf['match'] = "ANY"

        if conf['type'] == 'expanded':
            if 'members' in conf and conf['members'] and conf['members'].get('regex', []):
                for i in conf['members']['regex']:
                    community_members.extend(["REGEX:" + str(i)])
        elif conf['type'] == 'standard':
            for attr in self.standard_communities_map:
                if 'members' in conf and conf['members'] and conf['members'].get(attr, []):
                    for i in conf['members'][attr]:
                        community_members.extend([self.standard_communities_map[attr] + ":" + str(i)])

        if not community_members:
            self._module.fail_json(msg='Cannot create {0} community-list {1} without community attributes'.format(conf['type'], conf['name']))
            return {}

        if conf['permit']:
            community_action = "PERMIT"
        else:
            community_action = "DENY"

        input_data = {'name': conf['name'], 'members_list': community_members, 'match': conf['match'].upper(), 'permit': community_action}

        payload_template = """
                            {
                                "openconfig-bgp-policy:ext-community-sets": {
                                    "ext-community-set": [
                                        {
                                            "ext-community-set-name": "{{name}}",
                                            "config": {
                                                "ext-community-set-name": "{{name}}",
                                                "ext-community-member": [
                                                    {% for member in members_list %}"{{member}}"{%- if not loop.last -%},{% endif %}{%endfor%}
                                                ],
                                                "openconfig-bgp-policy-ext:action": "{{permit}}",
                                                "match-set-options": "{{match}}"
                                            }
                                        }
                                    ]
                                }
                            }"""
        env = jinja2.Environment(autoescape=False)
        t = env.from_string(payload_template)
        intended_payload = t.render(input_data)
        ret_payload = json.loads(intended_payload)
        request = {"path": url, "method": method, "data": ret_payload}
        return request

    def get_modify_bgp_ext_community_requests(self, commands, have, cur_state):
        requests = []
        if not commands:
            return requests

        for conf in commands:
            if cur_state == "merged":
                for item in have:
                    if item['name'] == conf['name']:
                        if 'type' not in conf:
                            conf['type'] = item['type']
                        if 'permit' not in conf or conf['permit'] is None:
                            conf['permit'] = item['permit']
                        if 'match' not in conf:
                            conf['match'] = item['match']
                        if 'members' not in conf:
                            if conf['type'] == "expanded":
                                if item.get('members', {}) and item['members'].get('regex', []):
                                    conf['members'] = {'regex': item['members']['regex']}
                                else:
                                    conf['members'] = item['members']
                            else:
                                no_members = True
                                for attr in self.standard_communities_map:
                                    if item.get('members', {}) and item['members'].get(attr, []):
                                        no_members = False
                                        conf['members'] = {attr: item['members'][attr]}
                                if no_members:
                                    conf['members'] = item['members']
                        break

            new_req = self.get_new_add_request(conf)
            if new_req:
                requests.append(new_req)
        return requests

    def validate_type(self, want):
        new_want = []
        if want:
            for conf in want:
                cfg = conf.copy()
                cfg['type'] = 'standard'
                members = conf.get('members', None)
                if members and members.get('regex', None):
                    cfg['type'] = 'expanded'

                new_want.append(cfg)
        return new_want

    def get_replaced_overridden_config(self, want, have, cur_state):
        commands, requests = [], []

        commands_del, requests_del = [], []
        commands_add, requests_add = [], []

        for conf in want:
            name = conf['name']
            in_have = False
            for have_conf in have:
                if have_conf['name'] == name:
                    in_have = True
                    if have_conf['type'] != conf['type']:
                        # If both extended community list are of same name but different types
                        commands_del.append(have_conf)
                        commands_add.append(conf)
                    else:
                        is_change = False

                        if have_conf['permit'] != conf['permit']:
                            is_change = True

                        if have_conf['match'] != conf['match']:
                            is_change = True

                        if conf["type"] == "expanded":
                            members = conf.get('members', {})
                            if members and conf['members'].get('regex', []):
                                if have_conf.get('members', {}) and have_conf['members'].get('regex', []):
                                    if set(have_conf['members']['regex']).symmetric_difference(set(members['regex'])):
                                        is_change = True
                            else:
                                # If there are no members in any expanded ext community list of want, then
                                # abort the playbook with an error message explaining why the specified command is not valid
                                self._module.fail_json(msg='Cannot create expanded extended community-list '
                                                           '{0} without community attributes'.format(conf['name']))
                        else:
                            members = conf.get('members', {})
                            no_members = True
                            for attr in self.standard_communities_map:
                                if members and conf['members'].get(attr, []):
                                    no_members = False
                                    if have_conf.get('members', {}) and have_conf['members'].get(attr, []):
                                        if set(have_conf['members'][attr]).symmetric_difference(set(members[attr])):
                                            is_change = True

                            if no_members:
                                # If there are no members in any standard ext community list of want, then
                                # abort the playbook with an error message explaining why the specified command is not valid
                                self._module.fail_json(msg='Cannot create standard extended community-list '
                                                           '{0} without community attributes'.format(conf['name']))

                        if is_change:
                            commands_add.append(conf)
                            commands_del.append(have_conf)
                    break
            if not in_have:
                commands_add.append(conf)

        if cur_state == "overridden":
            for have_conf in have:
                in_want = next((conf for conf in want if conf['name'] == have_conf['name']), None)
                if not in_want:
                    commands_del.append(have_conf)

        if commands_del:
            requests_del = self.get_delete_bgp_ext_communities(commands_del, have, False)

            if len(requests_del) > 0:
                commands.extend(update_states(commands_del, "deleted"))
                requests.extend(requests_del)

        if commands_add:
            requests_add = self.get_modify_bgp_ext_community_requests(commands_add, have, cur_state)

            if len(requests_add) > 0:
                commands.extend(update_states(commands_add, cur_state))
                requests.extend(requests_add)

        return commands, requests

    def post_process_generated_config(self, configs):
        confs = remove_void_config(configs, TEST_KEYS_sort_config)
        if confs:
            for conf in confs[:]:
                members = conf.get('members', None)
                if members:
                    if conf.get('permit', None) is None:
                        conf['permit'] = False
                    if not conf.get('match', None):
                        conf['match'] = 'any'

                    if members.get('regex', []):
                        conf['type'] = 'expanded'
                    else:
                        conf['type'] = 'standard'
                else:
                    confs.remove(conf)
        return confs
