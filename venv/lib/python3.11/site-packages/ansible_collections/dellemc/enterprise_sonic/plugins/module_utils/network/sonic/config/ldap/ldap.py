#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_ldap class
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
    validate_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    update_states,
    get_diff,
    remove_matching_defaults,
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    get_new_config,
    get_formatted_config_diff,
    __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF,
    __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF
)
from ansible.module_utils.connection import ConnectionError

PATCH = 'patch'
DELETE = 'delete'
modName = 'openconfig-aaa-ldap-ext:ldap'

TEST_KEYS = [
    {'config': {'name': ''}},
    {'servers': {'address': ''}},
    {'attribute': {'from': ''}},
    {'default_attribute': {'from': ''}},
    {'objectclass': {'from': ''}},
    {'override_attribute': {'from': ''}},
    {'map_remote_groups_to_sonic_roles': {'remote_group': ''}}
]

TEST_KEYS_formatted_diff = [
    {'config': {'name': '', '__delete_op': __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'servers': {'address': '', '__delete_op': __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'attribute': {'from': '', '__delete_op': __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'default_attribute': {'from': '', '__delete_op': __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'objectclass': {'from': '', '__delete_op': __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'override_attribute': {'from': '', '__delete_op': __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'map_remote_groups_to_sonic_roles': {'remote_group': '', '__delete_op': __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF}},
]

LDAP_GROUPS = {'global': 'LDAP', 'nss': 'LDAP_NSS', 'pam': 'LDAP_PAM', 'sudo': 'LDAP_SUDO'}

COMMON_ATTRIBUTES = ['base', 'bind_timelimit', 'binddn', 'bindpw', 'port', 'ssl', 'retry', 'version', 'timelimit']

MAP_ATTRIBUTES = ['attribute', 'default_attribute', 'objectclass', 'override_attribute', 'map_remote_groups_to_sonic_roles']
SERVER_ATTRIBUTES = ['address', 'server_type', 'port', 'ssl', 'priority', 'retry']

ONLY_NSS_ATTRIBUTES = ['nss_base_group', 'nss_base_netgroup', 'nss_base_passwd',
                       'nss_base_shadow', 'nss_base_sudoers', 'nss_initgroups_ignoreusers']
ONLY_PAM_ATTRIBUTES = ['pam_filter', 'pam_group_dn', 'pam_login_attribute', 'pam_member_attribute']

GLOBAL_ATTRIBUTES = COMMON_ATTRIBUTES + ['servers', 'idle_timelimit', 'nss_skipmembers', 'map', 'source_interface', 'security_profile', 'scope', 'sudoers_base',
                                         'sudoers_search_filter', 'vrf'] + ONLY_NSS_ATTRIBUTES + ONLY_PAM_ATTRIBUTES
NSS_ATTRIBUTES = COMMON_ATTRIBUTES + ONLY_NSS_ATTRIBUTES + ['idle_timelimit', 'scope']
PAM_ATTRIBUTES = COMMON_ATTRIBUTES + ONLY_PAM_ATTRIBUTES + ['nss_base_passwd', 'scope']
SUDO_ATTRIBUTES = COMMON_ATTRIBUTES + ['sudoers_base', 'sudoers_search_filter']

ATTRIBUTES = {'global': GLOBAL_ATTRIBUTES, 'nss': NSS_ATTRIBUTES, 'pam': PAM_ATTRIBUTES, 'sudo': SUDO_ATTRIBUTES}

default_entries = [
    [
        {'name': 'bind_timelimit', 'default': 10}
    ],
    [
        {'name': 'port', 'default': 389}
    ],
    [
        {'name': 'bindpw'},
        {'name': 'encrypted', 'default': False}
    ],
    [
        {'name': 'idle_timelimit', 'default': 0}
    ],
    [
        {'name': 'nss_skipmembers', 'default': False}
    ],
    [
        {'name': 'servers'},
        {'name': 'server_type', 'default': 'all'}
    ],
    [
        {'name': 'servers'},
        {'name': 'ssl', 'default': 'off'}
    ],
    [
        {'name': 'servers'},
        {'name': 'priority', 'default': 1}
    ],
    [
        {'name': 'servers'},
        {'name': 'retry', 'default': 0}
    ],
    [
        {'name': 'retry', 'default': 0}
    ],
    [
        {'name': 'scope', 'default': 'sub'}
    ],
    [
        {'name': 'ssl', 'default': 'off'}
    ],
    [
        {'name': 'timelimit', 'default': 0}
    ],
    [
        {'name': 'version', 'default': 3}
    ]
]

base_url = 'data/openconfig-system:system/aaa/server-groups/server-group={name}'

CONFIG_ATTRIBUTES = {
    'base': 'base',
    'binddn': 'bind-dn',
    'bindpw': 'bind-pw',
    'bind_timelimit': 'bind-time-limit',
    'port': 'port',
    'ssl': 'ssl',
    'timelimit': 'search-time-limit',
    'retry': 'retransmit-attempts',
    'version': 'version'
}

ONLY_NSS_ATTRIBUTES = {
    'nss_base_group': 'nss-base-group',
    'nss_base_netgroup': 'nss-base-netgroup',
    'nss_base_passwd': 'nss-base-passwd',
    'nss_base_shadow': 'nss-base-shadow',
    'nss_base_sudoers': 'nss-base-sudoers',
    'nss_initgroups_ignoreusers': 'nss-initgroups-ignoreusers',
    'scope': 'scope',
    'idle_timelimit': 'idle-time-limit'
}

ONLY_PAM_ATTRIBUTES = {
    'pam_filter': 'pam-filter',
    'pam_group_dn': 'pam-group-dn',
    'pam_login_attribute': 'pam-login-attribute',
    'pam_member_attribute': 'pam-member-attribute',
    'scope': 'scope',
    'nss_base_passwd': 'nss-base-passwd'
}


ONLY_SUDO_ATTRIBUTES = {
    'sudoers_base': 'sudoers-base',
    'sudoers_search_filter': 'sudoers-search-filter'
}

MAP_ATTRIBUTES = {
    'attribute': 'ATTRIBUTE',
    'default_attribute': 'DEFAULT_ATTRIBUTE_VALUE',
    'objectclass': 'OBJECTCLASS',
    'override_attribute': 'OVERRIDE_ATTRIBUTE_VALUE',
    'map_remote_groups_to_sonic_roles': 'CUSTOM_SONIC_ROLES_ATTRIBUTE_VALUE'
}

SERVER_ATTRIBUTES = {
    'server_type': 'use-type',
    'port': 'port',
    'ssl': 'ssl',
    'priority': 'priority',
    'retry': 'retransmit-attempts'
}


class Ldap(ConfigBase):
    """
    The sonic_ldap class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'ldap',
    ]

    def __init__(self, module):
        super(Ldap, self).__init__(module)

    def get_ldap_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        ldap_facts = facts['ansible_network_resources'].get('ldap')
        if not ldap_facts:
            return []
        return ldap_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        commands = list()

        existing_ldap_facts = self.get_ldap_facts()
        commands, requests = self.set_config(existing_ldap_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True

        result['before'] = existing_ldap_facts
        old_config = existing_ldap_facts

        if self._module.check_mode:
            existing_ldap_facts = remove_empties_from_list(existing_ldap_facts)
            new_config = self._get_generated_config(commands, existing_ldap_facts, self._module.params['state'])
            self.sort_lists_in_config(new_config)
            result['after(generated)'] = new_config
        else:
            changed_ldap_facts = self.get_ldap_facts()
            new_config = changed_ldap_facts
            if result['changed']:
                result['after'] = changed_ldap_facts

        if self._module._diff:
            self.sort_lists_in_config(new_config)
            self.sort_lists_in_config(old_config)
            result['diff'] = get_formatted_config_diff(old_config, new_config, self._module._verbosity)

        result['commands'] = commands
        result['warnings'] = warnings
        return result

    def set_config(self, existing_ldap_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        if want:
            want = remove_empties_from_list(want)
            want = self.validate_and_normalize_config(want)
        else:
            want = []

        have = existing_ldap_facts
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
        commands, requests = [], []
        state = self._module.params['state']
        if state == 'overridden' or state == 'replaced':
            commands, requests = self._state_replaced_or_overridden(want, have)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have)
        return commands, requests

    def _state_replaced_or_overridden(self, want, have):
        """ The command generator when state is replaced or overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, requests = [], []
        self.sort_lists_in_config(want)
        self.sort_lists_in_config(have)
        add_config, del_config = self._get_replaced_overridden_config(want, have)
        if del_config:
            del_commands, del_requests = self.get_delete_ldap_requests(del_config, have, False)
            if del_commands and len(del_requests) > 0:
                commands.extend(update_states(del_config, 'deleted'))
                requests.extend(del_requests)

        if add_config:
            mod_requests = self.get_create_ldap_requests(add_config)
            if len(mod_requests) > 0:
                commands.extend(update_states(add_config, self._module.params['state']))
                requests.extend(mod_requests)
        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = get_diff(want, have)
        requests = self.get_create_ldap_requests(commands)

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
        commands , requests = [], []
        is_delete_all = False

        if not want:
            commands = have
            new_have = have
            is_delete_all = True
        else:
            self.sort_lists_in_config(want)
            self.sort_lists_in_config(have)
            new_want = deepcopy(want)
            new_have = deepcopy(have)
            for default_entry in default_entries:
                remove_matching_defaults(new_have, default_entry)

            new_have = remove_empties_from_list(new_have)
            commands = new_want

        commands, requests = self.get_delete_ldap_requests(commands, new_have, is_delete_all)

        if commands and len(requests) > 0:
            commands = update_states(commands, 'deleted')
        else:
            commands = []

        return commands, requests

    def _get_replaced_overridden_config(self, want, have):
        add_config, del_config = [], []
        for conf in want:
            name = conf.get('name')
            have_conf = next((item for item in have if item['name'] == name), None)

            if not have_conf:
                add_config.append(conf)
            else:
                add_cfg, del_cfg = {}, {}
                for attr in ATTRIBUTES[name]:
                    if attr in conf:
                        if attr not in have_conf:
                            add_cfg[attr] = conf[attr]
                        elif conf[attr] != have_conf[attr]:
                            if attr not in ('name', 'servers', 'map'):
                                add_cfg[attr] = conf[attr]
                                del_cfg[attr] = have_conf[attr]
                            elif attr == 'servers':
                                add_srv, del_srv = [], []
                                for server in conf[attr]:
                                    address = server.get('address')
                                    match_server = next((item for item in have_conf[attr] if item['address'] == address), None)
                                    if not match_server:
                                        add_srv.append(server)
                                    else:
                                        add_srv_cfg = {}
                                        del_srv_cfg = {}
                                        for srv_attr in SERVER_ATTRIBUTES:
                                            if srv_attr != 'address':
                                                if srv_attr in server:
                                                    if srv_attr not in match_server:
                                                        add_srv_cfg[srv_attr] = server[srv_attr]
                                                    elif server[srv_attr] != match_server[srv_attr]:
                                                        add_srv_cfg[srv_attr] = server[srv_attr]
                                                        del_srv_cfg[srv_attr] = match_server[srv_attr]
                                                elif srv_attr in match_server:
                                                    del_srv_cfg[srv_attr] = match_server[srv_attr]
                                        if add_srv_cfg:
                                            add_srv_cfg['address'] = address
                                            add_srv.append(add_srv_cfg)
                                        if del_srv_cfg:
                                            del_srv_cfg['address'] = address
                                            if del_srv_cfg != match_server:
                                                del_srv.append(del_srv_cfg)
                                            else:
                                                del_srv.append({'address': address})
                                for server in have_conf[attr]:
                                    address = server.get('address')
                                    match_server = next((item for item in conf[attr] if item['address'] == address), None)
                                    if not match_server:
                                        del_srv.append({'address': address})
                                if add_srv:
                                    add_cfg['servers'] = add_srv
                                if del_srv:
                                    del_cfg['servers'] = del_srv
                            elif attr == 'map':
                                add_map, del_map = {}, {}
                                for map_attr in MAP_ATTRIBUTES:
                                    if map_attr in conf[attr]:
                                        if map_attr not in have_conf[attr]:
                                            add_map[map_attr] = conf[attr][map_attr]
                                        elif conf[attr][map_attr] != have_conf[attr][map_attr]:
                                            if map_attr != 'map_remote_groups_to_sonic_roles':
                                                add_map_list, del_map_list = [], []
                                                for map in conf[attr][map_attr]:
                                                    match_map = next((item for item in have_conf[attr][map_attr] if item['from'] == map['from']), None)
                                                    if not match_map:
                                                        add_map_list.append(map)
                                                    elif map['to'] != match_map['to']:
                                                        add_map_list.append(map)
                                                        del_map_list.append(match_map)
                                                for map in have_conf[attr][map_attr]:
                                                    match_map = next((item for item in conf[attr][map_attr] if item['from'] == map['from']), None)
                                                    if not match_map:
                                                        del_map_list.append(map)
                                                if add_map_list:
                                                    add_map[map_attr] = add_map_list
                                                if del_map_list:
                                                    del_map[map_attr] = del_map_list
                                            else:
                                                add_map_list, del_map_list = [], []
                                                for map in conf[attr][map_attr]:
                                                    match_map = next((i for i in have_conf[attr][map_attr] if i['remote_group'] == map['remote_group']), None)
                                                    if not match_map:
                                                        add_map_list.append(map)
                                                    else:
                                                        added_roles = set(map['sonic_roles']) - set(match_map['sonic_roles'])
                                                        removed_roles = set(match_map['sonic_roles']) - set(map['sonic_roles'])
                                                        common = set(match_map['sonic_roles']) & set(map['sonic_roles'])
                                                        if added_roles or common:
                                                            roles = list(added_roles) + list(common)
                                                            add_map_list.append({'remote_group': map['remote_group'], 'sonic_roles': roles})
                                                        if removed_roles:
                                                            roles = list(removed_roles) + list(common)
                                                            del_map_list.append({'remote_group': map['remote_group'], 'sonic_roles': roles})
                                                for map in have_conf[attr][map_attr]:
                                                    match_map = next((i for i in conf[attr][map_attr] if i['remote_group'] == map['remote_group']), None)
                                                    if not match_map:
                                                        del_map_list.append({'remote_group': map['remote_group']})
                                                if add_map_list:
                                                    add_map[map_attr] = add_map_list
                                                if del_map_list:
                                                    del_map[map_attr] = del_map_list
                                    elif map_attr in have_conf[attr]:
                                        del_map[map_attr] = have_conf[attr][map_attr]
                                if add_map:
                                    add_cfg[attr] = add_map
                                if del_map:
                                    del_cfg[attr] = del_map
                    elif attr in have_conf:
                        del_cfg[attr] = have_conf[attr]
                if add_cfg:
                    add_cfg['name'] = name
                    add_config.append(add_cfg)
                if del_cfg:
                    del_cfg['name'] = name
                    del_config.append(del_cfg)

        if self._module.params['state'] == 'overridden':
            for conf in have:
                name = conf.get('name')
                want_conf = next((item for item in want if item['name'] == name), None)

                if not want_conf:
                    del_config.append({'name': name})

        return add_config, del_config

    def get_create_ldap_requests(self, commands):
        requests = []

        if not commands:
            return requests

        for cmd in commands:
            payload = {'openconfig-system:server-group': []}
            payload_attr = {}
            name = cmd.get('name', None)
            for attr in cmd:
                if cmd.get(attr) is not None:
                    if attr not in ('name', 'bindpw', 'source_interface', 'map', 'servers'):
                        attribute = CONFIG_ATTRIBUTES.get(attr)
                        attribute = attribute or ONLY_NSS_ATTRIBUTES.get(attr)
                        attribute = attribute or ONLY_PAM_ATTRIBUTES.get(attr)
                        attribute = attribute or ONLY_SUDO_ATTRIBUTES.get(attr)
                        if name == 'global':
                            ATTRIBUTES = {
                                'vrf': 'vrf-name',
                                'security_profile': 'security_profile',
                                'nss_skipmembers': 'nss-skipmembers'
                            }
                            attribute = attribute or ATTRIBUTES.get(attr)
                        if attribute:
                            payload_attr.setdefault(modName, {})
                            payload_attr[modName].setdefault('config', {})
                            value = cmd[attr].upper() if attribute in ('ssl', 'scope') else cmd[attr]
                            payload_attr[modName]['config'][attribute] = value
                    elif attr == 'bindpw':
                        bindpw = cmd.get('bindpw')
                        if bindpw:
                            pwd = cmd['bindpw'].get('pwd')
                            is_encrypted = cmd['bindpw'].get('encrypted')
                            if pwd is not None:
                                payload_attr.setdefault(modName, {})
                                payload_attr[modName].setdefault('config', {})
                                payload_attr[modName]['config']['bind-pw'] = pwd
                                if is_encrypted is not None:
                                    payload_attr[modName]['config']['encrypted'] = is_encrypted
                    elif attr == 'source_interface':
                        payload_attr.setdefault('config', {})
                        payload_attr['config']['source-interface'] = cmd['source_interface']
                    elif attr == 'map':
                        payload_attr.setdefault(modName, {})
                        payload_attr[modName].setdefault('maps', {})
                        payload_attr[modName]['maps'].setdefault('map', [])

                        if cmd.get('map'):
                            map_payload_list = []
                            for map_attributes in cmd['map']:
                                for map_attr in cmd['map'].get(map_attributes, []):
                                    map_payload = {}
                                    if map_attributes != 'map_remote_groups_to_sonic_roles':
                                        from_val = map_attr.get('from')
                                        to_val = map_attr.get('to')
                                        if from_val is not None and to_val is not None:
                                            map_payload = {
                                                'config': {
                                                    'to': to_val
                                                },
                                                'from': from_val,
                                                'name': MAP_ATTRIBUTES[map_attributes]
                                            }
                                    else:
                                        sonic_roles = map_attr.get('sonic_roles', [])
                                        sonic_roles_list = []
                                        for role in sonic_roles:
                                            sonic_roles_list.append(role)
                                        remote_group = map_attr.get('remote_group', '')
                                        if sonic_roles and remote_group:
                                            map_payload = {
                                                'config': {
                                                    'to': ','.join(sonic_roles_list),
                                                },
                                                'from': remote_group,
                                                'name': MAP_ATTRIBUTES[map_attributes]
                                            }
                                    if map_payload:
                                        map_payload_list.append(map_payload)
                            if map_payload_list:
                                payload_attr[modName]['maps']['map'] = map_payload_list
                    elif attr == 'servers':
                        payload_attr.setdefault('servers', {})
                        payload_attr['servers'].setdefault('server', [])

                        server_payload_list = []

                        for server in cmd['servers']:
                            server_payload = {}
                            for server_attr in server:
                                if server_attr == 'address':
                                    server_payload['address'] = server['address']
                                    server_payload['config'] = {'address': server['address']}
                                else:
                                    server_payload.setdefault('openconfig-aaa-ldap-ext:ldap', {})
                                    server_payload['openconfig-aaa-ldap-ext:ldap'].setdefault('config', {})
                                    server_attr_val = server[server_attr]
                                    if server_attr in ('ssl', 'server_type'):
                                        server_attr_val = server_attr_val.upper()
                                    server_payload['openconfig-aaa-ldap-ext:ldap']['config'][SERVER_ATTRIBUTES[server_attr]] = server_attr_val
                            if server_payload:
                                server_payload_list.append(server_payload)
                        if server_payload_list:
                            payload_attr['servers']['server'] = server_payload_list

            if payload_attr:
                payload_attr['name'] = LDAP_GROUPS[name]
                payload_attr.setdefault('config', {})
                payload_attr['config']['name'] = LDAP_GROUPS[name]
                payload['openconfig-system:server-group'].append(payload_attr)
                requests.append({'path': base_url.format(name=LDAP_GROUPS[name]), 'method': PATCH, 'data': payload})
        return requests

    def get_delete_ldap_requests(self, commands, have, is_delete_all):
        commands_del, requests = [], []

        for conf in commands:
            delete_cmd = {}
            name = conf.get('name')
            have_conf = next((item for item in have if item['name'] == name), None)
            if have_conf:
                if len(conf) == 1 or is_delete_all or have_conf == conf:
                    # Delete the LDAP server type configuration completely
                    delete_cmd = {'name': name}
                    commands_del.append(delete_cmd)
                    url = base_url.format(name=LDAP_GROUPS[name])
                    requests.append({'path': url, 'method': DELETE})
                    continue

                for attr in conf:
                    if attr not in ('name', 'bindpw', 'source_interface', 'map', 'servers'):
                        if have_conf.get(attr):
                            attribute = CONFIG_ATTRIBUTES.get(attr)
                            attribute = attribute or ONLY_NSS_ATTRIBUTES.get(attr)
                            attribute = attribute or ONLY_PAM_ATTRIBUTES.get(attr)
                            attribute = attribute or ONLY_SUDO_ATTRIBUTES.get(attr)
                            if name == 'global':
                                ATTRIBUTES = {
                                    'vrf': 'vrf-name',
                                    'security_profile': 'security_profile',
                                    'nss_skipmembers': 'nss-skipmembers'
                                }
                                attribute = attribute or ATTRIBUTES.get(attr)
                            if attribute and have_conf[attr] == conf[attr]:
                                delete_cmd[attr] = conf[attr]
                                url = base_url.format(name=LDAP_GROUPS[name]) + '/%s/config/%s' % (modName, attribute)
                                requests.append({'path': url, 'method': DELETE})
                    elif attr == 'bindpw':
                        if have_conf.get(attr) is not None and have_conf[attr] == conf[attr]:
                            delete_cmd[attr] = conf[attr]
                            url = base_url.format(name=LDAP_GROUPS[name]) + '/%s/config/%s' % (modName, 'bind-pw')
                            requests.append({'path': url, 'method': DELETE})
                    elif attr == 'source_interface':
                        if have_conf.get(attr) is not None and have_conf[attr] == conf[attr]:
                            delete_cmd[attr] = conf[attr]
                            url = base_url.format(name=LDAP_GROUPS[name]) + '/config/%s' % ('source-interface')
                            requests.append({'path': url, 'method': DELETE})
                    elif attr == 'map':
                        map_cmd, map_requests = self.get_delete_ldap_map_request(name, conf.get(attr), have_conf.get(attr))
                        if map_cmd and map_requests:
                            delete_cmd['map'] = map_cmd
                            requests.extend(map_requests)
                    elif attr == 'servers':
                        server_cmd, server_requests = self.get_delete_ldap_servers_request(name, conf.get(attr), have_conf.get(attr), is_delete_all)
                        if server_cmd and server_requests:
                            delete_cmd['servers'] = server_cmd
                            requests.extend(server_requests)

            if delete_cmd:
                delete_cmd['name'] = name
                commands_del.append(delete_cmd)

        return commands_del, requests

    def get_delete_ldap_map_request(self, name, conf, have_conf):
        commands, requests = {}, []

        if not conf:
            return commands, requests

        for attr in conf:
            map_attr = []
            if conf.get(attr) and attr in have_conf and have_conf.get(attr):
                for map_list in conf[attr]:
                    from_val, match = None, None
                    if attr != 'map_remote_groups_to_sonic_roles':
                        from_val = map_list.get('from')
                        match = next((item for item in have_conf[attr] if item['from'] == from_val), None)
                    else:
                        from_val = map_list.get('remote_group')
                        match = next((item for item in have_conf[attr] if item['remote_group'] == from_val), None)
                    if from_val is not None and match is not None:
                        map_attr.append(match)
                        from_val = from_val.replace('\\\\', '\\').replace('/', '%2F')
                        url = base_url.format(name=LDAP_GROUPS[name]) + '/%s/maps/map=%s,%s' % (modName, MAP_ATTRIBUTES[attr], from_val)
                        requests.append({'path': url, 'method': DELETE})
            if map_attr:
                commands[attr] = map_attr
        return commands, requests

    def get_delete_ldap_servers_request(self, name, conf, have_conf, is_delete_all):
        commands, requests = [], []

        if not conf:
            return commands, requests

        for server in conf:
            server_attr = {}
            address = server.get('address')
            if address:
                match = next((item for item in have_conf if item['address'] == address), None)
                if match:
                    if len(server) == 1 or is_delete_all:
                        server_attr = {'address': address}
                        url = base_url.format(name=LDAP_GROUPS[name]) + '/servers/server=%s' % (address)
                        requests.append({'path': url, 'method': DELETE})
                    else:
                        for attr in server:
                            if attr != 'address':
                                if server.get(attr) and match.get(attr) and server[attr] == match[attr]:
                                    server_attr[attr] = server[attr]
                                    url = base_url.format(name=LDAP_GROUPS[name])
                                    url = url + '/servers/server=%s/%s/config/%s' % (address, modName, SERVER_ATTRIBUTES[attr])
                                    requests.append({'path': url, 'method': DELETE})
            if server_attr:
                server_attr['address'] = address
                commands.append(server_attr)
        return commands, requests

    def sort_lists_in_config(self, config):
        if config:
            config.sort(key=lambda x: x.get('name'))
            for cfg in config:
                if cfg.get('servers'):
                    cfg['servers'].sort(key=lambda x: x['address'])
                if cfg.get('map'):
                    if cfg['map'].get('attributes'):
                        cfg['map']['attributes'].sort(key=lambda x: x['from'])
                    if cfg['map'].get('default_attribute'):
                        cfg['map']['default_attribute'].sort(key=lambda x: x['from'])
                    if cfg['map'].get('objectclass'):
                        cfg['map']['objectclass'].sort(key=lambda x: x['from'])
                    if cfg['map'].get('override_attribute'):
                        cfg['map']['override_attribute'].sort(key=lambda x: x['from'])
                    if cfg['map'].get('map_remote_groups_to_sonic_roles'):
                        cfg['map']['map_remote_groups_to_sonic_roles'].sort(key=lambda x: x['remote_group'])
                        for group in cfg['map']['map_remote_groups_to_sonic_roles']:
                            if group.get('sonic_roles'):
                                group['sonic_roles'].sort()

    def validate_and_normalize_config(self, config_list):
        updated_config_list = []

        # To ensure that the configuring attribute belongs only to those groups that are supported
        # For example, 'sudoers_search_filter' only supported in 'global' and 'sudo'.
        # Hence, for 'nss' and 'pam', this attr is ignored by this function
        for config in config_list:
            cfg = {}
            name = config.get('name')
            for attr in config:
                if attr == 'name':
                    continue
                elif attr in ATTRIBUTES[name]:
                    cfg[attr] = config[attr]
                else:
                    self._module.fail_json(msg='The {0} attribute is not supported for the LDAP {1} type.'.format(attr, name))
            if cfg or len(config) == 1:
                cfg['name'] = name
                updated_config_list.append(cfg)

        validate_config(self._module.argument_spec, {'config': updated_config_list})

        return updated_config_list

    def _get_generated_config(self, commands, have, state):
        """Get generated config"""

        new_config = remove_empties_from_list(get_new_config(commands, have, TEST_KEYS_formatted_diff))
        for conf in new_config:
            name = conf.get('name')
            if name == 'global':
                maps = conf.get('map')
                if maps:
                    # To handle check_mode merged case when sonic_roles is set
                    if maps.get('map_remote_groups_to_sonic_roles'):
                        match_conf = next((item for item in commands if item['name'] == name), None)
                        if match_conf:
                            match_maps = match_conf.get('map')
                            if match_maps:
                                for group in maps.get('map_remote_groups_to_sonic_roles', {}):
                                    remote_group = group.get('remote_group')
                                    match_groups = match_maps.get('map_remote_groups_to_sonic_roles', {})
                                    match_group = next((item for item in match_groups if item['remote_group'] == remote_group), None)
                                    if match_group:
                                        if state != 'deleted':
                                            group['sonic_roles'] = match_group.get('sonic_roles')

        return new_config
