#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic ldap fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils \
    import (
        remove_empties_from_list
    )
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ldap.ldap import LdapArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

LDAP_GROUPS = {'LDAP': 'global', 'LDAP_NSS': 'nss', 'LDAP_PAM': 'pam', 'LDAP_SUDO': 'sudo'}
CONFIG_ATTRIBUTES = {
    'base': 'base',
    'bind-dn': 'binddn',
    'bind-pw': 'bindpw',
    'bind-time-limit': 'bind_timelimit',
    'port': 'port',
    'search-time-limit': 'timelimit',
    'ssl': 'ssl',
    'retransmit-attempts': 'retry',
    'version': 'version'
}

ONLY_NSS_ATTRIBUTES = {
    'nss-base-group': 'nss_base_group',
    'nss-base-netgroup': 'nss_base_netgroup',
    'nss-base-passwd': 'nss_base_passwd',
    'nss-base-shadow': 'nss_base_shadow',
    'nss-base-sudoers': 'nss_base_sudoers',
    'nss-initgroups-ignoreusers': 'nss_initgroups_ignoreusers',
    'scope': 'scope',
    'idle-time-limit': 'idle_timelimit'
}

ONLY_PAM_ATTRIBUTES = {
    'pam-filter': 'pam_filter',
    'pam-group-dn': 'pam_group_dn',
    'pam-login-attribute': 'pam_login_attribute',
    'pam-member-attribute': 'pam_member_attribute',
    'scope': 'scope',
    'nss-base-passwd': 'nss_base_passwd',
}

ONLY_SUDO_ATTRIBUTES = {
    'sudoers-base': 'sudoers_base',
    'sudoers-search-filter': 'sudoers_search_filter'
}

MAP_ATTRIBUTES = {
    'ATTRIBUTE': 'attribute',
    'DEFAULT_ATTRIBUTE_VALUE': 'default_attribute',
    'OBJECTCLASS': 'objectclass',
    'OVERRIDE_ATTRIBUTE_VALUE': 'override_attribute',
    'CUSTOM_SONIC_ROLES_ATTRIBUTE_VALUE': 'map_remote_groups_to_sonic_roles'
}

SERVER_ATTRIBUTES = {
    'use-type': 'server_type',
    'port': 'port',
    'ssl': 'ssl',
    'priority': 'priority',
    'retransmit-attempts': 'retry'
}


class LdapFacts(object):
    """ The sonic ldap fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = LdapArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for ldap
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []
        if connection:  # just for linting purposes, remove
            pass

        all_ldap_configs = {}

        if not data:
            all_ldap_configs = self.get_ldap()

        for ldap_config in all_ldap_configs:
            obj = self.render_config(self.generated_spec, ldap_config)
            if obj:
                objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('ldap', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['ldap'] = remove_empties_from_list(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def render_config(self, spec, conf):
        """
        Render config as dictionary structure and delete keys
          from spec for null values

        :param spec: The facts tree, generated from the argspec
        :param conf: The configuration
        :rtype: dictionary
        :returns: The generated config
        """
        return conf

    def get_ldap(self):
        request = [{"path": 'data/openconfig-system:system/aaa/server-groups', "method": "GET"}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        ldap_configs = []

        if 'openconfig-system:server-groups' in response[0][1]:
            server_groups = response[0][1]['openconfig-system:server-groups']
            if server_groups and server_groups.get('server-group'):
                server_groups = server_groups['server-group']
                for server_group in server_groups:
                    name = server_group.get('name')
                    servers = server_group.get('servers', {})
                    if "LDAP" in name:
                        ldap_config = {}
                        if "openconfig-aaa-ldap-ext:ldap" in server_group:
                            if name == "LDAP":
                                ldap_config = self.get_ldap_global_config(server_group['openconfig-aaa-ldap-ext:ldap'], servers)
                                if "config" in server_group:
                                    if server_group['config'].get('source-interface'):
                                        ldap_config['source_interface'] = server_group['config']['source-interface']
                            elif name == "LDAP_NSS":
                                ldap_config = self.get_ldap_subtype_config(server_group['openconfig-aaa-ldap-ext:ldap'], 'NSS')
                            elif name == "LDAP_PAM":
                                ldap_config = self.get_ldap_subtype_config(server_group['openconfig-aaa-ldap-ext:ldap'], 'PAM')
                            elif name == "LDAP_SUDO":
                                ldap_config = self.get_ldap_subtype_config(server_group['openconfig-aaa-ldap-ext:ldap'], 'SUDO')
                        if ldap_config:
                            ldap_config['name'] = LDAP_GROUPS[name]
                            ldap_configs.append(ldap_config)
        return ldap_configs

    def get_ldap_global_config(self, ldap_config, servers):
        ATTRIBUTES = {
            "vrf-name": "vrf",
            "security_profile": "security_profile",
            "nss-skipmembers": "nss_skipmembers"
        }
        global_config, map_config = {}, {}
        config = ldap_config.get('config', [])
        maps = ldap_config.get('maps', {})

        for cfg in config:
            if cfg not in ("bind-pw", "encrypted"):
                attribute = CONFIG_ATTRIBUTES.get(cfg)
                attribute = attribute or ONLY_NSS_ATTRIBUTES.get(cfg)
                attribute = attribute or ONLY_PAM_ATTRIBUTES.get(cfg)
                attribute = attribute or ONLY_SUDO_ATTRIBUTES.get(cfg)
                attribute = attribute or ATTRIBUTES.get(cfg)
                if attribute:
                    global_config[attribute] = config[cfg].lower() if attribute in ("ssl", "scope") else config[cfg]
            else:
                if 'bind-pw' in config and config.get('bind-pw') not in (None, ''):
                    global_config.setdefault("bindpw", {})
                    global_config['bindpw']['pwd'] = config['bind-pw']
                    global_config['bindpw']['encrypted'] = config['encrypted']
        if maps:
            maps = maps.get('map', [])
        for map in maps:
            cfg = map.get('config')
            if cfg:
                from_value = cfg.get("from")
                to_value = cfg.get("to")
                attr = cfg.get("name")
                if from_value and to_value and attr:
                    map_config.setdefault(MAP_ATTRIBUTES[attr], [])
                    if attr != 'CUSTOM_SONIC_ROLES_ATTRIBUTE_VALUE':
                        map_config[MAP_ATTRIBUTES[attr]].append({"from": from_value, "to": to_value})
                    else:
                        sonic_roles = []
                        roles = to_value.split(",")
                        for role in roles:
                            sonic_roles.append(role)
                        map_config[MAP_ATTRIBUTES[attr]].append({"remote_group": from_value, "sonic_roles": sonic_roles})

        if map_config:
            global_config['map'] = map_config

        if servers:
            servers = servers.get('server', [])
            server_config = self.get_server_config(servers)
            if server_config:
                global_config['servers'] = server_config

        return global_config

    def get_ldap_subtype_config(self, ldap_config, ldap_subtype):
        subtype_config = {}
        enum_subtype = {
            'NSS': ONLY_NSS_ATTRIBUTES,
            'PAM': ONLY_PAM_ATTRIBUTES,
            'SUDO': ONLY_SUDO_ATTRIBUTES
        }
        config = ldap_config.get('config')
        for cfg in config:
            if cfg not in ("bind-pw", "encrypted"):
                attribute = CONFIG_ATTRIBUTES.get(cfg)
                attribute = attribute or enum_subtype[ldap_subtype].get(cfg)
                if attribute:
                    subtype_config[attribute] = config[cfg].lower() if attribute in ("ssl", "scope") else config[cfg]
            else:
                if 'bind-pw' in config and config.get('bind-pw') not in (None, ''):
                    subtype_config.setdefault("bindpw", {})
                    subtype_config['bindpw']['pwd'] = config['bind-pw']
                    subtype_config['bindpw']['encrypted'] = config['encrypted']

        return subtype_config

    def get_server_config(self, servers):
        server_configs = []
        for server in servers:
            server_config = {}
            address = server.get('address')
            if address:
                server_config['address'] = address
            config = server.get('openconfig-aaa-ldap-ext:ldap', {})
            if config:
                config = config.get('config', {})
            for cfg in config:
                attribute = SERVER_ATTRIBUTES.get(cfg)
                if attribute:
                    server_config[attribute] = config[cfg].lower() if attribute in ("ssl", "server_type") else config[cfg]
            if server_config:
                server_configs.append(server_config)
        return server_configs
