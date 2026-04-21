#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic aaa fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    remove_empties
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.aaa.aaa import AaaArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)

AAA_PATH = '/data/openconfig-system:system/aaa'


class AaaFacts(object):
    """ The sonic aaa fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = AaaArgs.argument_spec
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
        """ Populate the facts for aaa
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []

        if not data:
            data = self.update_aaa(self._module)
        objs = data
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['aaa'] = remove_empties(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_config(self, module, path, key_name):
        """Retrieve OC configuration from device"""
        cfg = None
        get_path = '%s/%s' % (AAA_PATH, path)
        request = {'path': get_path, 'method': 'get'}

        try:
            response = edit_config(module, to_request(module, request))
            if key_name in response[0][1]:
                cfg = response[0][1].get(key_name)
        except Exception as exc:
            # Avoid raising error when there is no configuration
            if 'Resource not found' in str(exc):
                pass
            else:
                module.fail_json(msg=str(exc), code=exc.code)

        return cfg

    def update_aaa(self, module):
        """Transform OC configuration to Ansible argspec"""
        config_dict = {}
        bool_dict = {'True': True, 'False': False, 'disable': False, 'enable': True}

        # Authentication configuration handling
        authentication_cfg = self.get_config(module, 'authentication/config', 'openconfig-system:config')

        if authentication_cfg:
            authentication_dict = {}
            auth_method = authentication_cfg.get('authentication-method')
            console_auth_local = authentication_cfg.get('console-authentication-local')
            failthrough = authentication_cfg.get('failthrough')
            mfa_auth_method = authentication_cfg.get('openconfig-mfa:mfa-authentication-method')
            login_mfa_console = authentication_cfg.get('openconfig-mfa:login-mfa-console', 'disable')

            if auth_method:
                authentication_dict['auth_method'] = auth_method
            if console_auth_local is not None:
                authentication_dict['console_auth_local'] = console_auth_local
            if failthrough:
                authentication_dict['failthrough'] = bool_dict[failthrough]
            if mfa_auth_method:
                authentication_dict['mfa_auth_method'] = mfa_auth_method
            authentication_dict['login_mfa_console'] = bool_dict[login_mfa_console]
            if authentication_dict:
                config_dict['authentication'] = authentication_dict

        # Authorization configuration handling
        authorization_dict = {}
        commands_auth_method = self.get_config(module, 'authorization/openconfig-aaa-tacacsplus-ext:commands/config/authorization-method',
                                               'openconfig-aaa-tacacsplus-ext:authorization-method')
        login_auth_method = self.get_config(module, 'authorization/openconfig-aaa-ext:login/config/authorization-method',
                                            'openconfig-aaa-ext:authorization-method')

        if commands_auth_method:
            authorization_dict['commands_auth_method'] = commands_auth_method
        if login_auth_method:
            authorization_dict['login_auth_method'] = login_auth_method
        if authorization_dict:
            config_dict['authorization'] = authorization_dict

        # Name-service configuration handling
        name_service_cfg = self.get_config(module, 'openconfig-aaa-ext:name-service/config', 'openconfig-aaa-ext:config')
        if name_service_cfg:
            name_service_dict = {}
            group = name_service_cfg.get('group-method')
            netgroup = name_service_cfg.get('netgroup-method')
            passwd = name_service_cfg.get('passwd-method')
            shadow = name_service_cfg.get('shadow-method')
            sudoers = name_service_cfg.get('sudoers-method')

            if group:
                name_service_dict['group'] = group
            if netgroup:
                name_service_dict['netgroup'] = netgroup
            if passwd:
                name_service_dict['passwd'] = passwd
            if shadow:
                name_service_dict['shadow'] = shadow
            if sudoers:
                name_service_dict['sudoers'] = sudoers
            if name_service_dict:
                config_dict['name_service'] = name_service_dict

        return config_dict
