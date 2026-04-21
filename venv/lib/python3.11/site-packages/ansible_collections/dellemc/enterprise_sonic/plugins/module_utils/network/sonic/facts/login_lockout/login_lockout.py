#
# -*- coding: utf-8 -*-
# Copyright 2023 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic login_lockout fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.login_lockout.login_lockout import Login_lockoutArgs


from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)

from ansible.module_utils.connection import ConnectionError


GET = "get"


class Login_lockoutFacts(object):
    """ The sonic login_lockout fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Login_lockoutArgs.argument_spec
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
        """ Populate the facts for login_lockout
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass

        obj = self.get_all_login_lockout_configs()

        ansible_facts['ansible_network_resources'].pop('login_lockout', None)
        facts = {}
        if obj:
            params = utils.validate_config(self.argument_spec, {'config': obj})
            facts['login_lockout'] = utils.remove_empties(params['config'])

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

    def get_all_login_lockout_configs(self):
        """Get all the login lockout configured in the device"""
        request = [{"path": "data/openconfig-system:system/openconfig-system-ext:login/lockout/config", "method": GET}]
        login_lockout_data = {}
        raw_login_lockout_data = {}
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)
        login_lockout_data['period'] = 0
        login_lockout_data['max_retries'] = 3
        login_lockout_data['console_exempt'] = False

        if 'openconfig-system-ext:config' in response[0][1]:
            raw_login_lockout_data = response[0][1]['openconfig-system-ext:config']

        if 'console-exempt' in raw_login_lockout_data:
            login_lockout_data['console_exempt'] = raw_login_lockout_data['console-exempt']
        if 'max-retry' in raw_login_lockout_data:
            login_lockout_data['max_retries'] = raw_login_lockout_data['max-retry']
        if 'lockout-period' in raw_login_lockout_data:
            login_lockout_data['period'] = raw_login_lockout_data['lockout-period']

        return login_lockout_data
