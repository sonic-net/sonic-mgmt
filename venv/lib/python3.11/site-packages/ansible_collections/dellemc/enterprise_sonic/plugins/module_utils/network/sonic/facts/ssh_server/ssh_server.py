#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic ssh server fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ssh_server.ssh_server import Ssh_serverArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

GET = "get"


class Ssh_serverFacts(object):
    """ The sonic ssh fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Ssh_serverArgs.argument_spec
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
        """ Populate the facts for ssh
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = self.get_all_ssh_configs()

        ansible_facts['ansible_network_resources'].pop('ssh_server', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['ssh_server'] = remove_empties(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_all_ssh_server_global_configs(self):
        """Get all the SSH server global configurations on the device"""
        request = [{"path": "data/openconfig-system:system/ssh-server/openconfig-system-ext:ssh-server-globals/config", "method": GET}]
        ssh_server_globals_data = {}
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)
        if 'openconfig-system-ext:config' in response[0][1]:
            raw_ssh_server_globals_data = response[0][1]['openconfig-system-ext:config']
            if 'password-authentication' in raw_ssh_server_globals_data:
                ssh_server_globals_data['password_authentication'] = raw_ssh_server_globals_data['password-authentication']
            if 'publickey-authentication' in raw_ssh_server_globals_data:
                ssh_server_globals_data['publickey_authentication'] = raw_ssh_server_globals_data['publickey-authentication']
            if 'max-auth-retries' in raw_ssh_server_globals_data:
                ssh_server_globals_data['max_auth_retries'] = raw_ssh_server_globals_data['max-auth-retries']
            if 'disable-forwarding' in raw_ssh_server_globals_data:
                ssh_server_globals_data['disable_forwarding'] = raw_ssh_server_globals_data['disable-forwarding']
            if 'permit-root-login' in raw_ssh_server_globals_data:
                ssh_server_globals_data['permit_root_login'] = raw_ssh_server_globals_data['permit-root-login']
            if 'permit-user-rc' in raw_ssh_server_globals_data:
                ssh_server_globals_data['permit_user_rc'] = raw_ssh_server_globals_data['permit-user-rc']
            if 'x11-forwarding' in raw_ssh_server_globals_data:
                ssh_server_globals_data['x11_forwarding'] = raw_ssh_server_globals_data['x11-forwarding']
            if 'permit-user-environment' in raw_ssh_server_globals_data:
                ssh_server_globals_data['permit_user_environment'] = raw_ssh_server_globals_data['permit-user-environment']
            if 'ciphers' in raw_ssh_server_globals_data:
                ssh_server_globals_data['ciphers'] = raw_ssh_server_globals_data['ciphers']
            if 'kexalgorithms' in raw_ssh_server_globals_data:
                ssh_server_globals_data['kexalgorithms'] = raw_ssh_server_globals_data['kexalgorithms']
            if 'macs' in raw_ssh_server_globals_data:
                ssh_server_globals_data['macs'] = raw_ssh_server_globals_data['macs']
            if 'hostkeyalgorithms' in raw_ssh_server_globals_data:
                ssh_server_globals_data['hostkeyalgorithms'] = raw_ssh_server_globals_data['hostkeyalgorithms']

        return ssh_server_globals_data

    def get_all_ssh_configs(self):
        """Transform OC configuration to Ansible argspec"""
        ssh_data = {}

        ssh_server_globals_data = self.get_all_ssh_server_global_configs()
        if ssh_server_globals_data:
            ssh_data['server_globals'] = ssh_server_globals_data

        return ssh_data
