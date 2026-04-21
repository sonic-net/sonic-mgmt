#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic ssh fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ssh.ssh import SshArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

GET = "get"


class SshFacts(object):
    """ The sonic ssh fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = SshArgs.argument_spec
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
        obj = self.get_all_ssh_configs()

        ansible_facts['ansible_network_resources'].pop('ssh', None)
        facts = {}
        if obj:
            params = utils.validate_config(self.argument_spec, {'config': obj})
            facts['ssh'] = params['config']

        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_all_ssh_client_configs(self):
        """Get all the SSH client algorithm configurations on the device"""
        request = [{"path": "data/openconfig-system:system/openconfig-system-ext:ssh-client/config", "method": GET}]
        ssh_client_data = {}
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)
        if 'openconfig-system-ext:config' in response[0][1]:
            raw_ssh_client_data = response[0][1]['openconfig-system-ext:config']
            if 'ciphers' in raw_ssh_client_data:
                ssh_client_data['cipher'] = raw_ssh_client_data['ciphers']
            if 'kexalgorithms' in raw_ssh_client_data:
                ssh_client_data['kex'] = raw_ssh_client_data['kexalgorithms']
            if 'macs' in raw_ssh_client_data:
                ssh_client_data['mac'] = raw_ssh_client_data['macs']
        return ssh_client_data

    def get_all_ssh_configs(self):
        """Transform OC configuration to Ansible argspec"""
        ssh_data = {}

        ssh_client_data = self.get_all_ssh_client_configs()

        if ssh_client_data:
            ssh_data['client'] = ssh_client_data

        return ssh_data
