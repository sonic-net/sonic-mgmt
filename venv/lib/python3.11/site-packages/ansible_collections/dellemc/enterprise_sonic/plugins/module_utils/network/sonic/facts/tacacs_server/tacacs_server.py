#
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic tacas server fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.tacacs_server.tacacs_server import Tacacs_serverArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

GET = "get"


class Tacacs_serverFacts(object):
    """ The sonic tacas server fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Tacacs_serverArgs.argument_spec
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
        """ Populate the facts for tacacs_server
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass

        obj = None
        if not data:
            # typically data is populated from the current device configuration
            # data = connection.get('show running-config | section ^interface')
            # using mock data instead
            data = self.get_all_tacacs_server()

            obj = self.render_config(self.generated_spec, data)

        ansible_facts['ansible_network_resources'].pop('tacacs_server', None)
        facts = {}
        if obj:
            facts['tacacs_server'] = {}
            params = utils.validate_config(self.argument_spec, {'config': obj})
            if params:
                facts['tacacs_server'] = params['config']
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

    def get_all_tacacs_server(self):
        """Get all the tacacs_server configured in the device"""
        request = [{"path": "data/openconfig-system:system/aaa/server-groups/server-group=TACACS/config", "method": GET}]
        tacacs_server_data = {}
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        if "openconfig-system:config" in response[0][1]:
            raw_tacacs_global_data = response[0][1].get("openconfig-system:config", {})

            if 'auth-type' in raw_tacacs_global_data:
                tacacs_server_data['auth_type'] = raw_tacacs_global_data['auth-type']
            if 'secret-key' in raw_tacacs_global_data:
                tacacs_server_data['key'] = raw_tacacs_global_data['secret-key']
            if 'source-interface' in raw_tacacs_global_data:
                tacacs_server_data['source_interface'] = raw_tacacs_global_data['source-interface']
            if 'timeout' in raw_tacacs_global_data:
                tacacs_server_data['timeout'] = raw_tacacs_global_data['timeout']

        request = [{"path": "data/openconfig-system:system/aaa/server-groups/server-group=TACACS/servers", "method": GET}]
        hosts = []
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        raw_tacacs_server_list = []
        if "openconfig-system:servers" in response[0][1]:
            raw_tacacs_server_list = response[0][1].get("openconfig-system:servers", {}).get('server', [])

        for tacacs_host in raw_tacacs_server_list:
            host_data = {}
            if 'address' in tacacs_host:
                host_data['name'] = tacacs_host['address']
                cfg = tacacs_host.get('config', None)
                if cfg:
                    if 'auth-type' in cfg:
                        host_data['auth_type'] = cfg['auth-type']
                    if 'priority' in cfg:
                        host_data['priority'] = cfg['priority']
                    if 'vrf' in cfg:
                        host_data['vrf'] = cfg['vrf']
                    if 'timeout' in cfg:
                        host_data['timeout'] = cfg['timeout']
                if tacacs_host.get('tacacs', None) and tacacs_host['tacacs'].get('config', None):
                    tacas_cfg = tacacs_host['tacacs']['config']
                    if tacas_cfg.get('port', None):
                        host_data['port'] = tacas_cfg['port']
                    if tacas_cfg.get('secret-key', None):
                        host_data['key'] = tacas_cfg['secret-key']
            if host_data:
                hosts.append(host_data)

        if hosts:
            tacacs_server_data['servers'] = {'host': hosts}

        return tacacs_server_data
