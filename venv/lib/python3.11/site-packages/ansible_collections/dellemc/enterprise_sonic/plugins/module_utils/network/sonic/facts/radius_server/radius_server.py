#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.radius_server.radius_server import Radius_serverArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

GET = "get"


class Radius_serverFacts(object):
    """ The sonic tacas server fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Radius_serverArgs.argument_spec
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
        """ Populate the facts for radius_server
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
            data = self.get_all_radius_server()

            obj = self.render_config(self.generated_spec, data)

        ansible_facts['ansible_network_resources'].pop('radius_server', None)
        facts = {}
        if obj:
            facts['radius_server'] = {}
            params = utils.validate_config(self.argument_spec, {'config': obj})
            if params:
                facts['radius_server'] = params['config']
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

    def get_all_radius_server(self):
        """Get all the radius_server configured in the device"""
        request = [{"path": "data/openconfig-system:system/aaa/server-groups/server-group=RADIUS/config", "method": GET}]
        radius_server_data = {}
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        if "openconfig-system:config" in response[0][1]:
            raw_radius_global_data = response[0][1].get("openconfig-system:config", {})

            if 'auth-type' in raw_radius_global_data:
                radius_server_data['auth_type'] = raw_radius_global_data['auth-type']
            if 'secret-key' in raw_radius_global_data and raw_radius_global_data['secret-key']:
                radius_server_data['key'] = raw_radius_global_data['secret-key']
            if 'timeout' in raw_radius_global_data:
                radius_server_data['timeout'] = raw_radius_global_data['timeout']

        request = [{"path": "data/openconfig-system:system/aaa/server-groups/server-group=RADIUS/openconfig-aaa-radius-ext:radius/config", "method": GET}]
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        if "openconfig-aaa-radius-ext:config" in response[0][1]:
            raw_radius_ext_global_data = response[0][1].get("openconfig-aaa-radius-ext:config", {})

            if 'nas-ip-address' in raw_radius_ext_global_data:
                radius_server_data['nas_ip'] = raw_radius_ext_global_data['nas-ip-address']
            if 'retransmit-attempts' in raw_radius_ext_global_data:
                radius_server_data['retransmit'] = raw_radius_ext_global_data['retransmit-attempts']
            if 'statistics' in raw_radius_ext_global_data:
                radius_server_data['statistics'] = raw_radius_ext_global_data['statistics']

        request = [{"path": "data/openconfig-system:system/aaa/server-groups/server-group=RADIUS/servers", "method": GET}]
        hosts = []
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        raw_radius_server_list = []
        if "openconfig-system:servers" in response[0][1]:
            raw_radius_server_list = response[0][1].get("openconfig-system:servers", {}).get('server', [])

        for radius_host in raw_radius_server_list:
            host_data = {}
            if 'address' in radius_host:
                host_data['name'] = radius_host['address']
                cfg = radius_host.get('config', None)
                if cfg:
                    if 'auth-type' in cfg:
                        host_data['auth_type'] = cfg['auth-type']
                    if 'priority' in cfg:
                        host_data['priority'] = cfg['priority']
                    if 'vrf' in cfg:
                        host_data['vrf'] = cfg['vrf']
                    if 'timeout' in cfg:
                        host_data['timeout'] = cfg['timeout']
                if radius_host.get('radius', None) and radius_host['radius'].get('config', None):
                    tacas_cfg = radius_host['radius']['config']
                    if tacas_cfg.get('auth-port', None):
                        host_data['port'] = tacas_cfg['auth-port']
                    if tacas_cfg.get('secret-key', None):
                        host_data['key'] = tacas_cfg['secret-key']
                    if tacas_cfg.get('openconfig-aaa-radius-ext:source-interface', None):
                        host_data['source_interface'] = tacas_cfg['openconfig-aaa-radius-ext:source-interface']
                    if tacas_cfg.get('retransmit-attempts', None):
                        host_data['retransmit'] = tacas_cfg['retransmit-attempts']
            if host_data:
                hosts.append(host_data)

        if hosts:
            radius_server_data['servers'] = {'host': hosts}

        return radius_server_data
