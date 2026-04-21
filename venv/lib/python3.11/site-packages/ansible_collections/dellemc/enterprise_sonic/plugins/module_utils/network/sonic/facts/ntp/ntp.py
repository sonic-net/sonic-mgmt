#
# -*- coding: utf-8 -*-
# Copyright 2022 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic ntp fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ntp.ntp import NtpArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

GET = "get"


class NtpFacts(object):
    """ The sonic ntp fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = NtpArgs.argument_spec
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
        """ Populate the facts for ntp
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if not data:
            # typically data is populated from the current device configuration
            # data = connection.get('show running-config | section ^interface')
            # using mock data instead
            data = self.get_ntp_configuration()

        obj = self.render_config(self.generated_spec, data)

        ansible_facts['ansible_network_resources'].pop('ntp', None)
        facts = {}
        if obj:
            params = utils.validate_config(self.argument_spec, {'config': obj})
            facts['ntp'] = params['config']

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

    def get_ntp_configuration(self):
        """Get all NTP configuration"""

        all_ntp_request = [{"path": "data/openconfig-system:system/ntp", "method": GET}]
        all_ntp_response = []
        try:
            all_ntp_response = edit_config(self._module, to_request(self._module, all_ntp_request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        all_ntp_config = dict()
        if 'openconfig-system:ntp' in all_ntp_response[0][1]:
            all_ntp_config = all_ntp_response[0][1].get('openconfig-system:ntp', {})

        ntp_global_config = dict()
        if 'config' in all_ntp_config:
            ntp_global_config = all_ntp_config.get('config', {})

        ntp_servers = []
        if 'servers' in all_ntp_config:
            ntp_servers = all_ntp_config['servers'].get('server', [])

        ntp_keys = []
        if 'ntp-keys' in all_ntp_config:
            ntp_keys = all_ntp_config['ntp-keys'].get('ntp-key', [])

        ntp_config = dict()

        if 'network-instance' in ntp_global_config and ntp_global_config['network-instance']:
            ntp_config['vrf'] = ntp_global_config['network-instance']

        if 'enable-ntp-auth' in ntp_global_config:
            ntp_config['enable_ntp_auth'] = ntp_global_config['enable-ntp-auth']

        if 'source-interface' in ntp_global_config and ntp_global_config['source-interface']:
            ntp_config['source_interfaces'] = ntp_global_config['source-interface']

        if 'trusted-key' in ntp_global_config and ntp_global_config['trusted-key']:
            ntp_config['trusted_keys'] = ntp_global_config['trusted-key']

        servers = []
        for ntp_server in ntp_servers:
            if 'config' in ntp_server:
                server = {}
                server['address'] = ntp_server['config'].get('address', None)
                if 'key-id' in ntp_server['config']:
                    server['key_id'] = ntp_server['config']['key-id']
                server['minpoll'] = ntp_server['config'].get('minpoll', None)
                server['maxpoll'] = ntp_server['config'].get('maxpoll', None)
                server['prefer'] = ntp_server['config'].get('prefer', None)
                servers.append(server)
        if servers:
            ntp_config['servers'] = servers

        keys = []
        for ntp_key in ntp_keys:
            if 'config' in ntp_key:
                key = {}
                key['encrypted'] = ntp_key['config'].get('encrypted', None)
                key['key_id'] = ntp_key['config'].get('key-id', None)
                key_type_str = ntp_key['config'].get('key-type', None)
                key_type = key_type_str.split(":", 1)[-1]
                key['key_type'] = key_type
                key['key_value'] = ntp_key['config'].get('key-value', None)
                keys.append(key)
        if keys:
            ntp_config['ntp_keys'] = keys

        return ntp_config
