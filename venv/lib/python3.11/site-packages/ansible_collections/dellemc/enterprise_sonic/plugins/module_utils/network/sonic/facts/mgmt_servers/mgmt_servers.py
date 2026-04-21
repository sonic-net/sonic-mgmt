#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic mgmt_servers fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy

from ansible.module_utils.connection import ConnectionError
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    remove_empties
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.mgmt_servers.mgmt_servers import Mgmt_serversArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)

SYS_PATH = '/data/openconfig-system:system'


class Mgmt_serversFacts(object):
    """ The sonic mgmt_servers fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Mgmt_serversArgs.argument_spec
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
        """ Populate the facts for mgmt_servers
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []

        if not data:
            data = self.update_mgmt_servers(self._module)
        objs = data
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['mgmt_servers'] = remove_empties(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def update_mgmt_servers(self, module):
        """Transform OC configuration to Ansible argspec"""
        config_dict = {}

        rest_cfg = self.get_config(module, 'rest-server/config')
        telemetry_cfg = self.get_config(module, 'telemetry-server/config')

        if rest_cfg:
            # Change from OC naming to Ansible naming
            if rest_cfg.get('openconfig-system-mgmt-servers:disable') is not None:
                rest_cfg['shutdown'] = rest_cfg.get('openconfig-system-mgmt-servers:disable')
                rest_cfg.pop('openconfig-system-mgmt-servers:disable')
            if rest_cfg.get('cipher-suite') is not None:
                rest_cfg['cipher_suite'] = rest_cfg.get('cipher-suite')
                rest_cfg.pop('cipher-suite')
            config_dict['rest'] = rest_cfg
        if telemetry_cfg:
            config_dict['telemetry'] = telemetry_cfg

        return config_dict

    def get_config(self, module, path):
        """Retrieve OC configuration from device"""
        cfg = None
        get_path = '%s/%s' % (SYS_PATH, path)
        request = {'path': get_path, 'method': 'get'}

        try:
            response = edit_config(module, to_request(module, request))
            if 'openconfig-system:config' in response[0][1]:
                cfg = response[0][1].get('openconfig-system:config')
        except ConnectionError as exc:
            module.fail_json(msg=str(exc), code=exc.code)

        return cfg
