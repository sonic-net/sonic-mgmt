#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic pms fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.pms.pms import PmsArgs

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    remove_empties_from_list,
    remove_empties
)
from ansible.module_utils.connection import ConnectionError


class PmsFacts(object):
    """ The sonic_pms fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = PmsArgs.argument_spec
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
        """ Populate the facts for pms
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []

        all_pms_interface_configs = {}
        if not data:
            all_pms_interface_configs = self.get_pms()

        for pms_interface_config in all_pms_interface_configs:
            if pms_interface_config:
                objs.append(pms_interface_config)

        ansible_facts['ansible_network_resources'].pop('pms', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['pms'] = remove_empties_from_list(params['config'])

        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_pms(self):
        """Get all pms interfaces available in chassis"""
        request = [{"path": "data/openconfig-pms-ext:port-security", "method": "GET"}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)
        pms_configs = []

        if response and "openconfig-pms-ext:port-security" in response[0][1]:
            interfaces = response[0][1].get("openconfig-pms-ext:port-security", {})
            if interfaces.get('interfaces'):
                interfaces = interfaces['interfaces']
            for interface in interfaces.get('interface', []):
                pms_config = interface.get('config', {})
                if pms_config:
                    config_object = {
                        'name': pms_config.get('name'),
                        'port_security_enable': pms_config.get('admin-enable'),
                        'max_allowed_macs': pms_config.get('maximum'),
                        'violation': pms_config.get('violation'),
                        'sticky_mac': pms_config.get('sticky-mac')
                    }
                    config_object = remove_empties(config_object)
                    if 'violation' in config_object and 'openconfig-pms-types:' in config_object['violation']:
                        config_object['violation'] = config_object['violation'].split(":")[1]
                    if len(config_object) > 1:
                        pms_configs.append(config_object)

        return pms_configs
