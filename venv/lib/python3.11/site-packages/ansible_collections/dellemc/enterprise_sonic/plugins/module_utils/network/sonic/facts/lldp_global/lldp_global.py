#
# -*- coding: utf-8 -*-
# Copyright 2022 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic lldp_global fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.lldp_global.lldp_global import Lldp_globalArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError


GET = "get"


class Lldp_globalFacts(object):
    """ The sonic lldp_global fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Lldp_globalArgs.argument_spec
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
        """ Populate the facts for lldp_global
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass

        obj = self.get_all_lldp_configs()

        ansible_facts['ansible_network_resources'].pop('lldp_global', None)
        facts = {}
        if obj:
            params = utils.validate_config(self.argument_spec, {'config': obj})
            facts['lldp_global'] = utils.remove_empties(params['config'])

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

    def get_all_lldp_configs(self):
        """Get all the lldp_global configured in the device"""
        request = [{"path": "data/openconfig-lldp:lldp/config", "method": GET}]
        lldp_global_data = {}
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)
        lldp_global_data['tlv_select'] = {}
        lldp_global_data['tlv_select']['management_address'] = True
        lldp_global_data['tlv_select']['system_capabilities'] = True
        lldp_global_data['enable'] = True
        if 'openconfig-lldp:config' in response[0][1]:
            raw_lldp_global_data = response[0][1]['openconfig-lldp:config']
            if 'enabled' in raw_lldp_global_data:
                lldp_global_data['enable'] = raw_lldp_global_data['enabled']
            if 'hello-timer' in raw_lldp_global_data:
                lldp_global_data['hello_time'] = raw_lldp_global_data['hello-timer']
            if 'openconfig-lldp-ext:mode' in raw_lldp_global_data:
                lldp_global_data['mode'] = raw_lldp_global_data['openconfig-lldp-ext:mode'].lower()
            if 'system-description' in raw_lldp_global_data:
                lldp_global_data['system_description'] = raw_lldp_global_data['system-description']
            if 'system-name' in raw_lldp_global_data:
                lldp_global_data['system_name'] = raw_lldp_global_data['system-name']
            if 'openconfig-lldp-ext:multiplier' in raw_lldp_global_data:
                lldp_global_data['multiplier'] = raw_lldp_global_data['openconfig-lldp-ext:multiplier']
            if 'suppress-tlv-advertisement' in raw_lldp_global_data:
                for tlv_select in raw_lldp_global_data['suppress-tlv-advertisement']:
                    tlv_select = tlv_select.replace('openconfig-lldp-types:', '').lower()
                    if tlv_select in ('management_address', 'system_capabilities'):
                        lldp_global_data['tlv_select'][tlv_select] = False
        return lldp_global_data
