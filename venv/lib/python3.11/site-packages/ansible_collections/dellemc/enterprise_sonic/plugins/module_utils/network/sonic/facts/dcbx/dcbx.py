#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic dcbx fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re
from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    remove_empties
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.dcbx.dcbx import DcbxArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

GET = 'GET'


class DcbxFacts(object):
    """ The sonic dcbx fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = DcbxArgs.argument_spec
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
        """ Populate the facts for dcbx
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass

        obj = self.get_all_dcbx()
        ansible_facts['ansible_network_resources'].pop('dcbx', None)
        facts = {}
        if obj:
            params = utils.validate_config(self.argument_spec, {'config': obj})
            facts['dcbx'] = remove_empties(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_all_dcbx(self):
        """Get all DCBx configurations available in chassis"""
        dcbx_path = 'data/openconfig-dcbx:dcbx'
        request = [{'path': dcbx_path, 'method': GET}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        dcbx_op = []
        dcbx_configs = {}
        dcbx_interface_configs = []
        if response and response[0]:
            if (response[0][1].get('openconfig-dcbx:dcbx')):
                dcbx_op = response[0][1].get('openconfig-dcbx:dcbx')
                if (dcbx_op.get('interfaces')):
                    dcbx_op_intf = dcbx_op.get('interfaces')
                    dcbx_intfs = dcbx_op_intf.get('interface')
                    for interface in dcbx_intfs:
                        dcbx_interface_data = {}
                        config = interface.get('config', {})

                        dcbx_interface_data['name'] = interface.get('name', [])
                        if re.search('Eth', interface['name']):
                            if 'name' in config:
                                dcbx_interface_data['name'] = config.get('name')
                            if 'enabled' in config:
                                dcbx_interface_data['enabled'] = config.get('enabled')
                            if 'pfc-tlv-enabled' in config:
                                dcbx_interface_data['pfc_tlv_enabled'] = config.get('pfc-tlv-enabled')
                            if 'ets-configuration-tlv-enabled' in config:
                                dcbx_interface_data['ets_configuration_tlv_enabled'] = config.get('ets-configuration-tlv-enabled')
                            if 'ets-recommendation-tlv-enabled' in config:
                                dcbx_interface_data['ets_recommendation_tlv_enabled'] = config.get('ets-recommendation-tlv-enabled')
                            dcbx_interface_configs.append(dcbx_interface_data)
                    dcbx_configs['interfaces'] = dcbx_interface_configs
                if (dcbx_op.get('config')):
                    dcbx_op_config = dcbx_op.get('config')
                    dcbx_global = {}
                    dcbx_global['enabled'] = dcbx_op_config.get('enabled')
                    dcbx_configs['global'] = dcbx_global

            return dcbx_configs
