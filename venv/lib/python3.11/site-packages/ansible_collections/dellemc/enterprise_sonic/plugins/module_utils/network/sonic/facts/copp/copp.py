#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic copp fact class
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
from ansible.module_utils.connection import ConnectionError
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    remove_empties
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.copp.copp import CoppArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)


class CoppFacts(object):
    """ The sonic copp fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = CoppArgs.argument_spec
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
        """ Populate the facts for bfd
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """

        if not data:
            copp_cfg = self.get_config(self._module)
            copp_data = self.update_copp(copp_cfg)

        facts = {}
        if copp_data:
            params = utils.validate_config(self.argument_spec, {'config': copp_data})
            facts['copp'] = remove_empties(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def update_copp(self, data):
        """This method parses the OC copp data and returns the parsed data in argspec format"""
        config_dict = {}
        if data:
            copp_groups = data.get('copp-groups')
            if copp_groups:
                copp_group_list = copp_groups.get('copp-group')
                if copp_group_list:
                    copp_groups_list = []
                    for group in copp_group_list:
                        group_dict = {}
                        copp_name = group['name']
                        config = group['config']
                        trap_priority = config.get('trap-priority')
                        trap_action = config.get('trap-action')
                        queue = config.get('queue')
                        cir = config.get('cir')
                        cbs = config.get('cbs')

                        group_dict['copp_name'] = copp_name
                        if trap_priority:
                            group_dict['trap_priority'] = trap_priority
                        if trap_action:
                            group_dict['trap_action'] = trap_action.lower()
                        if queue:
                            group_dict['queue'] = queue
                        if cir:
                            group_dict['cir'] = cir
                        if cbs:
                            group_dict['cbs'] = cbs
                        if group_dict:
                            copp_groups_list.append(group_dict)
                    if copp_groups_list:
                        config_dict['copp_groups'] = copp_groups_list

            copp_traps = data.get('copp-traps')
            if copp_traps:
                copp_trap_list = copp_traps.get('copp-trap')
                if copp_trap_list:
                    copp_traps_list = []
                    for trap in copp_trap_list:
                        trap_dict = {}
                        name = trap['name']
                        config = trap['config']
                        trap_protocol_ids = config.get('trap-ids')
                        trap_group = config.get('trap-group')

                        trap_dict['name'] = name
                        if trap_protocol_ids:
                            trap_dict['trap_protocol_ids'] = trap_protocol_ids
                        if trap_group:
                            trap_dict['trap_group'] = trap_group
                        if trap_dict:
                            copp_traps_list.append(trap_dict)
                    if copp_traps_list:
                        config_dict['copp_traps'] = copp_traps_list

        return config_dict

    def get_config(self, module):
        """This method returns the copp configuration from the device"""
        copp_cfg = None
        get_copp_path = 'data/openconfig-copp-ext:copp'
        request = {'path': get_copp_path, 'method': 'get'}

        try:
            response = edit_config(module, to_request(module, request))
            if 'openconfig-copp-ext:copp' in response[0][1]:
                copp_cfg = response[0][1].get('openconfig-copp-ext:copp')
        except ConnectionError as exc:
            module.fail_json(msg=str(exc), code=exc.code)
        return copp_cfg
