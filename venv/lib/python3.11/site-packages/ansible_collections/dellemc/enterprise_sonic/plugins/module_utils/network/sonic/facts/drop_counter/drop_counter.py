#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic drop_counter fact class
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
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.drop_counter.drop_counter import Drop_counterArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)


enum_dict = {
    'enable': True,
    'disable': False
}


class Drop_counterFacts(object):
    """ The sonic drop_counter fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Drop_counterArgs.argument_spec
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
        """ Populate the facts for drop_counter
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []

        if not data:
            cfg = self.get_config(self._module)
            data = self.get_parsed_drop_counter(cfg)
        objs = data
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['drop_counter'] = remove_empties_from_list(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_config(self, module):
        cfg = None
        get_path = 'data/sonic-debugcounter:sonic-debugcounter'
        request = {'path': get_path, 'method': 'get'}

        try:
            response = edit_config(module, to_request(module, request))
            if 'sonic-debugcounter:sonic-debugcounter' in response[0][1]:
                cfg = response[0][1].get('sonic-debugcounter:sonic-debugcounter')
        except ConnectionError as exc:
            module.fail_json(msg=str(exc), code=exc.code)

        return cfg

    def get_parsed_drop_counter(self, cfg):
        """This method parses the sonic-debugcounter data and returns the parsed data in argspec format"""
        config_list = []

        if cfg and cfg.get('DEBUG_COUNTER') and cfg['DEBUG_COUNTER'].get('DEBUG_COUNTER_LIST'):
            for counter in cfg['DEBUG_COUNTER']['DEBUG_COUNTER_LIST']:
                counter_dict = {}
                if counter.get('name'):
                    counter_dict['name'] = counter['name']
                if counter.get('alias'):
                    counter_dict['alias'] = counter['alias']
                if counter.get('desc'):
                    counter_dict['counter_description'] = counter['desc']
                if counter.get('group'):
                    counter_dict['group'] = counter['group']
                if counter.get('mirror'):
                    counter_dict['mirror'] = counter['mirror']
                if counter.get('reasons'):
                    counter_dict['reasons'] = counter['reasons']
                if counter.get('type'):
                    counter_dict['counter_type'] = counter['type']
                status = counter.get('status', 'disable')
                counter_dict['enable'] = enum_dict[status]
                if counter_dict:
                    config_list.append(counter_dict)

        return config_list
