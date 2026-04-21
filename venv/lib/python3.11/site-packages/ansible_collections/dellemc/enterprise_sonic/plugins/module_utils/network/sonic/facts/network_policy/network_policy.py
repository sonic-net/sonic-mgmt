#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic network_policy fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.network_policy.network_policy import Network_policyArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)


class Network_policyFacts(object):
    """ The sonic network_policy fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Network_policyArgs.argument_spec
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
        """ Populate the facts for network_policy
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []

        if not data:
            cfg = self.get_config(self._module)
            data = self.get_parsed_network_policy(cfg)
        objs = data
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['network_policy'] = remove_empties_from_list(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_config(self, module):
        cfg = None
        get_path = 'data/openconfig-network-policy-ext:network-policies'
        request = {'path': get_path, 'method': 'get'}

        try:
            response = edit_config(module, to_request(module, request))
            if 'openconfig-network-policy-ext:network-policies' in response[0][1]:
                cfg = response[0][1].get('openconfig-network-policy-ext:network-policies')
        except ConnectionError as exc:
            module.fail_json(msg=str(exc), code=exc.code)

        return cfg

    def get_parsed_network_policy(self, cfg):
        """This method parses the OC network policy data and returns the parsed data in argspec format"""
        config_list = []
        bool_dict = {True: False, False: True}

        if cfg and cfg.get('network-policy'):
            for policy in cfg['network-policy']:
                policy_dict = {}
                if policy.get('number'):
                    policy_dict['number'] = policy['number']
                if policy.get('applications') and policy['applications'].get('application'):
                    app_list = []
                    for app in policy['applications']['application']:
                        app_dict = {}
                        if app.get('type'):
                            app_dict['app_type'] = app['type'].lower().replace('_', '-')
                        if app.get('config'):
                            if app['config'].get('vlan-id') is not None:
                                if app['config']['vlan-id'] == 0:
                                    app_dict['dot1p'] = 'enabled'
                                else:
                                    app_dict['vlan_id'] = app['config']['vlan-id']
                            if app['config'].get('tagged') is not None:
                                app_dict['untagged'] = bool_dict[app['config']['tagged']]
                            if app['config'].get('priority') is not None:
                                app_dict['priority'] = app['config']['priority']
                            if app['config'].get('dscp') is not None:
                                app_dict['dscp'] = app['config']['dscp']
                        if app_dict:
                            app_list.append(app_dict)
                    if app_list:
                        policy_dict['applications'] = app_list
                if policy_dict:
                    config_list.append(policy_dict)

        return config_list
