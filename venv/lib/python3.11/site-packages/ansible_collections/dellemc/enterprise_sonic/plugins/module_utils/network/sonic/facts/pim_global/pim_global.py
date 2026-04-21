#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic pim_global fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.pim_global.pim_global import Pim_globalArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.bgp_utils import (
    get_all_vrfs
)
from ansible.module_utils.connection import ConnectionError


class Pim_globalFacts(object):
    """ The sonic pim_global fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Pim_globalArgs.argument_spec
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
        """ Populate the facts for pim_global
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass

        if not data:
            pim_global_configs = self.get_pim_global()

        objs = []
        for vrf_name, pim_global_config in pim_global_configs.items():
            obj = self.render_config(self.generated_spec, vrf_name, pim_global_config)
            if obj:
                objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('pim_global', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['pim_global'] = utils.remove_empties({'config': params['config']})['config']

        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def render_config(self, spec, vrf_name, conf):
        """
        Render config as dictionary structure and delete keys
          from spec for null values

        :param spec: The facts tree, generated from the argspec
        :param conf: The configuration
        :rtype: dictionary
        :returns: The generated config
        """
        config = deepcopy(spec)
        config['vrf_name'] = vrf_name

        if conf.get('config'):
            config['ecmp_enable'] = conf['config'].get('ecmp-enabled', False)
            config['ecmp_rebalance_enable'] = conf['config'].get('ecmp-rebalance-enabled', False)
            config['keepalive_timer'] = conf['config'].get('keep-alive-timer')
            config['join_prune_interval'] = conf['config'].get('join-prune-interval')

        if conf.get('ssm') and conf['ssm'].get('config'):
            config['ssm_prefix_list'] = conf['ssm']['config'].get('ssm-ranges')

        return config

    def get_pim_global(self):
        """Get all global PIM configurations available in chassis"""
        pim_global_path = (
            'data/openconfig-network-instance:network-instances/network-instance={vrf}'
            '/protocols/protocol=PIM,pim/pim/global'
        )
        method = 'GET'

        pim_global = {}
        vrf_list = get_all_vrfs(self._module)
        for vrf_name in vrf_list:
            request = {"path": pim_global_path.format(vrf=vrf_name), "method": method}
            try:
                response = edit_config(self._module, to_request(self._module, request))
            except ConnectionError as exc:
                self._module.fail_json(msg=str(exc), code=exc.code)

            response = response[0][1].get('openconfig-network-instance:global')
            if response:
                pim_global[vrf_name] = response

        return pim_global
