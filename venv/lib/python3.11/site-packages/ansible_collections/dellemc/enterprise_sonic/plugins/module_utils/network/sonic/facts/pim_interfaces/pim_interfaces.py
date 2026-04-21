#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic pim_interfaces fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.pim_interfaces.pim_interfaces import Pim_interfacesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.bgp_utils import (
    get_all_vrfs
)
from ansible.module_utils.connection import ConnectionError


class Pim_interfacesFacts(object):
    """ The sonic pim_interfaces fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Pim_interfacesArgs.argument_spec
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
        """ Populate the facts for pim_interfaces
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass

        if not data:
            pim_interfaces_configs = self.get_pim_interfaces()

        objs = []
        for pim_interface_config in pim_interfaces_configs:
            if pim_interface_config.get('interface-id'):
                obj = self.render_config(self.generated_spec, pim_interface_config)
                if obj:
                    objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('pim_interfaces', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['pim_interfaces'] = utils.remove_empties({'config': params['config']})['config']

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
        config = deepcopy(spec)
        config['name'] = conf['interface-id']

        if conf.get('config'):
            config['drpriority'] = conf['config'].get('dr-priority')
            config['hello_interval'] = conf['config'].get('hello-interval')
            config['sparse_mode'] = (conf['config'].get('mode') == 'openconfig-pim-types:PIM_MODE_SPARSE')

        if conf.get('enable-bfd') and conf['enable-bfd'].get('config'):
            config['bfd_enable'] = conf['enable-bfd']['config'].get('enabled', False)
            config['bfd_profile'] = conf['enable-bfd']['config'].get('bfd-profile')

        return config

    def get_pim_interfaces(self):
        """Get all interface PIM configurations available in chassis"""
        pim_interfaces_path = (
            'data/openconfig-network-instance:network-instances/network-instance={vrf}'
            '/protocols/protocol=PIM,pim/pim/interfaces'
        )
        method = 'GET'

        pim_interfaces = []
        vrf_list = get_all_vrfs(self._module)
        for vrf_name in vrf_list:
            request = {"path": pim_interfaces_path.format(vrf=vrf_name), "method": method}
            try:
                response = edit_config(self._module, to_request(self._module, request))
            except ConnectionError as exc:
                self._module.fail_json(msg=str(exc), code=exc.code)

            response = response[0][1].get('openconfig-network-instance:interfaces')
            if response and response.get('interface'):
                pim_interfaces.extend(response['interface'])

        return pim_interfaces
