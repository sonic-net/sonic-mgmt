#
# -*- coding: utf-8 -*-
# © Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic port breakout fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.port_breakout.port_breakout import Port_breakoutArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_breakout_mode,
)
from ansible.module_utils.connection import ConnectionError

GET = "get"


class Port_breakoutFacts(object):
    """ The sonic port breakout fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Port_breakoutArgs.argument_spec
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
        """ Populate the facts for port_breakout
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass

        if not data:
            # typically data is populated from the current device configuration
            # data = connection.get('show running-config | section ^interface')
            # using mock data instead
            data = self.get_all_port_breakout()

        objs = list()
        for conf in data:
            if conf:
                obj = self.render_config(self.generated_spec, conf)
                if obj:
                    objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('port_breakout', None)
        facts = {}
        if objs:
            facts['port_breakout'] = []
            params = utils.validate_config(self.argument_spec, {'config': objs})
            if params:
                facts['port_breakout'].extend(params['config'])
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

    def get_all_port_breakout(self):
        """Get all the port_breakout configured on the device"""
        request = [{"path": "data/sonic-port-breakout:sonic-port-breakout/BREAKOUT_CFG/BREAKOUT_CFG_LIST", "method": GET}]
        port_breakout_list = []
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        raw_port_breakout_list = []
        if "sonic-port-breakout:BREAKOUT_CFG_LIST" in response[0][1]:
            raw_port_breakout_list = response[0][1].get("sonic-port-breakout:BREAKOUT_CFG_LIST", [])

        for port_breakout in raw_port_breakout_list:
            name = port_breakout.get('port', None)
            mode = port_breakout.get('brkout_mode', None)
            if name and mode:
                if '[' in mode:
                    mode = mode[:mode.index('[')]
                norm_port_breakout = {'name': name, 'mode': mode}
                mode = get_breakout_mode(self._module, name)
                if mode:
                    norm_port_breakout['mode'] = mode
                port_breakout_list.append(norm_port_breakout)

        return port_breakout_list
