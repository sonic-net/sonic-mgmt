#
# -*- coding: utf-8 -*-
# © Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic port group fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy
import warnings
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.port_group.port_group import Port_groupArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

GET = "get"


class Port_groupFacts(object):
    """ The sonic port group fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Port_groupArgs.argument_spec
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
        """ Populate the facts for port groups
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if not data:
            # typically data is populated from the current device configuration
            # data = connection.get('show running-config | section port-group')
            # using mock data instead
            data = self.get_port_groups()

        objs = []
        for conf in data:
            if conf:
                obj = self.render_config(self.generated_spec, conf)
                if obj:
                    objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('port_group', None)
        facts = {}
        if objs:
            facts['port_group'] = []
            params = utils.validate_config(self.argument_spec, {'config': objs})
            if params:
                facts['port_group'].extend(params['config'])
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

    def get_port_groups(self):
        """Get all the port group configurations"""

        pgs_request = [{"path": "data/openconfig-port-group:port-groups/port-group", "method": GET}]
        try:
            pgs_response = edit_config(self._module, to_request(self._module, pgs_request))
        except ConnectionError as exc:
            if 'Resource not found' in str(exc):
                warnings.warn('The port group ("port_group") feature is not supported on this platform.')
                return []

            self._module.fail_json(msg=str(exc), code=exc.code)

        pgs_config = []
        if "openconfig-port-group:port-group" in pgs_response[0][1]:
            pgs_config = pgs_response[0][1].get("openconfig-port-group:port-group", [])

        pgs = []
        for pg_config in pgs_config:
            pg = {}
            if 'config' in pg_config:
                pg['id'] = pg_config['id']
                speed_str = pg_config['config'].get('speed', None)
                if speed_str:
                    pg['speed'] = speed_str.split(":", 1)[-1]
                    pgs.append(pg)

        return pgs
