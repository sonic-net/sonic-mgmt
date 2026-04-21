#
# -*- coding: utf-8 -*-
# Copyright 2020 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic bgp_as_paths fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.bgp_as_paths.bgp_as_paths import Bgp_as_pathsArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError


class Bgp_as_pathsFacts(object):
    """ The sonic bgp_as_paths fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Bgp_as_pathsArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def get_as_path_list(self):
        url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/as-path-sets"
        method = "GET"
        request = [{"path": url, "method": method}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        as_path_lists = []
        if "openconfig-bgp-policy:as-path-sets" in response[0][1]:
            temp = response[0][1].get("openconfig-bgp-policy:as-path-sets", {})
            if "as-path-set" in temp:
                as_path_lists = temp["as-path-set"]

        as_path_list_configs = []
        for as_path in as_path_lists:
            result = dict()
            as_name = as_path["as-path-set-name"]
            member_config = as_path['config']
            members = member_config.get("as-path-set-member", [])
            permit_str = member_config.get("openconfig-bgp-policy-ext:action", None)
            result['name'] = as_name
            result['members'] = members
            if permit_str and permit_str == "PERMIT":
                result['permit'] = True
            else:
                result['permit'] = False
            as_path_list_configs.append(result)
        return as_path_list_configs

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for as_path_list
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass

        if not data:
            resources = self.get_as_path_list()

        objs = []
        for resource in resources:
            if resource:
                obj = self.render_config(self.generated_spec, resource)
                if obj:
                    objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('bgp_as_paths', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['bgp_as_paths'] = params['config']

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
        try:
            config['name'] = str(conf['name'])
            config['members'] = conf['members']
            config['permit'] = conf['permit']
        except TypeError:
            config['name'] = None
            config['members'] = None
            config['permit'] = None
        return utils.remove_empties(config)
