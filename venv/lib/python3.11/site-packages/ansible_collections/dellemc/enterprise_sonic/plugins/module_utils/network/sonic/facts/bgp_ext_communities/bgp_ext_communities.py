#
# -*- coding: utf-8 -*-
# Copyright 2020 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic bgp_ext_communities fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.bgp_ext_communities.bgp_ext_communities import (
    Bgp_ext_communitiesArgs,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError


class Bgp_ext_communitiesFacts(object):
    """ The sonic bgp_ext_communities fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Bgp_ext_communitiesArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def get_bgp_extcommunities(self):
        url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/ext-community-sets"
        method = "GET"
        request = [{"path": url, "method": method}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        bgp_extcommunities = []
        if "openconfig-bgp-policy:ext-community-sets" in response[0][1]:
            temp = response[0][1].get("openconfig-bgp-policy:ext-community-sets", {})
            if "ext-community-set" in temp:
                bgp_extcommunities = temp["ext-community-set"]

        bgp_extcommunities_configs = []
        for bgp_extcommunity in bgp_extcommunities:
            result = dict()
            name = bgp_extcommunity["ext-community-set-name"]
            member_config = bgp_extcommunity['config']
            match = member_config['match-set-options']
            permit_str = member_config.get('openconfig-bgp-policy-ext:action', None)
            members = member_config.get("ext-community-member", [])
            result['name'] = str(name)
            result['match'] = match.lower()
            result['members'] = dict()
            result['type'] = 'standard'
            result['permit'] = False
            if permit_str and permit_str == 'PERMIT':
                result['permit'] = True
            if members:
                result['type'] = 'expanded' if 'REGEX' in members[0] else 'standard'
            if result['type'] == 'expanded':
                members = [':'.join(i.split(':')[1:]) for i in members]
                members_list = list(map(str, members))
                members_list.sort()
                result['members'] = {'regex': members_list}
            else:
                rt = list()
                soo = list()
                for member in members:
                    if member.startswith('route-origin'):
                        soo.append(':'.join(member.split(':')[1:]))
                    else:
                        rt.append(':'.join(member.split(':')[1:]))
                route_target_list = list(map(str, rt))
                route_origin_list = list(map(str, soo))
                route_target_list.sort()
                route_origin_list.sort()

                if route_target_list and len(route_target_list) > 0:
                    result['members']['route_target'] = route_target_list

                if route_origin_list and len(route_origin_list) > 0:
                    result['members']['route_origin'] = route_origin_list

            bgp_extcommunities_configs.append(result)

        return bgp_extcommunities_configs

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for bgp_ext_communities
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass

        if not data:
            resources = self.get_bgp_extcommunities()

        objs = []
        for resource in resources:
            if resource:
                obj = self.render_config(self.generated_spec, resource)
                if obj:
                    objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('bgp_ext_communities', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['bgp_ext_communities'] = params['config']

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
