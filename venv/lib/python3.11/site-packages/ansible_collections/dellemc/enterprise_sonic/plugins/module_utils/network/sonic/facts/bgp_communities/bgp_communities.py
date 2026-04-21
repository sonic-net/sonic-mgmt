#
# -*- coding: utf-8 -*-
# Copyright 2020 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic bgp_communities fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.bgp_communities.bgp_communities import Bgp_communitiesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    remove_empties_from_list
)
from ansible.module_utils.connection import ConnectionError


class Bgp_communitiesFacts(object):
    """ The sonic bgp_communities fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Bgp_communitiesArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def get_bgp_communities(self):
        url = "data/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/community-sets"
        method = "GET"
        request = [{"path": url, "method": method}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        bgp_communities = []
        if "openconfig-bgp-policy:community-sets" in response[0][1]:
            temp = response[0][1].get("openconfig-bgp-policy:community-sets", {})
            if "community-set" in temp:
                bgp_communities = temp["community-set"]

        bgp_communities_configs = []
        for bgp_community in bgp_communities:
            result = dict()
            name = bgp_community["community-set-name"]
            member_config = bgp_community['config']
            match = member_config['match-set-options']
            permit_str = member_config.get('openconfig-bgp-policy-ext:action', None)
            members = member_config.get("community-member", [])
            result['name'] = str(name)
            result['match'] = match
            result['members'] = None
            result['permit'] = False
            if permit_str and permit_str == 'PERMIT':
                result['permit'] = True
            if members:
                result['type'] = 'expanded' if 'REGEX' in members[0] else 'standard'
                if result['type'] == 'expanded':
                    members = [':'.join(i.split(':')[1:]) for i in members]
                    members.sort()
                    result['members'] = {'regex': members}
            else:
                result['type'] = 'standard'

            if result['type'] == 'standard':
                aann = []
                for i in members:
                    if "NO_EXPORT_SUBCONFED" in i:
                        result['local_as'] = True
                    elif "NO_ADVERTISE" in i:
                        result['no_advertise'] = True
                    elif "NO_EXPORT" in i:
                        result['no_export'] = True
                    elif "NOPEER" in i:
                        result['no_peer'] = True
                    else:
                        aann.append(i)

                if aann:
                    aann.sort()
                    result['members'] = {'aann': aann}

            bgp_communities_configs.append(result)
        return bgp_communities_configs

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for bgp_communities
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass

        if not data:
            resources = self.get_bgp_communities()

        objs = []
        for resource in resources:
            if resource:
                obj = self.render_config(self.generated_spec, resource)
                if obj:
                    objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('bgp_communities', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['bgp_communities'] = remove_empties_from_list(params['config'])

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
