# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The eos route_maps fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

import re

from copy import deepcopy

from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.arista.eos.plugins.module_utils.network.eos.argspec.route_maps.route_maps import (
    Route_mapsArgs,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.rm_templates.route_maps import (
    Route_mapsTemplate,
)


class Route_mapsFacts(object):
    """The eos route_maps facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Route_mapsArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def get_config(self, connection):
        """Wrapper method for `connection.get()`
        This method exists solely to allow the unit test framework to mock device connection calls.
        """
        return connection.get("show running-config | section route-map ")

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Route_maps network resource

        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf

        :rtype: dictionary
        :returns: facts
        """
        facts = {}
        objs = []

        if not data:
            data = self.get_config(connection)

        resource_delim = "route-map"
        find_pattern = r"(?:^|\n)%s.*?(?=(?:^|\n)%s|$)" % (
            resource_delim,
            resource_delim,
        )
        resources = [p.strip() for p in re.findall(find_pattern, data, re.DOTALL)]
        # parse native config using the Ospf_interfaces template
        route_maps_facts = []
        # parse native config using the Route_maps template
        for resource in resources:
            route_maps_parser = Route_mapsTemplate(lines=resource.splitlines())
            objs = route_maps_parser.parse()
            if objs:
                dict_update = {}
                for k, v in iteritems(objs):
                    if k == "entries":
                        e_list = []
                        match_dict = {}
                        match_ip = {}
                        match_ipv6 = {}
                        set_dict = {}
                        for el in v:
                            for entry_k, entry_v in iteritems(el):
                                if entry_k == "match":
                                    if "ip" in entry_v or "ipv6" in entry_v:
                                        for ipk, ipv in iteritems(entry_v):
                                            if "ip" in entry_v:
                                                match_ip.update(ipv)
                                            if "ipv6" in entry_v:
                                                match_ipv6.update(ipv)
                                        matchv = {
                                            "ip": match_ip,
                                            "ipv6": match_ipv6,
                                        }
                                    else:
                                        matchv = entry_v
                                    match_dict.update(matchv)
                                elif entry_k == "set":
                                    set_dict.update(entry_v)
                                else:
                                    dict_update.update(el)
                        dict_update.update(
                            {"match": match_dict, "set": set_dict},
                        )
                        e_list.append(dict_update)
                        objs.update({"entries": e_list})
                route_maps_facts.append(objs)
        maps = []
        r_facts = []
        for r_map in route_maps_facts:
            if r_map["route_map"] in maps:
                for r_f in r_facts:
                    if r_f["route_map"] == r_map["route_map"]:
                        r_f["entries"].extend(r_map["entries"])
            else:
                maps.append(r_map["route_map"])
                r_facts.append(r_map)
        ansible_facts["ansible_network_resources"].pop("route_maps", None)
        facts = {"route_maps": []}
        params = utils.remove_empties(
            utils.validate_config(self.argument_spec, {"config": r_facts}),
        )
        if params.get("config"):
            for cfg in params["config"]:
                facts["route_maps"].append(utils.remove_empties(cfg))
                ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
