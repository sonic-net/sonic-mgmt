# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The vyos route_maps fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.argspec.route_maps.route_maps import (
    Route_mapsArgs,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.route_maps import (
    Route_mapsTemplate,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.route_maps_14 import (
    Route_mapsTemplate14,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.utils.version import (
    LooseVersion,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.vyos import get_os_version


class Route_mapsFacts(object):
    """The vyos route_maps facts class"""

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
        return connection.get("show configuration commands | grep route-map")

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

        if LooseVersion(get_os_version(self._module)) >= LooseVersion("1.4"):
            route_maps_class = Route_mapsTemplate14
        else:
            route_maps_class = Route_mapsTemplate

        if not data:
            data = self.get_config(connection)

        # parse native config using the Route_maps template
        route_maps_parser = route_maps_class(lines=data.splitlines())

        if route_maps_parser.parse().get("route_maps"):
            objs = list(route_maps_parser.parse().get("route_maps").values())
        for item in objs:
            if item.get("entries"):
                item["entries"] = list(item["entries"].values())

        ansible_facts["ansible_network_resources"].pop("route_maps", None)

        # import epdb;epdb.serve()
        params = utils.remove_empties(utils.validate_config(self.argument_spec, {"config": objs}))

        if params.get("config"):
            facts["route_maps"] = params["config"]
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
