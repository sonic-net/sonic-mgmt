#
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The nxos static_routes fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.static_routes.static_routes import (
    Static_routesArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.static_routes import (
    Static_routesTemplate,
)


class Static_routesFacts(object):
    """The nxos static_routes fact class"""

    def __init__(self, module):
        self._module = module
        self.argument_spec = Static_routesArgs.argument_spec

    def get_static_routes_data(self, connection):
        non_vrf_data = connection.get("show running-config | include '^ip(v6)* route'") or ""
        if non_vrf_data:
            non_vrf_data = "\n".join(
                line for line in non_vrf_data.splitlines() if line and not line.startswith("  ")
            )
        vrf_data = connection.get("show running-config | section '^vrf context'")
        if vrf_data:
            non_vrf_data += "\n" + vrf_data
        return non_vrf_data

    def process_static_routes(self, objs):
        strout = {}
        for k, obj in objs.items():
            _routes = {"next_hops": []}
            _nx_hop = []
            is_vrf = False

            for routes in obj:
                grp_vrf = routes.pop("_vrf", None)
                if grp_vrf:
                    is_vrf = True
                _afi = routes.pop("_afi")

                _routes["dest"] = routes.pop("_dest")
                _nx_hop.append(routes)

            _routes["next_hops"].extend(_nx_hop)

            if is_vrf:
                if strout.get(grp_vrf) and strout[grp_vrf].get(_afi):
                    strout[grp_vrf][_afi].append(_routes)
                else:
                    if strout.get(grp_vrf):
                        _tma = {_afi: [_routes]}
                        strout[grp_vrf].update(_tma)
                    else:
                        _tm = {grp_vrf: {_afi: [_routes]}}
                        strout.update(_tm)
            else:
                if strout.get(_afi):
                    strout[_afi].append(_routes)
                else:
                    _tma = {_afi: [_routes]}
                    strout.update(_tma)
        return strout

    def structure_static_routes(self, strout):
        _static_route_facts = []
        afi_v4 = strout.pop("ipv4", None)
        afi_v6 = strout.pop("ipv6", None)

        if afi_v4 or afi_v6:
            _triv_static_route = {"address_families": []}

            if afi_v4:
                _triv_static_route["address_families"].append(
                    {"afi": "ipv4", "routes": afi_v4},
                )
            if afi_v6:
                _triv_static_route["address_families"].append(
                    {"afi": "ipv6", "routes": afi_v6},
                )

            _static_route_facts.append(_triv_static_route)

        for k, v in strout.items():
            afi_v4 = v.pop("ipv4", None)
            afi_v6 = v.pop("ipv6", None)

            _vrf_static_route = {
                "vrf": k,
                "address_families": [],
            }

            if afi_v4:
                _vrf_static_route["address_families"].append(
                    {"afi": "ipv4", "routes": afi_v4},
                )
            if afi_v6:
                _vrf_static_route["address_families"].append(
                    {"afi": "ipv6", "routes": afi_v6},
                )

            _static_route_facts.append(_vrf_static_route)
        return _static_route_facts

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Static_routes network resource

        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf

        :rtype: dictionary
        :returns: facts
        """

        facts = {}
        objs = []

        if not data:
            data = self.get_static_routes_data(connection)

        # parse native config using the Static_routes template
        static_routes_parser = Static_routesTemplate(
            lines=data.splitlines(),
            module=self._module,
        )
        objs = static_routes_parser.parse()

        strout = self.process_static_routes(objs)
        objs = self.structure_static_routes(strout)

        ansible_facts["ansible_network_resources"].pop("static_routes", None)

        params = utils.remove_empties(
            static_routes_parser.validate_config(
                self.argument_spec,
                {"config": objs},
                redact=True,
            ),
        )

        facts["static_routes"] = params.get("config")
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
