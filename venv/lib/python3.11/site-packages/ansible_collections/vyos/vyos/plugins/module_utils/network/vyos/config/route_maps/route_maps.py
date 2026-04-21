#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The vyos_route_maps config file.
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to its desired end-state is
created.
"""


from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.resource_module import (
    ResourceModule,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    dict_merge,
)

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.facts.facts import Facts
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


class Route_maps(ResourceModule):
    """
    The vyos_route_maps config class
    """

    def __init__(self, module):
        super(Route_maps, self).__init__(
            empty_fact_val=[],
            facts_module=Facts(module),
            module=module,
            resource="route_maps",
            tmplt=Route_mapsTemplate(),
        )
        self.parsers = [
            "call",
            "description",
            "action",
            "continue_sequence",
            "set_aggregator_ip",
            "set_aggregator_as",
            "set_as_path_exclude",
            "set_as_path_prepend",
            "set_atomic_aggregate",
            "set_bgp_extcommunity_rt",
            "set_extcommunity_rt",
            "set_extcommunity_soo",
            "set_extcommunity_bandwidth",
            "set_extcommunity_bandwidth_non_transitive",
            "set_ip_next_hop",
            "set_ipv6_next_hop",
            "set_large_community",
            "set_local_preference",
            "set_metric",
            "set_metric_type",
            "set_origin",
            "set_originator_id",
            "set_src",
            "set_tag",
            "set_weight",
            "set_table",
            "set_comm_list",
            "set_comm_list_delete",
            "set_community",
            "match_as_path",
            "match_community_community_list",
            "match_community_exact_match",
            "match_extcommunity",
            "match_interface",
            "match_large_community_large_community_list",
            "match_metric",
            "match_origin",
            "match_peer",
            "match_ip_address",
            "match_ip_next_hop",
            "match_ip_route_source",
            "on_match_goto",
            "on_match_next",
            "match_ipv6_address",
            "match_ipv6_nexthop",
            "match_protocol",
            "match_rpki",
        ]

    def _validate_template(self):
        version = get_os_version(self._module)
        if LooseVersion(version) >= LooseVersion("1.4"):
            self._tmplt = Route_mapsTemplate14()
        else:
            self._tmplt = Route_mapsTemplate()

    def parse(self):
        """override parse to check template"""
        self._validate_template()
        return super().parse()

    def get_parser(self, name):
        """get_parsers"""
        self._validate_template()
        return super().get_parser(name)

    def execute_module(self):
        """Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        self._validate_template()
        if self.state not in ["parsed", "gathered"]:
            self.generate_commands()
            self.run_commands()
        return self.result

    def generate_commands(self):
        """Generate configuration commands to send based on
        want, have and desired state.
        """
        wantd = self._route_maps_list_to_dict(self.want)
        haved = self._route_maps_list_to_dict(self.have)

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "deleted":
            haved = {k: v for k, v in iteritems(haved) if k in wantd or not wantd}
            wantd = {}

        # remove superfluous config for overridden and deleted
        if self.state in ["overridden", "deleted"]:
            for k, have in iteritems(haved):
                if k not in wantd:
                    self.commands.append(self._tmplt.render({"route_map": k}, "route_map", True))

        for wk, want in iteritems(wantd):
            self._compare(want=want, have=haved.pop(wk, {}))

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Route_maps network resource.
        """
        w_entries = want.get("entries", {})
        h_entries = have.get("entries", {})
        self._compare_entries(want=w_entries, have=h_entries)

    def _compare_entries(self, want, have):
        for wk, wentry in iteritems(want):
            hentry = have.pop(wk, {})
            self.compare(parsers=self.parsers, want=wentry, have=hentry)

    def _route_maps_list_to_dict(self, entry):
        entry = {x["route_map"]: x for x in entry}
        for rmap, data in iteritems(entry):
            if "entries" in data:
                for x in data["entries"]:
                    x.update({"route_map": rmap})
                data["entries"] = {
                    (rmap, entry.get("sequence")): entry for entry in data["entries"]
                }
        return entry
