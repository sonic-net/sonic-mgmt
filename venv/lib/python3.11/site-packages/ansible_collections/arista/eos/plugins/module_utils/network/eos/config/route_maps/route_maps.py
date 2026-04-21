#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The eos_route_maps config file.
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

from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.facts import Facts
from ansible_collections.arista.eos.plugins.module_utils.network.eos.rm_templates.route_maps import (
    Route_mapsTemplate,
)


class Route_maps(ResourceModule):
    """
    The eos_route_maps config class
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
            "continue",
            "route_map.copy",
            "route_map.rename",
            "description",
            "sub_route_map",
        ]

    def execute_module(self):
        """Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        if self.state not in ["parsed", "gathered"]:
            self.generate_commands()
            self.run_commands()
        return self.result

    def generate_commands(self):
        """Generate configuration commands to send based on
        want, have and desired state.
        """
        wantd = {}
        haved = {}

        for entry in self.want:
            wantd.update({entry["route_map"]: entry})
        for entry in self.have:
            haved.update({entry["route_map"]: entry})

        # turn all lists of dicts into dicts prior to merge
        for entry in wantd, haved:
            self._route_maps_list_to_dict(entry)
        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "deleted":
            h_del = {}
            for k, v in iteritems(haved):
                if k in wantd or not wantd:
                    h_del.update({k: v})
            haved = h_del
            for rmap, val in iteritems(haved):
                self.addcmd({"route_map": rmap}, "route_map.name", True)
            wantd = {}

        # remove superfluous config for overridden
        if self.state in ["overridden"]:
            for k, have in iteritems(haved):
                for entry, val in iteritems(have.get("entries", {})):
                    if not wantd.get(k) or entry not in wantd[k].get(
                        "entries",
                        {},
                    ):
                        self._compare_maps(want={}, have={entry: val})

        for k, want in iteritems(wantd):
            self._compare(want=want, have=haved.pop(k, {}))

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Route_maps network resource.
        """
        self._compare_entries(want=want, have=have)

    def _compare_entries(self, want, have):
        w_entries = want.get("entries", {})
        h_entries = have.get("entries", {})
        # overridden
        if not w_entries:
            for k, v in iteritems(h_entries):
                self._compare_maps({}, {k: v})
        for k, v in iteritems(w_entries):
            before_maps = len(self.commands)
            self._compare_maps({k: v}, {k: h_entries.get(k, {})})
            after_maps = len(self.commands)
            self._compare_match(v, h_entries.get(k, {}))
            self._comapre_set(v, h_entries.get(k, {}))
            for entry_k, entry_v in iteritems(v):
                h = {}
                if h_entries.get(k):
                    h = {"entries": {entry_k: h_entries[k].pop(entry_k, {})}}
                self.compare(
                    parsers=self.parsers,
                    want={"entries": {entry_k: entry_v}},
                    have=h,
                )
            for h_k, h_v in iteritems(h_entries.pop(k, {})):
                self.compare(
                    parsers=self.parsers,
                    have={"entries": {h_k: h_v}},
                    want={},
                )

            parent_present = False
            for c in self.commands[before_maps::]:
                if c.startswith("route-map"):
                    parent_present = True
                    break
            if (before_maps == after_maps and len(self.commands) > after_maps) or (
                not parent_present and len(self.commands) > after_maps
            ):
                self._compare_maps({k: v}, {})
                self.commands.insert(after_maps, self.commands.pop(-1))

    def _compare_maps(self, want, have):
        map_in_want = []
        for k, v in iteritems(want):
            map_name = k.split(" ")[0]
            map_in_want.append(map_name)
            w = {}
            h = {}
            h_entry = {}
            for entry_k, entry_v in iteritems(v):
                if entry_k not in [
                    "continue_sequence",
                    "sub_route_map",
                    "description",
                    "match",
                    "set",
                ]:
                    w.update({entry_k: entry_v})
                    if have.get(k):
                        h.update({entry_k: have[k].pop(entry_k, {})})
            if h:
                h_entry = {"route_map": map_name, "entries": h}
            parser = self._select_parser(w)
            self.compare(
                parsers=parser,
                want={"route_map": map_name, "entries": w},
                have=h_entry,
            )
        for k, v in iteritems(have):
            map_name = k.split(" ")[0]
            if k not in want.keys() and self.state in [
                "replaced",
                "overridden",
            ]:
                w_negate = {}
                if map_name not in map_in_want and self.state == "replaced":
                    continue
                parser = self._select_parser(v)
                w_negate.update({"route_map": map_name, "entries": v})
                self.addcmd(w_negate, parser, True)

    def _select_parser(self, w):
        parser = ""
        if "statement" in w.keys() and "action" in w.keys() and "sequence" in w.keys():
            parser = "route_map.statement.entries"
        elif "statement" in w.keys() and "action" in w.keys():
            parser = "route_map.statement.action"
        elif "statement" in w.keys():
            parser = "route_map.statement.name"
        elif "action" in w.keys() and "sequence" in w.keys():
            parser = "route_map.entries"
        elif "action" in w.keys():
            parser = "route_map.action"
        else:
            parser = "route_map.name"
        return parser

    def _compare_match(self, want, have):
        parsers = [
            "match.aggregate_role",
            "match.as",
            "match.as_path",
            "match.community.instances",
            "match.community.list",
            "match.extcommunity",
            "match.invert.aggregate_role",
            "match.invert.as_path",
            "match.invert.community.instances",
            "match.invert.community.list",
            "match.invert.extcommunity",
            "match.interface",
            "match.ip",
            "match.ipaddress",
            "match.ipv6",
            "match.ipv6address",
            "match.largecommunity",
            "match.isis",
            "match.local_pref",
            "match.metric",
            "match.metric_type",
            "match.route_type",
            "match.routerid",
            "match.source_protocol",
            "match.tag",
        ]
        w_match = want.pop("match", {})
        h_match = have.pop("match", {})
        for k, v in iteritems(w_match):
            if k in ["ip", "ipv6"]:
                for k_ip, v_ip in iteritems(v):
                    if h_match.get(k):
                        h = {k_ip: h_match[k].pop(k_ip, {})}
                    else:
                        h = {}
                    self.compare(
                        parsers=[
                            "match.ip",
                            "match.ipaddress",
                            "match.ipv6address",
                            "match.ipv6",
                        ],
                        want={"entries": {"match": {k: {k_ip: v_ip}}}},
                        have={"entries": {"match": {k: h}}},
                    )
                h_match.pop(k, {})
                continue
            self.compare(
                parsers=parsers,
                want={"entries": {"match": {k: v}}},
                have={"entries": {"match": {k: h_match.pop(k, {})}}},
            )
        for k, v in iteritems(h_match):
            if k in ["ip", "ipv6"]:
                for hk, hv in iteritems(v):
                    self.compare(
                        parsers=[
                            "match.ip",
                            "match.ipaddress",
                            "match.ipv6address",
                            "match.ipv6",
                        ],
                        want={},
                        have={"entries": {"match": {k: {hk: hv}}}},
                    )
                continue
            self.compare(
                parsers=parsers,
                want={},
                have={"entries": {"match": {k: v}}},
            )

    def _comapre_set(self, want, have):
        parsers = [
            "set.as_path.prepend",
            "set.as_path.match",
            "set.bgp",
            "set.community.graceful_shutdown",
            "set.community.none",
            "set.community.number",
            "set.community.list",
            "set.community.internet",
            "set.distance",
            "set.evpn",
            "set.extcommunity.lbw",
            "set.extcommunity.none",
            "set.extcommunity.rt",
            "set.extcommunity.soo",
            "set.ip",
            "set.ipv6",
            "set.isis",
            "set.local_pref",
            "set.metric.value",
            "set.metric_type",
            "set.nexthop",
            "set.origin",
            "set.segment_index",
            "set.tag",
            "set.weight",
        ]

        w_set = want.pop("set", {})
        h_set = have.pop("set", {})
        for k, v in iteritems(w_set):
            self.compare(
                parsers=parsers,
                want={"entries": {"set": {k: v}}},
                have={"entries": {"set": {k: h_set.pop(k, {})}}},
            )
        for k, v in iteritems(h_set):
            self.compare(
                parsers=parsers,
                want={},
                have={"entries": {"set": {k: v}}},
            )

    def _route_maps_list_to_dict(self, entry):
        for name, r_map in iteritems(entry):
            if r_map.get("entries"):
                map_dict = {}
                for entry in r_map["entries"]:
                    if entry.get("sequence"):
                        seq = entry["sequence"]
                    else:
                        seq = "seq"
                    mapkey = name + " " + str(seq)
                    map_dict.update({mapkey: entry})
                r_map["entries"] = map_dict
