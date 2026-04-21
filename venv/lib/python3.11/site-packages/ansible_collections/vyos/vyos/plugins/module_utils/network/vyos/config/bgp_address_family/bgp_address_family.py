#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The vyos_bgp_address_family config file.
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to its desired end-state is
created.
"""

import re

from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.resource_module import (
    ResourceModule,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    dict_merge,
)

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.facts.facts import Facts
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.bgp_address_family import (
    Bgp_address_familyTemplate,
)

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.bgp_address_family_14 import (
    Bgp_address_familyTemplate14,
)

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.vyos import get_os_version

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.utils.version import LooseVersion


class Bgp_address_family(ResourceModule):
    """
    The vyos_bgp_address_family config class
    """

    def __init__(self, module):
        super(Bgp_address_family, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="bgp_address_family",
            tmplt=Bgp_address_familyTemplate(),
        )
        self.parsers = []

    def _validate_template(self):
        version = get_os_version(self._module)
        if LooseVersion(version) >= LooseVersion("1.4"):
            self._tmplt = Bgp_address_familyTemplate14()
        else:
            self._tmplt = Bgp_address_familyTemplate()

    def parse(self):
        """ override parse to check template """
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
        wantd = {}
        haved = {}

        if (self.want.get("as_number") == self.have.get("as_number") or
                not self.have or
                LooseVersion(get_os_version(self._module)) >= LooseVersion("1.4")):
            if self.want:
                wantd = {self.want["as_number"]: self.want}
            if self.have:
                haved = {self.have["as_number"]: self.have}
        else:
            self._module.fail_json(msg="Only one bgp instance is allowed per device")

        # turn all lists of dicts into dicts prior to merge
        for entry in wantd, haved:
            self._bgp_af_list_to_dict(entry)

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "deleted":
            for k, have in iteritems(haved):
                self._delete_af(wantd, have)
            wantd = {}

        if self.state == "overridden":
            for k, have in iteritems(haved):
                if k not in wantd:
                    self._compare(want={}, have=have)

        for k, want in iteritems(wantd):
            self._compare(want=want, have=haved.pop(k, {}))

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Bgp_address_family network resource.
        """
        if LooseVersion(get_os_version(self._module)) >= LooseVersion("1.4"):
            self._compare_asn(want, have)

        self._compare_af(want, have)
        self._compare_neighbors(want, have)
        # Do the negation first
        command_set = []
        for cmd in self.commands:
            if cmd not in command_set:
                if "delete" in cmd:
                    command_set.insert(0, cmd)
                else:
                    command_set.append(cmd)
        self.commands = command_set

    def _compare_af(self, want, have):
        waf = want.get("address_family", {})
        haf = have.get("address_family", {})
        for name, entry in iteritems(waf):
            self._compare_lists(
                entry,
                have=haf.get(name, {}),
                as_number=want["as_number"],
                afi=name,
            )
        for name, entry in iteritems(haf):
            if name not in waf.keys() and self.state == "replaced":
                continue
            self._compare_lists({}, entry, as_number=have["as_number"], afi=name)

    def _delete_af(self, want, have):
        for as_num, entry in iteritems(want):
            for afi, af_entry in iteritems(entry.get("address_family", {})):
                if have.get("address_family"):
                    for hafi, hentry in iteritems(have["address_family"]):
                        if hafi == afi:
                            self.commands.append(
                                self._tmplt.render(
                                    {
                                        "as_number": as_num,
                                        "address_family": {"afi": afi},
                                    },
                                    "address_family",
                                    True,
                                ),
                            )
            for neigh, neigh_entry in iteritems(entry.get("neighbors", {})):
                if have.get("neighbors"):
                    for hneigh, hnentry in iteritems(have["neighbors"]):
                        if hneigh == neigh:
                            if not neigh_entry.get("address_family"):
                                self.commands.append(
                                    self._tmplt.render(
                                        {
                                            "as_number": as_num,
                                            "neighbors": {"neighbor_address": neigh},
                                        },
                                        "neighbors",
                                        True,
                                    ),
                                )
                            else:
                                for k in neigh_entry["address_family"].keys():
                                    if (
                                        hnentry.get("address_family")
                                        and k in hnentry["address_family"].keys()
                                    ):
                                        self.commands.append(
                                            self._tmplt.render(
                                                {
                                                    "as_number": as_num,
                                                    "neighbors": {
                                                        "neighbor_address": neigh,
                                                        "address_family": {"afi": k},
                                                    },
                                                },
                                                "neighbors.address_family",
                                                True,
                                            ),
                                        )

    def _compare_neighbors(self, want, have):
        parsers = [
            "neighbors.allowas_in",
            "neighbors.as_override",
            "neighbors.attribute_unchanged.as_path",
            "neighbors.attribute_unchanged.med",
            "neighbors.attribute_unchanged.next_hop",
            "neighbors.capability_dynamic",
            "neighbors.capability_orf",
            "neighbors.default_originate",
            "neighbors.distribute_list",
            "neighbors.prefix_list",
            "neighbors.filter_list",
            "neighbors.maximum_prefix",
            "neighbors.nexthop_local",
            "neighbors.nexthop_self",
            "neighbors.peer_group",
            "neighbors.remove_private_as",
            "neighbors.route_map",
            "neighbors.route_reflector_client",
            "neighbors.route_server_client",
            "neighbors.soft_reconfiguration",
            "neighbors.unsuppress_map",
            "neighbors.weight",
        ]
        wneigh = want.get("neighbors", {})
        hneigh = have.get("neighbors", {})
        for name, entry in iteritems(wneigh):
            for afi, af_entry in iteritems(entry.get("address_family")):
                for k, val in iteritems(af_entry):
                    w = {
                        "as_number": want["as_number"],
                        "neighbors": {
                            "neighbor_address": name,
                            "address_family": {"afi": afi, k: val},
                        },
                    }
                    h = {}
                    if hneigh.get(name):
                        if hneigh[name]["address_family"].get(afi):
                            if hneigh[name]["address_family"][afi].get(k):
                                h = {
                                    "as_number": want["as_number"],
                                    "neighbors": {
                                        "neighbor_address": name,
                                        "address_family": {
                                            "afi": afi,
                                            k: hneigh[name]["address_family"][afi].pop(k, {}),
                                        },
                                    },
                                }
                    self.compare(
                        parsers=parsers,
                        want=w,
                        have=h,
                    )
        for name, entry in iteritems(hneigh):
            if name not in wneigh.keys():
                # remove surplus config for overridden and replaced
                if self.state != "replaced":
                    self.commands.append(
                        self._tmplt.render(
                            {
                                "as_number": have["as_number"],
                                "neighbors": {"neighbor_address": name},
                            },
                            "neighbors",
                            True,
                        ),
                    )
                continue

            for hafi, haf_entry in iteritems(entry.get("address_family")):
                # remove surplus configs for given neighbor - replace and overridden
                for k, val in iteritems(haf_entry):
                    h = {
                        "as_number": have["as_number"],
                        "neighbors": {
                            "neighbor_address": name,
                            "address_family": {"afi": hafi, k: val},
                        },
                    }
                    self.compare(parsers=parsers, want={}, have=h)

    def _compare_lists(self, want, have, as_number, afi):
        parsers = [
            "aggregate_address",
            "network",
            "network.backdoor",
            "network.path_limit",
            "network.route_map",
            "redistribute",
            "redistribute.metric",
            "redistribute.route_map",
            "redistribute.table",
        ]

        if LooseVersion(get_os_version(self._module)) >= LooseVersion("1.4"):
            delete_asn = ""
        else:
            delete_asn = " " + str(as_number)

        for attrib in ["redistribute", "networks", "aggregate_address"]:
            wdict = want.pop(attrib, {})
            hdict = have.pop(attrib, {})
            for key, entry in iteritems(wdict):
                if entry != hdict.get(key, {}):
                    self.compare(
                        parsers=parsers,
                        want={
                            "as_number": as_number,
                            "address_family": {"afi": afi, attrib: entry},
                        },
                        have={
                            "as_number": as_number,
                            "address_family": {
                                "afi": afi,
                                attrib: hdict.pop(key, {}),
                            },
                        },
                    )
                hdict.pop(key, {})
            # remove remaining items in have for replaced
            if not wdict and hdict:
                attrib = re.sub("_", "-", attrib)
                attrib = re.sub("networks", "network", attrib)
                self.commands.append(
                    "delete protocols bgp"
                    + delete_asn
                    + " "
                    + "address-family "
                    + afi
                    + " "
                    + attrib,
                )
                hdict = {}
            for key, entry in iteritems(hdict):
                self.compare(
                    parsers=parsers,
                    want={},
                    have={
                        "as_number": as_number,
                        "address_family": {"afi": afi, attrib: entry},
                    },
                )
        # de-duplicate child commands if parent command is present
        for val in (self.commands):
            for val2 in self.commands:
                if val != val2 and val2.startswith(val):
                    self.commands.remove(val2)

    def _compare_asn(self, want, have):
        if want.get("as_number") and not have.get("as_number"):
            self.commands.append(
                "set protocols bgp "
                + "system-as "
                + str(want.get("as_number")),
            )

    def _bgp_af_list_to_dict(self, entry):
        for name, proc in iteritems(entry):
            if "address_family" in proc:
                af_dict = {}
                for entry in proc.get("address_family"):
                    if "networks" in entry:
                        network_dict = {}
                        for n_entry in entry.get("networks", []):
                            network_dict.update({n_entry["prefix"]: n_entry})
                        entry["networks"] = network_dict

                    if "aggregate_address" in entry:
                        agg_dict = {}
                        for a_entry in entry.get("aggregate_address", []):
                            agg_dict.update({a_entry["prefix"]: a_entry})
                        entry["aggregate_address"] = agg_dict

                    if "redistribute" in entry:
                        redis_dict = {}
                        for r_entry in entry.get("redistribute", []):
                            proto_key = r_entry.get("protocol", "table")
                            redis_dict.update({proto_key: r_entry})
                        entry["redistribute"] = redis_dict

                for af in proc.get("address_family"):
                    af_dict.update({af["afi"]: af})
                proc["address_family"] = af_dict

            if "neighbors" in proc:
                neigh_dict = {}
                for entry in proc.get("neighbors", []):
                    neigh_dict.update({entry["neighbor_address"]: entry})
                proc["neighbors"] = neigh_dict
                self._bgp_af_list_to_dict(proc["neighbors"])
