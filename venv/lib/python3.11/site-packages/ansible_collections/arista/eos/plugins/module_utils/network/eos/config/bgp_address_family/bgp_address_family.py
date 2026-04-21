#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The eos_bgp_address_family config file.
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

from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.facts import Facts
from ansible_collections.arista.eos.plugins.module_utils.network.eos.rm_templates.bgp_address_family import (
    Bgp_afTemplate,
)


class Bgp_af(ResourceModule):
    """
    The eos_bgp_address_family config class
    """

    def __init__(self, module):
        super(Bgp_af, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="bgp_address_family",
            tmplt=Bgp_afTemplate(),
        )
        self.parsers = [
            "router",
            "address_family",
            "bgp_params_additional_paths",
            "bgp_params.nexthop_address_family",
            "bgp_params.nexthop_unchanged",
            "bgp_params.redistribute_internal",
            "bgp_params.route",
            "graceful_restart",
            "neighbor.activate",
            "neighbor.additional_paths",
            "neighbor.default_originate",
            "neighbor.graceful_restart",
            "neighbor.next_hop_unchanged",
            "neighbor.next_hop_address_family",
            "neighbor.prefix_list",
            "neighbor.route_map",
            "neighbor.weight",
            "neighbor.encapsulation",
            "network",
            "redistribute",
            "route_target",
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

        if self.want:
            wantd = {self.want["as_number"]: self.want}
        if self.have:
            haved = {self.have["as_number"]: self.have}

        # turn all lists of dicts into dicts prior to merge
        for entry in wantd, haved:
            self._bgp_af_list_to_dict(entry)

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)
            if len(wantd.keys()) > 1:
                self._module.fail_json(
                    msg="Only one bgp instance is allowed per device",
                )
                wantd = {}
        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "deleted":
            h_del = {}
            for k, v in iteritems(haved):
                if k in wantd or not wantd:
                    h_del.update({k: v})
            haved = h_del
            for wk, wv in iteritems(wantd):
                self._compare(want=wv, have=haved.pop(wk, {}))

            wantd = {}

        # remove superfluous config for overridden
        if self.state == "overridden":
            for k, have in iteritems(haved):
                if k not in wantd:
                    self._compare(want={}, have=have)
        for k, want in iteritems(wantd):
            self._compare(want=want, have=haved.pop(k, {}))

    def _delete_af(self, want, have):
        waf = want.get("address_family", {})
        haf = have.get("address_family", {})
        for hkey, entry in iteritems(haf):
            if hkey in waf.keys():
                af_no_command = self._tmplt.render(
                    entry,
                    "address_family",
                    True,
                ).split("\n")
                if re.search(r"\S+_\S+", hkey):
                    af_no_command[0] = af_no_command[0][3:]
                    af_no_command[1] = "no " + af_no_command[1]
                    for cmd in af_no_command:
                        self.commands.append(cmd)
                else:
                    self.addcmd(entry, "address_family", True)
        have = {}

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Bgp_af network resource.
        """
        for name, entry in iteritems(want):
            if name != "as_number":
                if self.state == "deleted":
                    self._delete_af(want, have)
                else:
                    self._compare_af({name: entry}, {name: have.get(name, {})})

        if self.commands and "router bgp" not in self.commands[0]:
            self.commands.insert(
                0,
                self._tmplt.render(
                    {"as_number": want.get("as_number") or have["as_number"]},
                    "router",
                    False,
                ),
            )

    def _compare_af(self, want, have):
        waf = want.get("address_family", {})
        haf = have.get("address_family", {})
        for name, entry in iteritems(waf):
            begin = len(self.commands)
            self._compare_lists(entry, have=haf.get(name, {}))
            self._compare_neighbor(entry, have=haf.get(name, {}))
            # Removing the alias key
            if "route_target" in entry.keys():
                entry["route_target"].pop("mode", "")
            self.compare(
                parsers=self.parsers,
                want=entry,
                have=haf.pop(name, {}),
            )
            if len(self.commands) != begin:
                af_command = self._tmplt.render(
                    entry,
                    "address_family",
                    False,
                ).split("\n")
                for cmd in af_command:
                    self.commands.insert(begin, cmd)
                    self.commands.append("exit")
                    begin += 1
        for name, entry in iteritems(haf):
            # skip superfluous configs for replaced
            if self.state in ["replaced"]:
                if name in waf.keys():
                    self.addcmd(entry, "address_family", True)
            else:
                # overridden
                # check if want has vrf or not
                # if want doesnot have vrf, device's vrf config will not
                # be touched.
                vrf_present = False
                for w_key in waf.keys():
                    if re.search(r"\S+_\S+", w_key):
                        vrf_present = True
                        break
                if vrf_present:
                    if re.search(r"\S+_\S+", name):
                        af_no_command = self._tmplt.render(
                            entry,
                            "address_family",
                            True,
                        ).split("\n")
                        if name not in waf.keys():
                            af_no_command[0] = af_no_command[0][3:]
                            af_no_command[1] = "no " + af_no_command[1]
                            for cmd in af_no_command:
                                self.commands.append(cmd)
                    else:
                        self.addcmd(entry, "address_family", True)
                else:
                    if not re.search(r"\S+_\S+", name):
                        self.addcmd(entry, "address_family", True)

    def _compare_neighbor(self, want, have):
        parsers = [
            "neighbor.activate",
            "neighbor.additional_paths",
            "neighbor.default_originate",
            "neighbor.graceful_restart",
            "neighbor.next_hop_unchanged",
            "neighbor.next_hop_address_family",
            "neighbor.prefix_list",
            "neighbor.route_map",
            "neighbor.weight",
            "neighbor.encapsulation",
        ]
        wneigh = want.get("neighbor", {})
        hneigh = have.get("neighbor", {})
        for name, entry in iteritems(wneigh):
            self.compare(
                parsers=parsers,
                want={"neighbor": entry},
                have={"neighbor": hneigh.pop(name, {})},
            )
        for name, entry in iteritems(hneigh):
            self.compare(parsers=parsers, want={}, have={"neighbor": entry})

    def _compare_lists(self, want, have):
        for attrib in ["redistribute", "network"]:
            wdict = want.pop(attrib, {})
            hdict = have.pop(attrib, {})
            for key, entry in iteritems(wdict):
                if entry != hdict.pop(key, {}):
                    self.addcmd(entry, attrib, False)
            # remove remaining items in have for replaced
            for entry in hdict.values():
                self.addcmd(entry, attrib, True)

    def _bgp_af_list_to_dict(self, entry):
        for name, proc in iteritems(entry):
            if "address_family" in proc:
                addr_dict = {}
                for entry in proc.get("address_family", []):
                    addr_dict.update(
                        {entry["afi"] + "_" + entry.get("vrf", ""): entry},
                    )
                proc["address_family"] = addr_dict
                self._bgp_af_list_to_dict(proc["address_family"])

            if "neighbor" in proc:
                neigh_dict = {}
                for entry in proc.get("neighbor", []):
                    neigh_dict.update({entry["peer"]: entry})
                proc["neighbor"] = neigh_dict

            if "network" in proc:
                network_dict = {}
                for entry in proc.get("network", []):
                    network_dict.update({entry["address"]: entry})
                proc["network"] = network_dict

            if "redistribute" in proc:
                redis_dict = {}
                for entry in proc.get("redistribute", []):
                    redis_dict.update({entry["protocol"]: entry})
                proc["redistribute"] = redis_dict
