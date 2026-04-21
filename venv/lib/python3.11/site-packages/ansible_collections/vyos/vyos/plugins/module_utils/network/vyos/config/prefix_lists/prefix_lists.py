#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The vyos_prefix_lists config file.
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
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.prefix_lists import (
    Prefix_listsTemplate,
)


class Prefix_lists(ResourceModule):
    """
    The vyos_prefix_lists config class
    """

    def __init__(self, module):
        super(Prefix_lists, self).__init__(
            empty_fact_val=[],
            facts_module=Facts(module),
            module=module,
            resource="prefix_lists",
            tmplt=Prefix_listsTemplate(),
        )
        self.plist_parsers = [
            "name",
            "description",
        ]
        self.entries_parsers = [
            "sequence",
            "action",
            "rule_description",
            "ge",
            "le",
            "prefix",
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
        wantd = {entry["afi"]: entry for entry in self.want}
        haved = {entry["afi"]: entry for entry in self.have}

        self._prefix_list_list_to_dict(wantd)
        self._prefix_list_list_to_dict(haved)

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "deleted":
            haved = {k: v for k, v in iteritems(haved) if k in wantd or not wantd}
            for key, hvalue in iteritems(haved):
                wvalue = wantd.pop(key, {})
                if wvalue:
                    wplists = wvalue.get("prefix_lists", {})
                    hplists = hvalue.get("prefix_lists", {})
                    hvalue["prefix_lists"] = {
                        k: v for k, v in iteritems(hplists) if k in wplists or not wplists
                    }

        # remove superfluous config for overridden and deleted
        if self.state in ["overridden", "deleted"]:
            for k, have in iteritems(haved):
                if k not in wantd:
                    self._compare(want={}, have=have)

        for k, want in iteritems(wantd):
            self._compare(want=want, have=haved.pop(k, {}))

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Prefix_lists network resource.
        """
        wplists = want.get("prefix_lists", {})
        hplists = have.get("prefix_lists", {})

        self._compare_plists(want=wplists, have=hplists)

        if self.state in ["overridden", "deleted"]:
            # remove remaining prefix lists
            for h in hplists.values():
                self.commands.append(
                    "delete policy prefix-{0} {1}".format(
                        "list" if h["afi"] == "ipv4" else "list6",
                        h["name"],
                    ),
                )

    def _compare_plists(self, want, have):
        for wk, wentry in iteritems(want):
            hentry = have.pop(wk, {})

            # parser list for name and descriptions
            self.compare(
                parsers=self.plist_parsers,
                want=wentry,
                have=hentry,
            )

            wplrules = wentry.get("entries", {})
            hplrules = hentry.get("entries", {})

            self._compare_rules(want=wplrules, have=hplrules)

    def _compare_rules(self, want, have):
        for wr, wrule in iteritems(want):
            hrule = have.pop(wr, {})

            # parser list for entries
            self.compare(
                parsers=self.entries_parsers,
                want=wrule,
                have=hrule,
            )

        # remove remaining entries
        for hr in have.values():
            self.commands.append(
                "delete policy prefix-{0} {1} rule {2}".format(
                    "list" if hr["afi"] == "ipv4" else "list6",
                    hr["name"],
                    hr["sequence"],
                ),
            )

    def _prefix_list_list_to_dict(self, entry):
        for afi, value in iteritems(entry):
            if "prefix_lists" in value:
                for pl in value["prefix_lists"]:
                    pl.update({"afi": afi})
                    if "entries" in pl:
                        for entry in pl["entries"]:
                            entry.update({"afi": afi, "name": pl["name"]})
                        pl["entries"] = {x["sequence"]: x for x in pl["entries"]}
                value["prefix_lists"] = {entry["name"]: entry for entry in value["prefix_lists"]}
