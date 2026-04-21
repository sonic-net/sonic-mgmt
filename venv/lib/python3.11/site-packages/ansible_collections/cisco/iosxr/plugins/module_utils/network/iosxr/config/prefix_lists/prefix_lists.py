#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The iosxr_prefix_lists config file.
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to its desired end-state is
created.
"""


from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.resource_module import (
    ResourceModule,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    dict_merge,
)

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.facts.facts import Facts
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.rm_templates.prefix_lists import (
    Prefix_listsTemplate,
)


class Prefix_lists(ResourceModule):
    """
    The iosxr_prefix_lists config class
    """

    def __init__(self, module):
        super(Prefix_lists, self).__init__(
            empty_fact_val=[],
            facts_module=Facts(module),
            module=module,
            resource="prefix_lists",
            tmplt=Prefix_listsTemplate(),
        )
        self.parsers = ["prefix", "description", "prefix_list"]

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

        self._prefix_list_to_dict(wantd)
        self._prefix_list_to_dict(haved)

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "deleted":
            haved = {k: v for k, v in haved.items() if k in wantd or not wantd}
            wantd = {}

        # remove superfluous config for overridden and deleted
        if self.state in ["overridden", "deleted"]:
            for k, have in haved.items():
                if k not in wantd:
                    self._compare(want={}, have=have)

        for k, want in wantd.items():
            self._compare(want=want, have=haved.pop(k, {}))
            # alligning cmd with negate cmd 1st followed by config cmd
        if self.state in ["overridden", "replaced"]:
            self.commands = [each for each in self.commands if "no" in each] + [
                each for each in self.commands if "no" not in each
            ]

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Prefix_lists network resource.
        """
        self._compare_plists(
            want.get("prefix_lists", {}),
            have.get("prefix_lists", {}),
        )

    def _compare_plists(self, want, have):
        for wk, wentry in want.items():
            hentry = have.pop(wk, {})
            # compare sequences
            self._compare_seqs(
                wentry.pop("entries", {}),
                hentry.pop("entries", {}),
            )

        # remove remaining prefix lists
        for h in have.values():
            self.commands.append(
                "no {0} prefix-list {1}".format(h["afi"], h["name"]),
            )

    def _compare_seqs(self, want, have):
        for wseq, wentry in want.items():
            hentry = have.pop(wseq, {})
            self.compare(parsers=self.parsers, want=wentry, have=hentry)

        # remove remaining entries from have prefix list
        for hseq in have.values():
            self.compare(parsers=self.parsers, want={}, have=hseq)

    def _prefix_list_to_dict(self, entry):
        for afi, value in entry.items():
            if "prefix_lists" in value:
                for plist in value["prefix_lists"]:
                    plist.update({"afi": afi})
                    if "entries" in plist:
                        for seq in plist["entries"]:
                            seq.update({"afi": afi, "name": plist["name"]})
                        plist["entries"] = {x["sequence"]: x for x in plist["entries"]}
                value["prefix_lists"] = {
                    (entry["name"], afi): entry for entry in value["prefix_lists"]
                }
