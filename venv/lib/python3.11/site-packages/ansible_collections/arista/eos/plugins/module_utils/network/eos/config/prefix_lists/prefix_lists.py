#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The eos_prefix_lists config file.
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
    dict_diff,
    dict_merge,
)

from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.facts import Facts
from ansible_collections.arista.eos.plugins.module_utils.network.eos.rm_templates.prefix_lists import (
    Prefix_listsTemplate,
)


class Prefix_lists(ResourceModule):
    """
    The eos_prefix_lists config class
    """

    def __init__(self, module):
        super(Prefix_lists, self).__init__(
            empty_fact_val=[],
            facts_module=Facts(module),
            module=module,
            resource="prefix_lists",
            tmplt=Prefix_listsTemplate(),
        )
        self.parsers = []

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
            wantd.update({entry["afi"]: entry})
        for entry in self.have:
            haved.update({entry["afi"]: entry})

        # turn all lists of dicts into dicts prior to merge
        for entry in wantd, haved:
            self._prefix_lists_list_to_dict(entry)

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
            wantd = {}

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
        h_parent = {}
        for k, v in iteritems(want):
            if k == "afi":
                continue
            afi = want["afi"]
            for pk, pv in iteritems(v):
                begin = len(self.commands)
                w_parent = {"afi": afi, "prefix_lists": {"name": pk}}
                if pv.get("entries"):
                    self._compare_prefix_lists(afi, pk, pv, have)
                if have.get("prefix_lists"):
                    if have["prefix_lists"].get(pk):
                        h_parent = {"afi": afi, "prefix_lists": {"name": pk}}
                if begin != len(self.commands):
                    self.commands.insert(
                        begin,
                        self._tmplt.render(
                            w_parent or h_parent,
                            "prefixlist.name",
                            False,
                        ),
                    )
        for hk, hv in iteritems(have):
            if hk == "afi":
                continue
            h_afi = have["afi"]
            for hpk, hpv in iteritems(hv):
                self.commands.append(
                    self._tmplt.render(
                        {"afi": h_afi, "prefix_lists": {"name": hpk}},
                        "prefixlist.name",
                        True,
                    ),
                )

    def _compare_prefix_lists(self, afi, pk, w_list, have):
        parser = ["prefixlist.entry", "prefixlist.resequence"]
        for ek, ev in iteritems(w_list):
            if ek == "name":
                continue
            h_child = {}
            if have.get("prefix_lists"):
                if have["prefix_lists"].get(pk):
                    if have["prefix_lists"][pk].get(ek):
                        self._compare_seq(
                            afi,
                            w_list["entries"],
                            have["prefix_lists"][pk][ek],
                        )
                    for seq, seq_val in iteritems(
                        have["prefix_lists"][pk][ek],
                    ):
                        h_child = {
                            "afi": afi,
                            "prefix_lists": {"entries": {seq: seq_val}},
                        }
                        self.compare(parsers=parser, want={}, have=h_child)
                    have["prefix_lists"].pop(pk)
                else:
                    self._compare_seq(afi, w_list["entries"], {})
            else:
                self._compare_seq(afi, w_list["entries"], {})

    def _compare_seq(self, afi, w, h):
        wl_child = {}
        hl_child = {}
        parser = ["prefixlist.entry", "prefixlist.resequence"]
        for seq, ent in iteritems(w):
            seq_diff = {}
            wl_child = {"afi": afi, "prefix_lists": {"entries": {seq: ent}}}
            if h.get(seq):
                hl_child = {
                    "afi": afi,
                    "prefix_lists": {"entries": {seq: h.pop(seq)}},
                }
                seq_diff = dict_diff(
                    hl_child["prefix_lists"]["entries"][seq],
                    wl_child["prefix_lists"]["entries"][seq],
                )
            if seq_diff:
                if self.state == "merged":
                    self._module.fail_json(
                        msg="Sequence number "
                        + str(seq)
                        + " is already present. Use replaced/overridden operation to change the configuration",
                    )

                self.compare(
                    parsers="prefixlist.entry",
                    want={},
                    have=hl_child,
                )
            self.compare(parsers=parser, want=wl_child, have=hl_child)

    def _prefix_lists_list_to_dict(self, entry):
        for afi, plist in iteritems(entry):
            if "prefix_lists" in plist:
                pl_dict = {}
                for el in plist["prefix_lists"]:
                    if "entries" in el:
                        ent_dict = {}
                        for en in el["entries"]:
                            if "sequence" not in en.keys():
                                num = "seq"
                            else:
                                num = en["sequence"]
                            ent_dict.update({num: en})
                        el["entries"] = ent_dict
                for el in plist["prefix_lists"]:
                    pl_dict.update({el["name"]: el})
                plist["prefix_lists"] = pl_dict
