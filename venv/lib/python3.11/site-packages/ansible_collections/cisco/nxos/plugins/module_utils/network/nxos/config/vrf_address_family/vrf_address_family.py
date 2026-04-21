#
# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos_vrf_address_family config file.
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

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.facts import Facts
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.vrf_address_family import (
    Vrf_address_familyTemplate,
)


class Vrf_address_family(ResourceModule):
    """
    The nxos_vrf_address_family config class
    """

    def __init__(self, module):
        super(Vrf_address_family, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="vrf_address_family",
            tmplt=Vrf_address_familyTemplate(),
        )
        self.parsers = [
            "maximum",
        ]
        self.list_parsers = [
            "route_target.import",
            "route_target.export",
            "export.map",
            "export.vrf",
            "import.map",
            "import.vrf",
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
        wantd = self._vrf_address_family_list_to_dict(self.want)
        haved = self._vrf_address_family_list_to_dict(self.have)

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "deleted":
            haved = self._filter_have_to_want(haved, wantd)
            wantd = {}

        # remove superfluous config for overridden and deleted
        if self.state in ["overridden", "deleted"]:
            for k, have in haved.items():
                if k not in wantd:
                    self._compare(want={}, have=have, vrf=k)

        if self.state == "purged":
            purge_list = wantd or haved
            for k, item in purge_list.items():
                self.purge(k, item)
        else:
            for k, want in wantd.items():
                self._compare(want=want, have=haved.pop(k, {}), vrf=k)

    def _compare(self, want, have, vrf):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Vrf_address_family network resource.
        """
        begin = len(self.commands)
        self._compare_vrf_afs(want=want, have=have)
        if len(self.commands) != begin:
            self.commands.insert(begin, f"vrf context {vrf}")

    def _compare_vrf_afs(self, want, have):
        """Compare the VRF address families lists.
        :params want: the want VRF dictionary
        :params have: the have VRF dictionary
        """
        waafs = want.get("address_families", {})
        haafs = have.get("address_families", {})

        address_fam_list = [
            ("ipv4", "unicast"),
            ("ipv6", "unicast"),
            ("ipv4", "multicast"),
            ("ipv6", "multicast"),
        ]

        for item in address_fam_list:
            begin = len(self.commands)
            for afk, afv in waafs.items():
                if afv.get("afi", "") == item[0] and afv.get("safi", "") == item[1]:
                    self._compare_single_af(wantaf=afv, haveaf=haafs.pop(afk, {}))
            for afk, afv in haafs.items():
                if afv.get("afi", "") == item[0] and afv.get("safi", "") == item[1]:
                    self._compare_single_af(wantaf={}, haveaf=afv)
            if len(self.commands) != begin:
                self.commands.insert(
                    begin,
                    self._tmplt.render(
                        {"afi": item[0], "safi": item[1]},
                        "address_family",
                        False,
                    ),
                )

    def _compare_single_af(self, wantaf, haveaf):
        """Compare a single address family.
        :params want: the want address family dictionary
        :params have: the have address family dictionary
        """
        self.compare(parsers=self.parsers, want=wantaf, have=haveaf)
        self._compare_af_lists(want=wantaf, have=haveaf)

    def _compare_af_lists(self, want, have):
        """Compare single vrf af list items.
        :params want: the want list item dictionary
        :params have: the have list item dictionary
        """

        for attrib in self.list_parsers:
            parser_split = attrib.split(".")
            wdict = self._convert_to_dict(want.get(parser_split[0], []), parser_split[1])
            hdict = self._convert_to_dict(have.get(parser_split[0], []), parser_split[1])

            for key, entry in wdict.items():
                if entry != hdict.pop(key, {}):
                    self.addcmd(entry, attrib, False)
            # remove remaining items in have for replaced
            for entry in hdict.values():
                self.addcmd(entry, attrib, True)

    def purge(self, vrf, item):
        """Purge the VRF configuration"""
        self.commands.append(f"vrf context {vrf}")
        for i, value in item.get("address_families", {}).items():
            self.commands.append(
                self._tmplt.render(
                    {"afi": value.get("afi"), "safi": value.get("safi")},
                    "address_family",
                    True,
                ),
            )

    def _convert_to_dict(self, vrf_af_item: list, parser_item: str) -> dict:
        """Convert to dict based on parser name.

        :params vrf_af_item: the vrf af item
        :params parser_item: the parser name based on which it needs to be converted
        :returns: A dictionary with items that have the key parser_item
        """
        if not vrf_af_item:
            return {}

        result = {}
        for item in vrf_af_item:
            if parser_item in item:
                if parser_item == "vrf":
                    vrf_item = item.get("vrf", {})
                    key = f"vrf_{vrf_item.get('max_prefix', 'noprefix')}_{vrf_item.get('map_import', 'nomap')}"
                else:
                    key = item[parser_item]
                result[key] = item
        return result

    def _filter_have_to_want(self, haved, wantd):
        if isinstance(haved, dict) and isinstance(wantd, dict):
            filtered = {
                k: self._filter_have_to_want(haved[k], wantd[k]) for k in haved if k in wantd
            }
            return {k: v for k, v in filtered.items() if v not in [None, {}, []]}
        elif isinstance(haved, list) and isinstance(wantd, list):
            filtered_list = []
            for h_item in haved:
                if isinstance(h_item, dict):
                    for w_item in wantd:
                        filtered_item = self._filter_have_to_want(h_item, w_item)
                        if filtered_item not in [None, {}, []]:
                            filtered_list.append(filtered_item)
                            break
                else:
                    if h_item in wantd:
                        filtered_list.append(h_item)
            return filtered_list
        else:
            return haved if haved == wantd else None

    def _vrf_address_family_list_to_dict(self, vrf_af_list: list) -> dict:
        """Convert a list of vrf_address_family dictionaries to a dictionary.

        :param vrf_af_list: A list of vrf_address_family dictionaries.
        :type vrf_af_list: list
        :rtype: dict
        :returns: A dictionary of vrf_address_family dictionaries.
        """

        items = {}
        for af_item in vrf_af_list:
            name = af_item.get("name")
            address_families = af_item.get("address_families", [])
            item = {
                "name": name,
                "address_families": {
                    f"{name}_{af.get('afi')}_{af.get('safi')}": af for af in address_families
                },
            }

            items[name] = item
        return items
