#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The iosxr_bgp_address_family config file.
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
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.rm_templates.bgp_address_family import (
    Bgp_address_familyTemplate,
)


class Bgp_address_family(ResourceModule):
    """
    The iosxr_bgp_address_family config class
    """

    def __init__(self, module):
        super(Bgp_address_family, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="bgp_address_family",
            tmplt=Bgp_address_familyTemplate(),
        )
        self.parsers = [
            "router",
            "address_family",
            "advertise_best_external",
            "additional_paths",
            "allocate_label",
            "as_path_loopcheck_out_disable",
            "bgp_attribute_download",
            "bgp_bestpath_origin_as_use",
            "bgp_bestpath_origin_as_allow",
            "bgp_client_to_client_reflection_cluster_id",
            "bgp_reflection_disable",
            "bgp_dampening",
            "bgp_label_delay",
            "bgp_import_delay",
            "bgp_origin_as_validation",
            "bgp_scan_time",
            "default_martian_check_disable",
            "distance",
            "dynamic_med",
            "maximum_paths_ibgp",
            "maximum_paths_ebgp",
            "maximum_paths_eibgp",
            "optimal_route_reflection",
            "nexthop",
            "permanent_network_route_policy",
            "retain_local_label",
            "update",
            "global_table_multicast",
            "segmented_multicast",
            "inter_as_install",
            "vrf_all_conf",
            "weight",
            "route_target_download",
            "label_mode",
            "mvpn_single_forwarder_selection_highest_ip_address",
            "mvpn_single_forwarder_selection_all",
            "table_policy",
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
        wantd = self.want
        haved = self.have
        for entry in self.want, self.have:
            self._bgp_list_to_dict(entry)

        # if state is deleted, clean up global params
        if self.state == "deleted":
            if wantd:
                to_del = {"address_family": self._set_to_delete(haved, wantd)}
                haved.update(to_del)

            wantd = {"as_number": haved.get("as_number")}

        else:
            wantd = self.want
            # if state is merged, merge want onto have and then compare
            if self.state == "merged":
                wantd = dict_merge(self.have, self.want)

        self._compare(want=wantd, have=haved)

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Bgp_global network resource.
        """

        self._compare_af(want=want, have=have)
        if self.commands and "router bgp" not in self.commands[0]:
            self.commands.insert(
                0,
                self._tmplt.render(
                    {"as_number": want["as_number"]},
                    "router",
                    False,
                ),
            )

    def _compare_af(self, want, have):
        """Custom handling of afs option
        :params want: the want BGP dictionary
        :params have: the have BGP dictionary
        """
        wafs = want.get("address_family", {})
        hafs = have.get("address_family", {})
        vrf_want_have = []
        for name, entry in wafs.items():
            begin = len(self.commands)
            af_have = hafs.pop(name, {})
            if "vrf" in entry:
                vrf_want_have.append((entry, af_have))

            else:
                self.compare(parsers=self.parsers, want=entry, have=af_have)
                self._compare_lists(want=entry, have=af_have)
                if len(self.commands) != begin:
                    self.commands.insert(
                        begin,
                        self._tmplt.render(
                            {
                                "afi": entry.get("afi"),
                                "safi": entry.get("safi"),
                            },
                            "address_family",
                            False,
                        ),
                    )

        # compare af under vrf separately to ensure correct generation of commands
        for waf, haf in vrf_want_have:
            begin = len(self.commands)
            self.compare(parsers=self.parsers, want=waf, have=haf)
            self._compare_lists(want=waf, have=haf)
            if len(self.commands) != begin:
                self.commands.insert(
                    begin,
                    self._tmplt.render(
                        {"afi": waf.get("afi"), "safi": waf.get("safi")},
                        "address_family",
                        False,
                    ),
                )
                self.commands.insert(
                    begin,
                    self._tmplt.render({"vrf": waf.get("vrf")}, "vrf", False),
                )

        # for deleted and overridden state
        if self.state != "replaced":
            for name, entry in hafs.items():
                if "vrf" in entry:
                    self.addcmd({"vrf": entry.get("vrf")}, "vrf", False)
                self.addcmd(
                    {"afi": entry.get("afi"), "safi": entry.get("safi")},
                    "address_family",
                    True,
                )

    def _compare_lists(self, want, have):
        for attrib in ["aggregate_address", "networks", "redistribute"]:
            wdict = want.get(attrib, {})
            hdict = have.get(attrib, {})
            for key, entry in wdict.items():
                if entry != hdict.pop(key, {}):
                    self.addcmd(entry, attrib.format(attrib), False)

            # remove remaining items in have for replaced
            for entry in hdict.values():
                self.addcmd(entry, attrib.format(attrib), True)

    def _bgp_list_to_dict(self, entry):
        """Convert list of items to dict of items
           for efficient diff calculation.
        :params entry: data dictionary
        """
        for item in entry.get("address_family", []):
            item["aggregate_address"] = {x["value"]: x for x in item.get("aggregate_address", [])}
            item["networks"] = {x["network"]: x for x in item.get("networks", [])}
            item["redistribute"] = {
                (x.get("id"), x["protocol"]): x for x in item.get("redistribute", [])
            }

        if "address_family" in entry:
            entry["address_family"] = {
                "address_family_" + x["afi"] + "_" + x["safi"] + "_vrf_" + x.get("vrf", ""): x
                for x in entry.get("address_family", [])
            }

    def _get_config(self):
        return self._connection.get("show running-config router bgp")

    def _set_to_delete(self, haved, wantd):
        afs_to_del = {}
        h_addrs = haved.get("address_family", {})
        w_addrs = wantd.get("address_family", {})
        for af, h_addr in h_addrs.items():
            if af in w_addrs:
                afs_to_del[af] = h_addr
        return afs_to_del
