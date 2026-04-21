#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The iosxr_bgp_neighbor_address_family config file.
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
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.rm_templates.bgp_neighbor_address_family import (
    Bgp_neighbor_address_familyTemplate,
)


class Bgp_neighbor_address_family(ResourceModule):
    """
    The iosxr_bgp_neighbor_address_family config class
    """

    def __init__(self, module):
        super(Bgp_neighbor_address_family, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="bgp_neighbor_address_family",
            tmplt=Bgp_neighbor_address_familyTemplate(),
        )
        self.parsers = [
            "router",
            "aigp",
            "allowas_in",
            "as_override",
            "bestpath_origin_as_allow_invalid",
            "capability_orf_prefix",
            "default_originate",
            "long_lived_graceful_restart_capable",
            "long_lived_graceful_restart_stale_time",
            "maximum_prefix",
            "multipath",
            "next_hop_self",
            "next_hop_unchanged",
            "optimal_route_reflection_group_name",
            "origin_as",
            "remove_private_AS",
            "route_reflector_client",
            "send_community_ebgp",
            "send_community_gshut_ebgp",
            "send_extended_community_ebgp",
            "send_multicast_attributes",
            "soft_reconfiguration",
            "weight",
            "site_of_origin",
            "validation",
            "route_policy.inbound",
            "route_policy.outbound",
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

        for entry in self.want, self.have:
            self._bgp_list_to_dict(entry)

        wantd = self.want
        haved = self.have
        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(self.have, self.want)

        # if state is deleted, empty out wantd and set haved to elements to delete
        if self.state == "deleted":
            if wantd:
                to_del = {
                    "neighbors": self._set_to_delete(haved, wantd),
                    "vrfs": {},
                }

                for k, hvrf in haved.get("vrfs", {}).items():
                    wvrf = wantd.get("vrfs", {}).get(k, {})
                    to_del["vrfs"][k] = {
                        "neighbors": self._set_to_delete(hvrf, wvrf),
                        "vrf": k,
                    }
                haved.update(to_del)

            wantd = {"as_number": haved.get("as_number")}

        self._compare(want=wantd, have=haved)

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Bgp_global network resource.
        """

        self._compare_neighbors(want=want, have=have)
        self._compare_vrf(want=want, have=have)
        if self.commands and "router bgp" not in self.commands[0]:
            self.commands.insert(
                0,
                self._tmplt.render(
                    {"as_number": want["as_number"]},
                    "router",
                    False,
                ),
            )

    def _compare_neighbors(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Bgp_global neighbor resource.
        """
        want_nbr = want.get("neighbors", {})
        have_nbr = have.get("neighbors", {})
        for name, entry in want_nbr.items():
            have = have_nbr.pop(name, {})
            begin = len(self.commands)
            self._compare_af(want=entry, have=have)
            if len(self.commands) != begin:
                self.commands.insert(begin, "neighbor {0}".format(name))

        # for deleted and overridden state
        if self.state != "replaced":
            for name, entry in have_nbr.items():
                begin = len(self.commands)
                self._compare_af(want={}, have=entry)
                if len(self.commands) != begin:
                    self.commands.insert(begin, "neighbor {0}".format(name))

    def _compare_af(self, want, have):
        """Custom handling of afs option
        :params want: the want BGP dictionary
        :params have: the have BGP dictionary
        """
        wafs = want.get("address_family", {})
        hafs = have.get("address_family", {})
        for name, entry in wafs.items():
            begin = len(self.commands)
            af_have = hafs.pop(name, {})
            self.compare(parsers=self.parsers, want=entry, have=af_have)
            if len(self.commands) != begin or (not af_have and entry):
                self.commands.insert(
                    begin,
                    self._tmplt.render(
                        {"afi": entry.get("afi"), "safi": entry.get("safi")},
                        "address_family",
                        False,
                    ),
                )

        for name, entry in hafs.items():
            self.addcmd(
                {"afi": entry.get("afi"), "safi": entry.get("safi")},
                "address_family",
                True,
            )

    def _compare_vrf(self, want, have):
        """Custom handling of VRFs option
        :params want: the want BGP dictionary
        :params have: the have BGP dictionary
        """
        wvrfs = want.get("vrfs", {})
        hvrfs = have.get("vrfs", {})
        for name, entry in wvrfs.items():
            begin = len(self.commands)
            vrf_have = hvrfs.pop(name, {})
            self._compare_neighbors(want=entry, have=vrf_have)
            if len(self.commands) != begin:
                self.commands.insert(begin, "vrf {0}".format(name))
        # for deleted and replaced state
        for name, entry in hvrfs.items():
            begin = len(self.commands)
            self._compare_neighbors(want={}, have=entry)
            if len(self.commands) != begin:
                self.commands.insert(begin, "vrf {0}".format(name))

    def _bgp_list_to_dict(self, data):
        if "neighbors" in data:
            for nbr in data["neighbors"]:
                if "address_family" in nbr:
                    nbr["address_family"] = {
                        (x["afi"], x.get("safi")): x for x in nbr["address_family"]
                    }
            data["neighbors"] = {x["neighbor_address"]: x for x in data["neighbors"]}

        if "vrfs" in data:
            for vrf in data["vrfs"]:
                self._bgp_list_to_dict(vrf)
            data["vrfs"] = {x["vrf"]: x for x in data["vrfs"]}

    def _set_to_delete(self, haved, wantd):
        neighbors = {}
        h_nbrs = haved.get("neighbors", {})
        w_nbrs = wantd.get("neighbors", {})

        for k, h_nbr in h_nbrs.items():
            w_nbr = w_nbrs.pop(k, {})
            if w_nbr:
                neighbors[k] = h_nbr
                afs_to_del = {}
                h_addrs = h_nbr.get("address_family", {})
                w_addrs = w_nbr.get("address_family", {})
                for af, h_addr in h_addrs.items():
                    if af in w_addrs:
                        afs_to_del[af] = h_addr
                neighbors[k]["address_family"] = afs_to_del

        return neighbors
