#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos_bgp_neighbor_address_family config file.
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to its desired end-state is
created.
"""
from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.resource_module import (
    ResourceModule,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    dict_merge,
)

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.facts import Facts
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.bgp_neighbor_address_family import (
    Bgp_neighbor_address_familyTemplate,
)


class Bgp_neighbor_address_family(ResourceModule):
    """
    The nxos_bgp_neighbor_address_family config class
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
            "advertise_map.exist_map",
            "advertise_map.non_exist_map",
            "advertisement_interval",
            "allowas_in",
            "as_override",
            "capability.additional_paths.receive",
            "capability.additional_paths.send",
            "default_originate",
            "disable_peer_as_check",
            "filter_list.inbound",
            "filter_list.outbound",
            "inherit",
            "maximum_prefix",
            "next_hop_self",
            "next_hop_third_party",
            "prefix_list.inbound",
            "prefix_list.outbound",
            "rewrite_evpn_rt_asn",
            "rewrite_rt_asn",
            "route_map.inbound",
            "route_map.outbound",
            "route_reflector_client",
            "send_community.extended",
            "send_community.standard",
            "soft_reconfiguration_inbound",
            "soo",
            "suppress_inactive",
            "unsuppress_map",
            "weight",
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
        wantd = deepcopy(self.want)
        haved = deepcopy(self.have)

        for entry in wantd, haved:
            self._bgp_list_to_dict(entry)

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

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

            wantd = {}

        self._compare(want=wantd, have=haved)

        if self.commands:
            self.commands.insert(0, "router bgp {as_number}".format(**haved or wantd))

    def _compare(self, want, have, vrf=""):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Bgp_neighbor_address_family network resource.
        """
        w_nbrs = want.get("neighbors", {})
        h_nbrs = have.get("neighbors", {})

        if vrf:
            begin_vrf = len(self.commands)

        for k, w_nbr in w_nbrs.items():
            begin = len(self.commands)
            h_nbr = h_nbrs.pop(k, {})
            want_afs = w_nbr.get("address_family", {})
            have_afs = h_nbr.get("address_family", {})

            for k, want_af in want_afs.items():
                begin_af = len(self.commands)
                have_af = have_afs.pop(k, {})

                # swap `both` and `set` for idempotence
                if "send_community" in want_af:
                    if want_af["send_community"].get("both"):
                        want_af["send_community"] = {
                            "extended": True,
                            "standard": True,
                        }
                    elif want_af["send_community"].get("set"):
                        want_af["send_community"].update({"standard": True})

                self.compare(parsers=self.parsers, want=want_af, have=have_af)

                if len(self.commands) != begin_af or (not have_af and want_af):
                    self.commands.insert(
                        begin_af,
                        self._tmplt.render(want_af, "address_family", False),
                    )

            # remove remaining items in have for replaced
            for k, have_af in have_afs.items():
                self.addcmd(have_af, "address_family", True)

            if len(self.commands) != begin:
                self.commands.insert(begin, "neighbor {0}".format(w_nbr["neighbor_address"]))

        if self.state in ["overridden", "deleted"]:
            for k, h_nbr in h_nbrs.items():
                begin = len(self.commands)
                if not w_nbrs.pop(k, {}):
                    have_afs = h_nbr.get("address_family", {})
                    for k, have_af in have_afs.items():
                        self.addcmd(have_af, "address_family", True)
                if len(self.commands) != begin:
                    self.commands.insert(begin, "neighbor {0}".format(h_nbr["neighbor_address"]))

        if vrf:
            if len(self.commands) != begin_vrf:
                self.commands.insert(begin_vrf, "vrf {0}".format(vrf))
        else:
            self._vrfs_compare(want, have)

    def _vrfs_compare(self, want, have):
        wvrfs = want.get("vrfs", {})
        hvrfs = have.get("vrfs", {})
        for k, wvrf in wvrfs.items():
            h_vrf = hvrfs.pop(k, {})
            self._compare(want=wvrf, have=h_vrf, vrf=k)
        # remove remaining items in have
        for k, h_vrf in hvrfs.items():
            self._compare(want={}, have=h_vrf, vrf=k)

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
