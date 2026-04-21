#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos_bgp_address_family config file.
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
    remove_empties,
)

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.facts import Facts
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.bgp_address_family import (
    Bgp_address_familyTemplate,
)


class Bgp_address_family(ResourceModule):
    """
    The nxos_bgp_address_family config class
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
            "additional_paths.install_backup",
            "additional_paths.receive",
            "additional_paths.selection.route_map",
            "additional_paths.send",
            "advertise_l2vpn_evpn",
            "advertise_pip",
            "advertise_system_mac",
            "allow_vni_in_ethertag",
            "client_to_client.no_reflection",
            "dampen_igp_metric",
            "dampening",
            "default_information.originate",
            "default_metric",
            "distance",
            "export_gateway_ip",
            "maximum_paths.parallel_paths",
            "maximum_paths.ibgp.parallel_paths",
            "maximum_paths.eibgp.parallel_paths",
            "maximum_paths.local.parallel_paths",
            "maximum_paths.mixed.parallel_paths",
            "nexthop.route_map",
            "nexthop.trigger_delay",
            "retain.route_target.retain_all",
            "retain.route_target.route_map",
            "suppress_inactive",
            "table_map",
            "timers.bestpath_defer",
            "wait_igp_convergence",
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

        self._bgp_af_list_to_dict(wantd)
        self._bgp_af_list_to_dict(haved)

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        wantd = remove_empties(wantd)
        haved = remove_empties(haved)

        have_af = haved.get("address_family", {})
        want_af = wantd.get("address_family", {})
        wvrfs = wantd.get("vrfs", {})
        hvrfs = haved.get("vrfs", {})

        # if state is overridden or deleted, remove superfluos config
        if self.state in ["deleted", "overridden"]:
            if (haved and haved["as_number"] == wantd.get("as_number")) or not wantd:
                remove = True if self.state == "deleted" else False
                purge = True if not wantd else False
                self._remove_af(want_af, have_af, remove=remove, purge=purge)

                for k, hvrf in hvrfs.items():
                    wvrf = wvrfs.get(k, {})
                    self._remove_af(wvrf, hvrf, vrf=k, remove=remove, purge=purge)

        if self.state in ["merged", "replaced", "overridden", "rendered"]:
            for k, want in want_af.items():
                self._compare(want=want, have=have_af.pop(k, {}))

            # handle vrf->af
            for wk, wvrf in wvrfs.items():
                cur_ptr = len(self.commands)

                hvrf = hvrfs.pop(wk, {})
                for k, want in wvrf.items():
                    self._compare(want=want, have=hvrf.pop(k, {}))

                # add VRF command at correct position once
                if cur_ptr != len(self.commands):
                    self.commands.insert(cur_ptr, "vrf {0}".format(wk))

        if self.commands:
            self.commands.insert(0, "router bgp {as_number}".format(**haved or wantd))

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Bgp_address_family network resource.
        """
        begin = len(self.commands)

        self.compare(parsers=self.parsers, want=want, have=have)
        self._compare_lists(want=want, have=have)

        if len(self.commands) != begin or (not have and want):
            self.commands.insert(
                begin,
                self._tmplt.render(want or have, "address_family", False),
            )

    def _compare_lists(self, want, have):
        for attrib in [
            "aggregate_address",
            "inject_map",
            "networks",
            "redistribute",
        ]:
            wdict = want.get(attrib, {})
            hdict = have.get(attrib, {})
            for key, entry in wdict.items():
                if entry != hdict.pop(key, {}):
                    self.addcmd(entry, attrib.format(attrib), False)

            # remove remaining items in have for replaced
            for entry in hdict.values():
                self.addcmd(entry, attrib.format(attrib), True)

    def _bgp_af_list_to_dict(self, entry):
        def _build_key(data):
            """Build primary key for each dict

            :params x: dictionary
            :returns: primary key as tuple
            """
            # afi should always be present
            # safi and vrf are optional
            # a combination of these 3 uniquely
            # identifies an AF context
            afi = "afi_" + data["afi"]
            safi = "safi_" + data.get("safi", "")
            vrf = "vrf_" + data.get("vrf", "")

            return (afi, safi, vrf)

        # transform parameters which are
        # list of dicts to dict of dicts
        for item in entry.get("address_family", []):
            item["aggregate_address"] = {x["prefix"]: x for x in item.get("aggregate_address", [])}
            item["inject_map"] = {
                (x["route_map"], x["exist_map"]): x for x in item.get("inject_map", [])
            }
            item["networks"] = {x["prefix"]: x for x in item.get("networks", [])}
            item["redistribute"] = {
                (x.get("id"), x["protocol"]): x for x in item.get("redistribute", [])
            }

        # transform all entries under
        # config->address_family to dict of dicts
        af = {_build_key(x): x for x in entry.get("address_family", [])}

        temp = {}
        entry["vrfs"] = {}
        entry["address_family"] = {}

        # group AFs by VRFs
        # vrf_ denotes global AFs
        for k in af.keys():
            for x in k:
                if x.startswith("vrf_"):
                    if x not in temp:
                        temp[x] = {}
                    temp[x][k] = af[k]

        for k in temp.keys():
            if k == "vrf_":
                # populate global AFs
                entry["address_family"][k] = temp[k]
            else:
                # populate VRF AFs
                entry["vrfs"][k.replace("vrf_", "", 1)] = temp[k]

        entry["address_family"] = entry["address_family"].get("vrf_", {})

        # final structure: https://gist.github.com/NilashishC/628dae5fe39a4908e87c9e833bfbe57d

    def _remove_af(self, want_af, have_af, vrf=None, remove=False, purge=False):
        cur_ptr = len(self.commands)
        for k, v in have_af.items():
            # first conditional is for deleted with config provided
            # second conditional is for overridden
            # third condition is for deleted with empty config
            if any(
                (
                    (remove and k in want_af),
                    (not remove and k not in want_af),
                    purge,
                ),
            ):
                self.addcmd(v, "address_family", True)
        if cur_ptr < len(self.commands) and vrf:
            self.commands.insert(cur_ptr, "vrf {0}".format(vrf))
            self.commands.append("exit")
