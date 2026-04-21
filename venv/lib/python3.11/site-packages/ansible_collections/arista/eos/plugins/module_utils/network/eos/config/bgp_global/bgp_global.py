#
# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The eos_bgp_global config file.
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

from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.facts import Facts
from ansible_collections.arista.eos.plugins.module_utils.network.eos.rm_templates.bgp_global import (
    Bgp_globalTemplate,
)


class Bgp_global(ResourceModule):
    """
    The eos_bgp_global config class
    """

    def __init__(self, module):
        super(Bgp_global, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="bgp_global",
            tmplt=Bgp_globalTemplate(),
        )
        self.parsers = [
            "router",
            "vrf",
            "default_metric",
            "distance",
            "graceful_restart",
            "graceful_restart_helper",
            "maximum_paths",
            "monitoring",
            "route_target",
            "router_id",
            "shutdown",
            "timers",
            "ucmp_fec",
            "ucmp_link_bandwidth",
            "ucmp_mode",
            "update",
            "vlan",
            "vlan_aware_bundle",
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
        if self.want.get("as_number") == self.have.get("as_number") or not self.have:
            if self.want:
                wantd = {self.want["as_number"]: self.want}
            if self.have:
                haved = {self.have["as_number"]: self.have}
        else:
            self._module.fail_json(
                msg="Only one bgp instance is allowed per device",
            )

        # turn all lists of dicts into dicts prior to merge
        for entry in wantd, haved:
            self._bgp_global_list_to_dict(entry)

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state in ["deleted", "purged"]:
            h_del = {}
            for k, v in iteritems(haved):
                if k in wantd or not wantd:
                    h_del.update({k: v})
            wantd = {}
            haved = h_del

        if self.state == "deleted":
            self._compare(want={}, have=self.have)

        if self.state == "purged":
            for num, entry in iteritems(haved):
                self.commands.append(
                    self._tmplt.render({"as_number": num}, "router", True),
                )

        for k, want in iteritems(wantd):
            self._compare(want=want, have=haved.pop(k, {}))

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Bgp_global network resource.
        """
        self._compare_vrfs(want, have)
        self._compare_neighbor(want, have)
        self._compare_lists(want, have)
        self._compare_bgp_params(want, have)
        for name, entry in iteritems(want):
            if name != "as_number":
                self.compare(
                    parsers=self.parsers,
                    want={name: entry},
                    have={name: have.pop(name, {})},
                )
        for name, entry in iteritems(have):
            if name != "as_number":
                self.compare(
                    parsers=self.parsers,
                    want={},
                    have={name: have.get(name)},
                )

        if self.commands and "router bgp" not in self.commands[0]:
            self.commands.insert(
                0,
                self._tmplt.render(want or have, "router", False),
            )

    def _compare_bgp_params(self, want, have):
        parsers = [
            "bgp_params_additional_paths",
            "bgp_params_advertise_inactive",
            "bgp_params_allowas_in",
            "bgp_params_always_compare_med",
            "bgp_params_asn",
            "bgp_params_auto_local_addr",
            "bgp_params_bestpath_as_path",
            "bgp_params_bestpath_ecmp_fast",
            "bgp_params_bestpath_med",
            "bgp_params_bestpath_skip",
            "bgp_params_tie_break",
            "bgp_params_client_to_client",
            "bgp_params_cluster_id",
            "bgp_params_confederation",
            "bgp_params_control_plane_filter",
            "bgp_params_convergence",
            "bgp_params_default",
            "bgp_params.enforce_first_as",
            "bgp_params.host_routes",
            "bgp_params.labelled_unicast",
            "bgp_params.listen_limit",
            "bgp_params.listen_range",
            "bgp_params.log_neighbor_changes",
            "bgp_params.missing_policy",
            "bgp_params.monitoring",
            "bgp_params.nexthop_unchanged",
            "bgp_params.redistribute_internal",
            "bgp_params.route",
            "bgp_params.route_reflector",
            "bgp_params.transport",
        ]
        wbgp = want.pop("bgp_params", {})
        hbgp = have.pop("bgp_params", {})
        for name, entry in iteritems(wbgp):
            if name == "bestpath":
                for k, v in iteritems(entry):
                    h = {}
                    if hbgp.get(name):
                        h = {name: hbgp[name].pop(v, {})}
                    self.compare(
                        parsers=parsers,
                        want={"bgp_params": {name: {k: v}}},
                        have={"bgp_params": h},
                    )
                hbgp.pop(name, {})
                continue
            self.compare(
                parsers=parsers,
                want={"bgp_params": {name: entry}},
                have={"bgp_params": {name: hbgp.pop(name, {})}},
            )
        for name, entry in iteritems(hbgp):
            self.compare(
                parsers=parsers,
                want={},
                have={"bgp_params": {name: entry}},
            )

    def _compare_vrfs(self, want, have):
        wvrf = want.pop("vrfs", {})
        hvrf = have.pop("vrfs", {})
        begin = len(self.commands)
        for name, entry in iteritems(wvrf):
            self._compare_neighbor(entry, hvrf.get(name, {}))
            self._compare_lists(entry, hvrf.get(name, {}))
            self._compare_bgp_params(entry, hvrf.get(name, {}))
            for k, v in entry.items():
                if hvrf.get(name):
                    h = {k: hvrf[name].pop(k, {})}
                else:
                    h = {}
                if k != "vrf":
                    self.compare(parsers=self.parsers, want={k: v}, have=h)

            if len(self.commands) != begin:
                self.commands.insert(
                    begin,
                    self._tmplt.render({"vrf": name}, "vrf", False),
                )
                self.commands.append("exit")
        begin_negate = len(self.commands)
        for name, entry in iteritems(hvrf):
            if name not in wvrf.keys():
                if self._check_af(name):
                    self._module.fail_json(
                        msg="Use the _bgp_address_family module to delete the address_family under vrf, before replacing/deleting the vrf.",
                    )
                else:
                    self.commands.append(
                        self._tmplt.render({"vrf": name}, "vrf", True),
                    )
                continue
            self.compare(parsers=self.parsers, want={}, have=entry)
            after_negate = len(self.commands)
            if after_negate != begin_negate:
                if "vrf " + name in self.commands:
                    index = self.commands.index("vrf " + name)
                    i = begin_negate
                    while i < after_negate:
                        cmd = self.commands.pop(i)
                        if cmd != "exit":
                            self.commands.insert(index + 1, cmd)
                        i += 1
                else:
                    self.commands.insert(
                        begin_negate,
                        self._tmplt.render({"vrf": name}, "vrf", False),
                    )
                    self.commands.append("exit")

    def _get_config(self, connection):
        return connection.get("show running-config | section bgp ")

    def _check_af(self, vrf):
        af_present = False
        if self._connection:
            config_lines = self._get_config(self._connection).splitlines()
            index = [i + 1 for i, el in enumerate(config_lines) if vrf in el]
            if index:
                # had to do this to escape flake8 and black errors
                ind = index[0]
                for line in config_lines[ind:]:
                    if "vrf" in line:
                        break
                    if "address-family" in line:
                        af_present = True
                        break
        return af_present

    def _compare_neighbor(self, want, have):
        parsers = [
            "neighbor.additional_paths",
            "neighbor.allowas_in",
            "neighbor.auto_local_addr",
            "neighbor.bfd",
            "neighbor.default_originate",
            "neighbor.description",
            "neighbor.dont_capability_negotiate",
            "neighbor.ebgp_multihop",
            "neighbor.encryption_password",
            "neighbor.enforce_first_as",
            "neighbor.export_localpref",
            "neighbor.fall_over",
            "neighbor.graceful_restart",
            "neighbor.graceful_restart_helper",
            "neighbor.idle_restart_timer",
            "neighbor.import_localpref",
            "neighbor.link_bandwidth",
            "neighbor.local_as",
            "neighbor.local_v6_addr",
            "neighbor.maximum_accepted_routes",
            "neighbor.maximum_received_routes",
            "neighbor.metric_out",
            "neighbor.monitoring",
            "neighbor.next_hop_self",
            "neighbor.next_hop_unchanged",
            "neighbor.next_hop_v6_addr",
            "neighbor.out_delay",
            "neighbor.remote_as",
            "neighbor.remove_private_as",
            "neighbor.peer_group",
            "neighbor.prefix_list",
            "neighbor.route_map",
            "neighbor.route_reflector_client",
            "neighbor.route_to_peer",
            "neighbor.send_community",
            "neighbor.shutdown",
            "neighbor.soft_reconfiguration",
            "neighbor.transport",
            "neighbor.timers",
            "neighbor.ttl",
            "neighbor.update_source",
            "neighbor.weight",
        ]
        wneigh = want.pop("neighbor", {})
        hneigh = have.pop("neighbor", {})
        for name, entry in iteritems(wneigh):
            for k, v in entry.items():
                if entry.get("peer"):
                    peer = entry["peer"]
                else:
                    peer = entry["neighbor_address"]
                if hneigh.get(name):
                    h = {"neighbor_address": peer, k: hneigh[name].pop(k, {})}
                else:
                    h = {}
                self.compare(
                    parsers=parsers,
                    want={"neighbor": {"neighbor_address": peer, k: v}},
                    have={"neighbor": h},
                )
        for name, entry in iteritems(hneigh):
            if name not in wneigh.keys() and "peer_group" not in entry.keys():
                self.commands.append("no neighbor " + name)
                continue
            for k, v in entry.items():
                self.compare(
                    parsers=parsers,
                    want={},
                    have={"neighbor": {"neighbor_address": name, k: v}},
                )

    def _compare_lists(self, want, have):
        for attrib in [
            "redistribute",
            "network",
            "aggregate_address",
            "access_group",
        ]:
            wdict = want.pop(attrib, {})
            hdict = have.pop(attrib, {})
            for key, entry in iteritems(wdict):
                if entry != hdict.pop(key, {}):
                    self.addcmd(entry, attrib, False)
            # remove remaining items in have for replaced
            for entry in hdict.values():
                self.addcmd(entry, attrib, True)

    def _bgp_global_list_to_dict(self, entry):
        for name, proc in iteritems(entry):
            if "neighbor" in proc:
                neigh_dict = {}
                for entry in proc.get("neighbor", []):
                    if entry.get("peer"):
                        peer = entry["peer"]
                    else:
                        peer = entry["neighbor_address"]
                    neigh_dict.update({peer: entry})
                proc["neighbor"] = neigh_dict

            if "network" in proc:
                network_dict = {}
                for entry in proc.get("network", []):
                    network_dict.update({entry["address"]: entry})
                proc["network"] = network_dict

            if "aggregate_address" in proc:
                agg_dict = {}
                for entry in proc.get("aggregate_address", []):
                    agg_dict.update({entry["address"]: entry})
                proc["aggregate_address"] = agg_dict

            if "access_group" in proc:
                access_dict = {}
                for entry in proc.get("access_group", []):
                    access_dict.update({entry["afi"]: entry})
                proc["access_group"] = access_dict

            if "redistribute" in proc:
                redis_dict = {}
                for entry in proc.get("redistribute", []):
                    redis_dict.update({entry["protocol"]: entry})
                proc["redistribute"] = redis_dict

            if "vrfs" in proc:
                vrf_dict = {}
                for entry in proc.get("vrfs", []):
                    vrf_dict.update({entry["vrf"]: entry})
                proc["vrfs"] = vrf_dict
                self._bgp_global_list_to_dict(proc["vrfs"])
