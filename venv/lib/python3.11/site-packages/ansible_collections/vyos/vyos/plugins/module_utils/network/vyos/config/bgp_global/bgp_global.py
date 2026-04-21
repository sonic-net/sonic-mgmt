#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The vyos_bgp_global config file.
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
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.bgp_global import (
    Bgp_globalTemplate,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.bgp_global_14 import (
    Bgp_globalTemplate14,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.utils.version import (
    LooseVersion,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.vyos import get_os_version


class Bgp_global(ResourceModule):
    """
    The vyos_bgp_global config class
    """

    def __init__(self, module):
        super(Bgp_global, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="bgp_global",
            tmplt=Bgp_globalTemplate(),
        )
        self.parsers = []

    def _validate_template(self):
        version = get_os_version(self._module)
        if LooseVersion(version) >= LooseVersion("1.4"):
            self._tmplt = Bgp_globalTemplate14()
        else:
            self._tmplt = Bgp_globalTemplate()

    def parse(self):
        """override parse to check template"""
        self._validate_template()
        return super().parse()

    def get_parser(self, name):
        """get_parsers"""
        self._validate_template()
        return super().get_parser(name)

    def execute_module(self):
        """Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        version = get_os_version(self._module)
        if LooseVersion(version) >= LooseVersion("1.4"):
            self._asn_mod = ""
        else:
            self._asn_mod = " " + str(self.have.get("as_number"))
        self._validate_template()
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

        if (
            self.want.get("as_number") == self.have.get("as_number")
            or not self.have
            or LooseVersion(get_os_version(self._module)) >= LooseVersion("1.4")
        ):
            if self.want:
                wantd = {self.want["as_number"]: self.want}
            if self.have:
                haved = {self.have["as_number"]: self.have}
        else:
            self._module.fail_json(msg="Only one bgp instance is allowed per device")

        # turn all lists of dicts into dicts prior to merge
        for entry in wantd, haved:
            self._bgp_global_list_to_dict(entry)

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "purged":
            h_del = {}
            for k, v in iteritems(haved):
                if k in wantd or not wantd:
                    h_del.update({k: v})
            for num, entry in iteritems(h_del):
                self.commands.append(self._tmplt.render({"as_number": num}, "router", True))
            wantd = {}

        if self.state == "deleted":
            self._compare(want={}, have=self.have)
            wantd = {}

        for k, want in iteritems(wantd):
            self._compare(want=want, have=haved.pop(k, {}))

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Bgp_global network resource.
        """
        if LooseVersion(get_os_version(self._module)) >= LooseVersion("1.4"):
            self._compare_asn(want, have)

        parsers = ["maximum_paths", "timers"]
        self._compare_neighbor(want, have)
        self._compare_bgp_params(want, have)
        for name, entry in iteritems(want):
            if name != "as_number":
                self.compare(
                    parsers=parsers,
                    want={"as_number": want["as_number"], name: entry},
                    have={
                        "as_number": want["as_number"],
                        name: have.pop(name, {}),
                    },
                )
        for name, entry in iteritems(have):
            if name != "as_number":
                self.compare(
                    parsers=parsers,
                    want={},
                    have={"as_number": have["as_number"], name: entry},
                )
        # Do the negation first
        command_set = []
        for cmd in self.commands:
            if cmd not in command_set:
                if "delete" in cmd:
                    command_set.insert(0, cmd)
                else:
                    command_set.append(cmd)
        self.commands = command_set

    def _compare_neighbor(self, want, have):
        parsers = [
            "neighbor.advertisement_interval",
            "neighbor.allowas_in",
            "neighbor.as_override",
            "neighbor.attribute_unchanged.as_path",
            "neighbor.attribute_unchanged.med",
            "neighbor.attribute_unchanged.next_hop",
            "neighbor.capability_dynamic",
            "neighbor.capability_orf",
            "neighbor.default_originate",
            "neighbor.description",
            "neighbor.disable_capability_negotiation",
            "neighbor.disable_connected_check",
            "neighbor.disable_send_community",
            "neighbor.distribute_list",
            "neighbor.ebgp_multihop",
            "neighbor.filter_list",
            "neighbor.local_as",
            "neighbor.maximum_prefix",
            "neighbor.nexthop_self",
            "neighbor.override_capability",
            "neighbor.passive",
            "neighbor.password",
            "neighbor.peer_group_name",
            "neighbor.port",
            "neighbor.prefix_list",
            "neighbor.remote_as",
            "neighbor.remove_private_as",
            "neighbor.route_map",
            "neighbor.route_reflector_client",
            "neighbor.route_server_client",
            "neighbor.shutdown",
            "neighbor.soft_reconfiguration",
            "neighbor.strict_capability_match",
            "neighbor.unsuppress_map",
            "neighbor.update_source",
            "neighbor.weight",
            "neighbor.ttl_security",
            "neighbor.timers",
        ]

        wneigh = want.pop("neighbor", {})
        hneigh = have.pop("neighbor", {})
        self._compare_neigh_lists(wneigh, hneigh)

        for name, entry in iteritems(wneigh):
            for k, v in entry.items():
                if k == "address":
                    continue
                if hneigh.get(name):
                    h = {"address": name, k: hneigh[name].pop(k, {})}
                else:
                    h = {}
                self.compare(
                    parsers=parsers,
                    want={
                        "as_number": want["as_number"],
                        "neighbor": {"address": name, k: v},
                    },
                    have={"as_number": want["as_number"], "neighbor": h},
                )
        for name, entry in iteritems(hneigh):
            if name not in wneigh.keys():
                if self._check_af(name):
                    msg = "Use the _bgp_address_family module to delete the address_family under neighbor {0}, before replacing/deleting the neighbor.".format(
                        name,
                    )
                    self._module.fail_json(msg=msg)
                else:
                    self.commands.append(
                        "delete protocols bgp" + self._asn_mod + " neighbor " + name,
                    )
                    continue
            for k, v in entry.items():
                self.compare(
                    parsers=parsers,
                    want={},
                    have={
                        "as_number": have["as_number"],
                        "neighbor": {"address": name, k: v},
                    },
                )

    def _compare_bgp_params(self, want, have):
        parsers = [
            "bgp_params.always_compare_med",
            "bgp_params.bestpath.as_path",
            "bgp_params.bestpath.compare_routerid",
            "bgp_params.bestpath.med",
            "bgp_params.cluster_id",
            "bgp_params.confederation",
            "bgp_params.dampening_half_life",
            "bgp_params.dampening_max_suppress_time",
            "bgp_params.dampening_re_use",
            "bgp_params.dampening_start_suppress_time",
            "bgp_params.default",
            "bgp_params.deterministic_med",
            "bgp_params.disbale_network_import_check",
            "bgp_params.enforce_first_as",
            "bgp_params.graceful_restart",
            "bgp_params.log_neighbor_changes",
            "bgp_params.no_client_to_client_reflection",
            "bgp_params.no_fast_external_failover",
            "bgp_params.routerid",
            "bgp_params.scan_time",
        ]

        wbgp = want.pop("bgp_params", {})
        hbgp = have.pop("bgp_params", {})
        for name, entry in iteritems(wbgp):
            if name == "confederation":
                if entry != hbgp.pop(name, {}):
                    self.addcmd(
                        {
                            "as_number": want["as_number"],
                            "bgp_params": {name: entry},
                        },
                        "bgp_params.confederation",
                        False,
                    )
            elif name == "distance":
                if entry != hbgp.pop(name, {}):
                    distance_parsers = [
                        "bgp_params.distance.global",
                        "bgp_params.distance.prefix",
                    ]
                    for distance_type in entry:
                        self.compare(
                            parsers=distance_parsers,
                            want={
                                "as_number": want["as_number"],
                                "bgp_params": {name: distance_type},
                            },
                            have={
                                "as_number": want["as_number"],
                                "bgp_params": {name: hbgp.pop(name, {})},
                            },
                        )
            else:
                self.compare(
                    parsers=parsers,
                    want={
                        "as_number": want["as_number"],
                        "bgp_params": {name: entry},
                    },
                    have={
                        "as_number": want["as_number"],
                        "bgp_params": {name: hbgp.pop(name, {})},
                    },
                )
        if not wbgp and hbgp:
            self.commands.append("delete protocols bgp" + self._asn_mod + " parameters")
            hbgp = {}
        for name, entry in iteritems(hbgp):
            if name == "confederation":
                self.commands.append(
                    "delete protocols bgp" + self._asn_mod + " parameters confederation",
                )
            elif name == "distance":
                distance_parsers = [
                    "bgp_params.distance.global",
                    "bgp_params.distance.prefix",
                ]
                self.compare(
                    parsers=distance_parsers,
                    want={},
                    have={
                        "as_number": have["as_number"],
                        "bgp_params": {name: entry[0]},
                    },
                )
            else:
                self.compare(
                    parsers=parsers,
                    want={},
                    have={
                        "as_number": have["as_number"],
                        "bgp_params": {name: entry},
                    },
                )

    def _compare_neigh_lists(self, want, have):
        for attrib in [
            "distribute_list",
            "filter_list",
            "prefix_list",
            "route_map",
        ]:
            wdict = want.pop(attrib, {})
            hdict = have.pop(attrib, {})
            for key, entry in iteritems(wdict):
                if entry != hdict.pop(key, {}):
                    self.addcmd(entry, "neighbor.{0}".format(attrib), False)
            # remove remaining items in have for replaced
            for entry in hdict.values():
                self.addcmd(entry, "neighbor.{0}".format(attrib), True)

    def _bgp_global_list_to_dict(self, entry):
        for name, proc in iteritems(entry):
            if "neighbor" in proc:
                neigh_dict = {}
                for entry in proc.get("neighbor", []):
                    neigh_dict.update({entry["address"]: entry})
                proc["neighbor"] = neigh_dict

            if "network" in proc:
                network_dict = {}
                for entry in proc.get("network", []):
                    network_dict.update({entry["address"]: entry})
                proc["network"] = network_dict

            if "aggregate_address" in proc:
                agg_dict = {}
                for entry in proc.get("aggregate_address", []):
                    agg_dict.update({entry["prefix"]: entry})
                proc["aggregate_address"] = agg_dict

            if "redistribute" in proc:
                redis_dict = {}
                for entry in proc.get("redistribute", []):
                    redis_dict.update({entry["protocol"]: entry})
                proc["redistribute"] = redis_dict

    def _compare_asn(self, want, have):
        if want.get("as_number") and not have.get("as_number"):
            self.commands.append(
                "set protocols bgp " + "system-as" + " " + str(want.get("as_number")),
            )

    def _check_af(self, neighbor):
        af_present = False
        if self._connection:
            config_lines = self._get_config(self._connection).splitlines()
            for line in config_lines:
                if neighbor in line:
                    if "address-family" in line:
                        af_present = True
        return af_present

    def _get_config(self, connection):
        return connection.get(
            'show configuration commands |  match "set protocols bgp .*neighbor"',
        )
