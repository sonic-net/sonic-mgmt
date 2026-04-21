#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos_bgp_global config file.
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
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.bgp_global import (
    Bgp_globalTemplate,
)


class Bgp_global(ResourceModule):
    """
    The nxos_bgp_global config class
    """

    def __init__(self, module):
        super(Bgp_global, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="bgp_global",
            tmplt=Bgp_globalTemplate(),
        )
        # VRF parsers = 29
        self.parsers = [
            "allocate_index",
            "affinity_group.group_id",
            "bestpath.always_compare_med",
            "bestpath.as_path.ignore",
            "bestpath.as_path.multipath_relax",
            "bestpath.compare_neighborid",
            "bestpath.compare_routerid",
            "bestpath.cost_community_ignore",
            "bestpath.igp_metric_ignore",
            "bestpath.med.confed",
            "bestpath.med.missing_as_worst",
            "bestpath.med.non_deterministic",
            "cluster_id",
            "local_as",
            "local_as_config",
            "confederation.identifier",
            "graceful_restart",
            "graceful_restart.restart_time",
            "graceful_restart.stalepath_time",
            "graceful_restart.helper",
            "log_neighbor_changes",
            "maxas_limit",
            "neighbor_down.fib_accelerate",
            "reconnect_interval",
            "router_id",
            "timers.bestpath_limit",
            "timers.bgp",
            "timers.prefix_peer_timeout",
            "timers.prefix_peer_wait",
            # end VRF parsers
            "disable_policy_batching",
            "disable_policy_batching.ipv4.prefix_list",
            "disable_policy_batching.ipv6.prefix_list",
            "disable_policy_batching.nexthop",
            "dynamic_med_interval",
            "enforce_first_as",
            "enhanced_error",
            "fast_external_fallover",
            "flush_routes",
            "graceful_shutdown.activate",
            "graceful_shutdown.aware",
            "isolate",
            "nexthop.suppress_default_resolution",
            "shutdown",
            "suppress_fib_pending",
            "fabric_soo",
            "rd",
        ]
        self._af_data = {}

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
        # we fail early if state is merged or
        # replaced and want ASN != have ASN
        if self.state in ["merged", "replaced"]:
            w_asn = self.want.get("as_number")
            h_asn = self.have.get("as_number")

            if h_asn and w_asn != h_asn:
                self._module.fail_json(
                    msg="BGP is already configured with ASN {0}. "
                    "Please remove it with state purged before "
                    "configuring new ASN".format(h_asn),
                )

        if self.state in ["deleted", "replaced"]:
            self._build_af_data()

        for entry in self.want, self.have:
            self._bgp_list_to_dict(entry)

        # if state is deleted, clean up global params
        if self.state == "deleted":
            if not self.want or (self.have.get("as_number") == self.want.get("as_number")):
                self._compare(want={}, have=self.have)

        elif self.state == "purged":
            if not self.want or (self.have.get("as_number") == self.want.get("as_number")):
                self.addcmd(self.have or {}, "as_number", True)

        else:
            wantd = self.want
            # if state is merged, merge want onto have and then compare
            if self.state == "merged":
                wantd = dict_merge(self.have, self.want)

            self._compare(want=wantd, have=self.have)

    def _compare(self, want, have, vrf=None):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Bgp_global network resource.
        """
        begin = len(self.commands)
        self.compare(parsers=self.parsers, want=want, have=have)
        self._compare_confederation_peers(want, have)
        self._compare_neighbors(want, have, vrf=vrf)
        self._vrfs_compare(want=want, have=have)

        if len(self.commands) != begin or (not have and want):
            self.commands.insert(
                begin,
                self._tmplt.render(
                    want or have,
                    "vrf" if "vrf" in (want.keys() or have.keys()) else "as_number",
                    False,
                ),
            )

    def _compare_confederation_peers(self, want, have):
        """Custom handling of confederation.peers option

        :params want: the want BGP dictionary
        :params have: the have BGP dictionary
        """
        w_cpeers = want.get("confederation", {}).get("peers", [])
        h_cpeers = have.get("confederation", {}).get("peers", [])

        if set(w_cpeers) != set(h_cpeers):
            if self.state in ["replaced", "deleted"]:
                # if there are peers already configured
                # we need to remove those before we pass
                # the new ones otherwise the device appends
                # them to the existing ones
                if h_cpeers:
                    self.addcmd(have, "confederation.peers", True)
            if w_cpeers:
                self.addcmd(want, "confederation.peers", False)

    def _compare_neighbors(self, want, have, vrf=None):
        """Custom handling of neighbors option

        :params want: the want BGP dictionary
        :params have: the have BGP dictionary
        """
        nbr_parsers = [
            "remote_as",
            "bfd",
            "bfd.multihop.interval",
            "neighbor_affinity_group.group_id",
            "bmp_activate_server",
            "capability",
            "description",
            "disable_connected_check",
            "dont_capability_negotiate",
            "dscp",
            "dynamic_capability",
            "ebgp_multihop",
            "graceful_shutdown",
            "inherit.peer",
            "inherit.peer_session",
            "local_as",
            "local_as_config",
            "log_neighbor_changes",
            "low_memory",
            "password",
            "peer_type",
            "remove_private_as",
            "shutdown",
            "timers",
            "transport",
            "ttl_security",
            "update_source",
        ]
        wnbrs = want.get("neighbors", {})
        hnbrs = have.get("neighbors", {})

        # neighbors have separate contexts in NX-OS
        for name, entry in wnbrs.items():
            begin = len(self.commands)
            have_nbr = hnbrs.pop(name, {})

            self.compare(parsers=nbr_parsers, want=entry, have=have_nbr)
            self._compare_path_attribute(entry, have_nbr)

            if len(self.commands) != begin or (entry and not have_nbr):
                self.commands.insert(begin, self._tmplt.render(entry, "neighbor_address", False))

        # cleanup remaining neighbors
        # but do not negate it entirely
        # instead remove only those attributes
        # that this module manages
        for name, entry in hnbrs.items():
            if self._has_af(vrf=vrf, neighbor=name):
                self._module.fail_json(
                    msg="Neighbor {0} has address-family configurations. "
                    "Please use the nxos_bgp_neighbor_af module to remove those first.".format(
                        name,
                    ),
                )
            else:
                self.addcmd(entry, "neighbor_address", True)

    def _compare_path_attribute(self, want, have):
        """Custom handling of neighbor path_attribute
           option.

        :params want: the want neighbor dictionary
        :params have: the have neighbor dictionary
        """
        w_p_attr = want.get("path_attribute", {})
        h_p_attr = have.get("path_attribute", {})

        for wkey, wentry in w_p_attr.items():
            if wentry != h_p_attr.pop(wkey, {}):
                self.addcmd(wentry, "path_attribute", False)

        # remove remaining items in have for replaced
        for hkey, hentry in h_p_attr.items():
            self.addcmd(hentry, "path_attribute", True)

    def _vrfs_compare(self, want, have):
        """Custom handling of VRFs option

        :params want: the want BGP dictionary
        :params have: the have BGP dictionary
        """
        wvrfs = want.get("vrfs", {})
        hvrfs = have.get("vrfs", {})
        for name, entry in wvrfs.items():
            self._compare(want=entry, have=hvrfs.pop(name, {}), vrf=name)
        # cleanup remaining VRFs
        # but do not negate it entirely
        # instead remove only those attributes
        # that this module manages
        for name, entry in hvrfs.items():
            if self._has_af(vrf=name):
                self._module.fail_json(
                    msg="VRF {0} has address-family configurations. "
                    "Please use the nxos_bgp_af module to remove those first.".format(name),
                )
            else:
                self.addcmd(entry, "vrf", True)

    def _bgp_list_to_dict(self, entry):
        """Convert list of items to dict of items
           for efficient diff calculation.

        :params entry: data dictionary
        """

        def _build_key(x):
            """Build primary key for path_attribute
               option.
            :params x: path_attribute dictionary
            :returns: primary key as tuple
            """
            key_1 = "start_{0}".format(x.get("range", {}).get("start", ""))
            key_2 = "end_{0}".format(x.get("range", {}).get("end", ""))
            key_3 = "type_{0}".format(x.get("type", ""))
            key_4 = x["action"]

            return (key_1, key_2, key_3, key_4)

        def _update_as_numbers(x):
            # Check if both 'local_as' and 'local_as_config' are in the dictionary
            if "local_as" in x and "local_as_config" in x:
                if x["local_as"] and "as_number" in x["local_as_config"]:
                    del x["local_as"]

                elif x["local_as"] and "as_number" not in x["local_as_config"]:
                    # Move 'as_number' from 'local_as' to 'local_as_config'
                    x["local_as_config"]["as_number"] = x["local_as"]
                    del x["local_as"]

        if "neighbors" in entry:
            for x in entry["neighbors"]:
                _update_as_numbers(x)  # handle deprecated local_as with local_as_config
                if "path_attribute" in x:
                    x["path_attribute"] = {
                        _build_key(item): item for item in x.get("path_attribute", [])
                    }

            entry["neighbors"] = {x["neighbor_address"]: x for x in entry.get("neighbors", [])}

        if "vrfs" in entry:
            entry["vrfs"] = {x["vrf"]: x for x in entry.get("vrfs", [])}
            for _k, vrf in entry["vrfs"].items():
                self._bgp_list_to_dict(vrf)

    def _get_config(self):
        return self._connection.get("show running-config | section '^router bgp'")

    def _build_af_data(self):
        """Build a dictionary with AF related information
        from fetched BGP config.
         _af_data = {
             gbl_data = {'192.168.1.100', '192.168.1.101'},
             vrf_data = {
                 'vrf_1': {
                     'has_af': True,
                     'nbrs': {'192.0.1.1', '192.8.1.1'}
                 },
                 'vrf_2': {
                     'has_af': False,
                     'nbrs': set()
                 }
             }
         }
        """
        data = self._get_config().split("\n")
        cur_nbr = None
        cur_vrf = None
        gbl_data = set()
        vrf_data = {}

        for x in data:
            if x.strip().startswith("vrf"):
                cur_nbr = None
                cur_vrf = x.split(" ")[-1]
                vrf_data[cur_vrf] = {"nbrs": set(), "has_af": False}

            elif x.strip().startswith("neighbor"):
                cur_nbr = x.split(" ")[-1]

            elif x.strip().startswith("address-family"):
                if cur_nbr:
                    if cur_vrf:
                        vrf_data[cur_vrf]["nbrs"].add(cur_nbr)
                    else:
                        gbl_data.add(cur_nbr)
                else:
                    if cur_vrf:
                        vrf_data[cur_vrf]["has_af"] = True

        self._af_data["global"] = gbl_data
        self._af_data["vrf"] = vrf_data

    def _has_af(self, vrf=None, neighbor=None):
        """Determine if the given vrf + neighbor
           combination has AF configurations.

        :params vrf: vrf name
        :params neighbor: neighbor name
        :returns: bool
        """
        has_af = False

        if self._af_data:
            vrf_af_data = self._af_data.get("vrf", {})
            global_af_data = self._af_data.get("global", set())
            if vrf:
                vrf_nbr_has_af = vrf_af_data.get(vrf, {}).get("nbrs", set())
                vrf_has_af = vrf_af_data.get(vrf, {}).get("has_af", False)
                if neighbor and neighbor in vrf_nbr_has_af:
                    # we are inspecting neighbor within a VRF
                    # if the given neighbor has AF we return True
                    has_af = True
                else:
                    # we are inspecting VRF as a whole
                    # if there is at least one neighbor
                    # with AF or VRF has AF itself return True
                    if vrf_nbr_has_af or vrf_has_af:
                        has_af = True
            else:
                # we are inspecting top level neighbors
                # if the given neighbor has AF we return True
                if neighbor and neighbor in global_af_data:
                    has_af = True

        return has_af
