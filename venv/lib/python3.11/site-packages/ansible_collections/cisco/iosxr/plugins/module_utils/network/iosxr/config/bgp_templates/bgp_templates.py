#
# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The iosxr_bgp_templates config file.
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

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.facts.facts import Facts
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.rm_templates.bgp_templates import (
    Bgp_templatesTemplate,
)


class Bgp_templates(ResourceModule):
    """
    The iosxr_bgp_templates config class
    """

    def __init__(self, module):
        super(Bgp_templates, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="bgp_templates",
            tmplt=Bgp_templatesTemplate(),
        )
        self.parsers = [
            "router",
            "advertise.local_labeled_route.disable",
            "advertise.local_labeled_route.set",
            "advertise.permanent_network",
            "aigp.set",
            "aigp.disable",
            "aigp.send_med",
            "aigp.send_cost_community_disable",
            "allowas_in",
            "as_override",
            "bestpath_origin_as_allow_invalid",
            "capability_orf_prefix",
            "default_originate.set",
            "default_originate.route_policy",
            "default_originate.inheritance_disable",
            "long_lived_graceful_restart_capable",
            "long_lived_graceful_restart_stale_time",
            "maximum_prefix",
            "multipath",
            "next_hop_self",
            "next_hop_unchanged.set",
            "next_hop_unchanged.inheritance_disable",
            "next_hop_unchanged.multipath",
            "optimal_route_reflection_group_name",
            "origin_as",
            "remove_private_AS",
            "remove_private_AS.set",
            "route_reflector_client",
            "send_community_ebgp",
            "send_community_gshut_ebgp",
            "send_extended_community_ebgp",
            "send_multicast_attributes",
            "soft_reconfiguration",
            "weight",
            "route_policy.inbound",
            "route_policy.outbound",
            "signalling",
            "update.out_originator_loopcheck_disable",
            "update.out_originator_loopcheck_set",
            "use",
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
        w_asn = self.want.pop("as_number", "")
        h_asn = self.have.pop("as_number", "")

        asn = w_asn or h_asn
        wantd = self._bgp_list_to_dict(deepcopy(self.want))
        haved = self._bgp_list_to_dict(deepcopy(self.have))
        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "deleted":
            haved = {k: v for k, v in haved.items() if k in wantd or not wantd}
            wantd = {}

        if self.state in ["overridden", "deleted"]:
            cmds = []
            for k, have in haved.get("neighbor", {}).items():
                if k not in wantd.get("neighbor", {}):
                    cmds.append("no neighbor-group {0}".format(have["name"]))
            self.commands.extend(cmds)

        self._compare(asn, want=wantd, have=haved)

    def sort_commands(self, index):
        old_cmd = self.commands[index:]
        self.commands = self.commands[0:index]
        self.commands.extend(
            [each for each in old_cmd if "no" in each]
            + [each for each in old_cmd if "no" not in each],
        )

    def _compare(self, asn, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Bgp_global network resource.
        """
        self._compare_ngs(want=want, have=have)
        if self.commands and "router bgp" not in self.commands[0]:
            self.commands.insert(0, "router bgp {0}".format(asn))

    def _compare_ngs(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Bgp_global neighbor resource.
        """
        neighbor_parsers = [
            "use.neighbor_group",
            "use.session_group",
            "advertisement_interval",
            "bfd_fast_detect_disable",
            "bfd_fast_detect_strict_mode",
            "bfd_fast_detect_set",
            "bfd_nbr_minimum_interval",
            "bfd_nbr_multiplier",
            "bmp_activate",
            "dmz_link_bandwidth",
            "dmz_link_bandwidth_inheritance_disable",
            "neighbor_description",
            "neighbor_cluster_id",
            "dscp",
            "ebgp_multihop_value",
            "ebgp_multihop_mpls",
            "ebgp_recv_extcommunity_dmz",
            "ebgp_recv_extcommunity_dmz_set",
            "ebgp_send_extcommunity_dmz",
            "ebgp_send_extcommunity_dmz_set",
            "ebgp_send_extcommunity_dmz_cumulatie",
            "egress_engineering",
            "egress_engineering_set",
            "idle_watch_time",
            "internal_vpn_client",
            "ignore_connected_check",
            "ignore_connected_check_set",
            "neighbor_enforce_first_as_disable",
            "neighbor_graceful_restart_restart_time",
            "neighbor_graceful_restart_stalepath_time",
            "keychain",
            "keychain_name",
            "local_as_inheritance_disable",
            "local_as",
            "local",
            "local_address",
            "origin_as",
            "password_inheritance_disable",
            "password_encrypted",
            "peer_set",
            "precedence",
            "remote_as",
            "remote_as_list",
            "receive_buffer_size",
            "send_buffer_size",
            "session_open_mode",
            "neighbor_shutdown",
            "neighbor_shutdown_inheritance_disable",
            "neighbor_tcp_mss",
            "neighbor_tcp_mss_inheritance_disable",
            "neighbor_timers_keepalive",
            "update_source",
            "neighbor_ttl_security_inheritance_disable",
            "neighbor_ttl_security",
            "neighbor_graceful_maintenance_set",
            "neighbor_graceful_maintenance_activate",
            "neighbor_graceful_maintenance_activate_inheritance_disable",
            "neighbor_graceful_maintenance_as_prepends",
            "neighbor_graceful_maintenance_local_preference_disable",
            "neighbor_graceful_maintenance_local_preference",
            "neighbor_graceful_maintenance_as_prepends_value",
            "neighbor_capability_additional_paths_send",
            "neighbor_capability_additional_paths_send_disable",
            "neighbor_capability_additional_paths_rcv_disable",
            "neighbor_capability_additional_paths_rcv",
            "neighbor_capability_suppress_four_byte_AS",
            "neighbor_capability_suppress_all",
            "neighbor_capability_suppress_all_inheritance_disable",
            "neighbor_log_message_in_value",
            "neighbor_log_message_in_disable",
            "neighbor_log_message_in_inheritance_disable",
            "neighbor_log_message_out_value",
            "neighbor_log_message_out_disable",
            "neighbor_log_message_out_inheritance_disable",
            "neighbor_update_in_filtering_attribute_filter_group",
            "neighbor_update_in_filtering_logging_disable",
            "neighbor_update_in_filtering_message_buffers",
        ]

        want_nbr = want.get("neighbor", {})
        have_nbr = have.get("neighbor", {})
        for name, entry in want_nbr.items():
            have = have_nbr.pop(name, {})
            begin = len(self.commands)
            self.compare(parsers=neighbor_parsers, want=entry, have=have)
            if self.state in ["replaced", "overridden"]:
                self.sort_commands(begin)
            self._compare_af(want=entry, have=have)
            name = entry.get("name", "")
            if len(self.commands) != begin:
                self.commands.insert(
                    begin,
                    self._tmplt.render(
                        {"name": name},
                        "neighbor_group",
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
        for name, entry in wafs.items():
            begin = len(self.commands)
            af_have = hafs.pop(name, {})
            self.compare(parsers=self.parsers, want=entry, have=af_have)
            if self.state in ["replaced", "overridden"]:
                self.sort_commands(begin)
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

    def _bgp_list_to_dict(self, data):
        if "neighbor" in data:
            for nbr in data["neighbor"]:
                if "address_family" in nbr:
                    nbr["address_family"] = {
                        (x["afi"], x.get("safi")): x for x in nbr["address_family"]
                    }
            data["neighbor"] = {x["name"]: x for x in data["neighbor"]}
        return data
