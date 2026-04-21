#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The iosxr_snmp_server config file.
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
    dict_diff,
    dict_merge,
)

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.facts.facts import Facts
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.rm_templates.snmp_server import (
    Snmp_serverTemplate,
)


class Snmp_server(ResourceModule):
    """
    The iosxr_snmp_server config class
    """

    def __init__(self, module):
        super(Snmp_server, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="snmp_server",
            tmplt=Snmp_serverTemplate(),
        )
        self.parsers = [
            "chassis_id",
            "correlator.buffer_size",
            "contact",
            "ifindex",
            "ipv4.dscp",
            "ipv6.dscp",
            "ipv4.precedence",
            "ipv6.precedence",
            "location",
            "logging_threshold_oid_processing",
            "logging_threshold_pdu_processing",
            "mib_bulkstat_max_procmem_size",
            "mroutemib_send_all_vrf",
            "oid_poll_stats",
            "overload_control",
            "packetsize",
            "queue_length",
            "throttle_time",
            "trap_source",
            "trap_timeout",
            "drop.report_IPv4",
            "drop.report_IPv6",
            "drop.unknown_user",
            "ifmib.internal_cache_max_duration",
            "ifmib.ipsubscriber",
            "ifmib.stats",
            "ifmib.ifalias_long",
            "inform.timeout",
            "inform.retries",
            "inform.pending",
            "notification_log_mib.size",
            "notification_log_mib.default",
            "notification_log_mib.disable",
            "notification_log_mib.GlobalSize",
            "trap.link_ietf",
            "trap.authentication_vrf_disable",
            "trap.throttle_time",
            "timeouts.threshold",
            "timeouts.pdu_stats",
            "timeouts.subagent",
            "timeouts.inQdrop",
            "timeouts.duplicate",
            "traps.addrpool.low",
            "traps.addrpool.high",
            "traps.bfd",
            "traps.bgp.cbgp2",
            "traps.bgp.updown",
            "traps.bulkstat_collection",
            "traps.bulkstat_transfer",
            "traps.bridgemib",
            "traps.copy_complete",
            "traps.cisco_entity_ext",
            "traps.config",
            "traps.diameter.peerdown",
            "traps.diameter.peerup",
            "traps.diameter.protocolerror",
            "traps.diameter.permanentfail",
            "traps.diameter.transientfail",
            "traps.entity",
            "traps.entity_redundancy.all",
            "traps.entity_redundancy.status",
            "traps.entity_redundancy.switchover",
            "traps.entity_state.operstatus",
            "traps.entity_state.switchover",
            "traps.flash.removal",
            "traps.flash.insertion",
            "traps.fru_ctrl",
            "traps.hsrp",
            "traps.ipsla",
            "traps.ipsec.start",
            "traps.ipsec.stop",
            "traps.isakmp.start",
            "traps.isakmp.stop",
            "traps.isis",
            "traps.l2tun.pseudowire_status",
            "traps.l2tun.sessions",
            "traps.l2tun.tunnel_up",
            "traps.l2tun.tunnel_down",
            "traps.l2vpn.all",
            "traps.l2vpn.cisco",
            "traps.l2vpn.vc_up",
            "traps.l2vpn.vc_down",
            "traps.msdp_peer_state_change",
            "traps.ospf.retransmit.virt_packets",
            "traps.ospf.retransmit.packets",
            "traps.ospf.lsa.lsa_originate",
            "traps.ospf.lsa.lsa_maxage",
            "traps.ospf.errors.bad_packet",
            "traps.ospf.errors.authentication_failure",
            "traps.ospf.errors.config_error",
            "traps.ospf.errors.virt_bad_packet",
            "traps.ospf.errors.virt_authentication_failure",
            "traps.ospf.errors.virt_config_error",
            "traps.ospf.state_change.if_state_change",
            "traps.ospf.state_change.neighbor_state_change",
            "traps.ospf.state_change.virtif_state_change",
            "traps.ospf.state_change.virtneighbor_state_change",
            "traps.ospfv3.errors.bad_packet",
            "traps.ospfv3.errors.authentication_failure",
            "traps.ospfv3.errors.config_error",
            "traps.ospfv3.errors.virt_config_error",
            "traps.ospfv3.errors.virt_bad_packet",
            "traps.ospfv3.state_change.neighbor_state_change",
            "traps.ospfv3.state_change.virtif_state_change",
            "traps.ospfv3.state_change.virtneighbor_state_change",
            "traps.ospfv3.state_change.restart_status_change",
            "traps.ospfv3.state_change.restart_helper_status_change",
            "traps.ospfv3.state_change.restart_virtual_helper_status_change",
            "traps.ospfv3.state_change.nssa_state_change",
            "traps.power",
            "traps.rf",
            "traps.pim.neighbor_change",
            "traps.pim.invalid_message_received",
            "traps.pim.rp_mapping_change",
            "traps.pim.interface_state_change",
            "traps.rsvp.lost_flow",
            "traps.rsvp.new_flow",
            "traps.rsvp.all",
            "traps.selective_vrf_download_role_change",
            "traps.sensor",
            "traps.vrrp_events",
            "traps.syslog",
            "traps.system",
            "traps.subscriber.session_agg_access_interface",
            "traps.subscriber.session_agg_node",
            "traps.vpls.all",
            "traps.vpls.full_clear",
            "traps.vpls.full_raise",
            "traps.vpls.status",
            "traps.snmp.linkup",
            "traps.snmp.linkdown",
            "traps.snmp.coldstart",
            "traps.snmp.warmstart",
            "traps.snmp.authentication",
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

    def handle_alieses(self, want):
        for x in [want.get("groups", []), want.get("users", [])]:
            for y in x:
                if y.get("Ipv4_acl"):
                    del y["Ipv4_acl"]
                if y.get("Ipv6_acl"):
                    del y["Ipv6_acl"]
        return want

    def generate_commands(self):
        """Generate configuration commands to send based on
        want, have and desired state.
        """

        self.want = self.handle_alieses(self.want)
        wantd = self.list_to_dict(self.want)
        haved = self.list_to_dict(self.have)

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "deleted":
            wantd = {}

        self._compare(want=wantd, have=haved)

        # --- ensure explicit 'no' commands for interfaces & vrfs when deleting ---
        # When state is deleted, the comparison may already produce many 'no ...' commands,
        # but ensure we always include explicit removals for interfaces and vrfs that
        # existed in `have` but weren't generated by compare.
        if self.state == "deleted":
            # ensure interfaces get explicit 'no snmp-server interface <name>'
            interfaces = haved.get("interfaces", {}) or {}
            for if_name in interfaces.keys():
                no_cmd = f"no snmp-server interface {if_name}"
                if no_cmd not in self.commands:
                    self.commands.append(no_cmd)

            # ensure vrfs get explicit 'no snmp-server vrf <name>'
            vrfs = haved.get("vrfs", {}) or {}
            for vrf_name in vrfs.keys():
                no_cmd = f"no snmp-server vrf {vrf_name}"
                if no_cmd not in self.commands:
                    self.commands.append(no_cmd)

        if self.state in ["overridden", "replaced"]:
            self.commands = [each for each in self.commands if "no" in each] + [
                each for each in self.commands if "no" not in each
            ]

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Logging_global network resource.
        """
        self.compare(parsers=self.parsers, want=want, have=have)
        self._compare_lists(want, have)
        self._compare_vrfs(want, have)

    def _remove_snmp_server(self, begin):
        for i in range(begin, len(self.commands)):
            self.commands[i] = self.commands[i].replace("snmp-server ", "")

    def _compare_vrfs(self, want, have):
        wvrfs = want.get("vrfs", {})
        hvrfs = have.get("vrfs", {})
        for name, entry in wvrfs.items():
            begin = len(self.commands)
            vrf_have = hvrfs.pop(name, {})
            self._compare_lists(want=entry, have=vrf_have)
            if len(self.commands) != begin:
                self._remove_snmp_server(begin)
                self.commands.insert(
                    begin,
                    self._tmplt.render(
                        {"vrf": entry.get("vrf")},
                        "vrfs",
                        False,
                    ),
                )
        for name, entry in hvrfs.items():
            self.addcmd(entry, "vrfs", True)

    def _compare_lists(self, want, have):
        """
        Handles list attributes from config_data
        """
        for x in [
            "communities",
            "community_maps",
            "correlator.rule_sets",
            "correlator.rules",
            "context",
            "groups",
            "hosts",
            "interfaces",
            "mib_object_lists",
            "mib_schema",
            "mib_bulkstat_transfer_ids",
            "users",
            "targets",
        ]:
            wantx = want.get(x, {})
            havex = have.get(x, {})
            if "." in x:
                complex_parser = x.split(".")
                wantx = want.get(complex_parser[0], {}).get(
                    complex_parser[1],
                    {},
                )
                havex = have.get(complex_parser[0], {}).get(
                    complex_parser[1],
                    {},
                )

            if x in [
                "interfaces",
                "correlator.rules",
                "mib_schema",
                "mib_bulkstat_transfer_ids",
            ]:
                # handling complex parsers for replaced and overridden state

                for key, wentry in wantx.items():
                    hentry = havex.pop(key, {})
                    updates = dict_diff(hentry, wentry)
                    if updates and x in [
                        "interfaces",
                        "mib_schema",
                        "mib_bulkstat_transfer_ids",
                    ]:
                        updates.update(name=wentry["name"])
                        self.addcmd(updates, x)
                    elif updates and x == "correlator.rules":
                        updates.update(rule_name=wentry["rule_name"])
                        self.addcmd(updates, x)
            else:
                for key, wentry in wantx.items():
                    hentry = havex.pop(key, {})
                    if wentry != hentry:
                        self.addcmd(wentry, x)

                for key, hentry in havex.items():
                    self.addcmd(hentry, x, negate=True)

    def _host_list_to_dict(self, data):
        host_dict = {}
        host_data = deepcopy(data)
        for el in host_data["hosts"]:
            tr = ""
            inf = ""
            if el.get("traps"):
                tr = "traps"
            if el.get("informs"):
                inf = "informs"
            host_dict.update(
                {
                    (
                        el.get("host"),
                        el.get("community"),
                        el.get("version"),
                        inf,
                        tr,
                        el.get("udp_port"),
                    ): el,
                },
            )
        return host_dict

    def list_to_dict(self, config):
        data = deepcopy(config)

        if data.get("vrfs"):
            for x in data["vrfs"]:
                if "context" in x:
                    x["context"] = {y: {"name": y} for y in x["context"]}
                if "hosts" in x:
                    x["hosts"] = self._host_list_to_dict(x)

        pkey = {
            "communities": "name",
            "community_maps": "name",
            "interfaces": "name",
            "mib_schema": "name",
            "groups": "group",
            "mib_bulkstat_transfer_ids": "name",
            "users": "user",
            "vrfs": "vrf",
        }
        for k in pkey.keys():
            if k in data:
                data[k] = {i[pkey[k]]: i for i in data[k]}

        if "correlator" in data:
            if "rules" in data["correlator"]:
                data["correlator"]["rules"] = {
                    x["rule_name"]: x for x in data["correlator"]["rules"]
                }
            if "rule_sets" in data["correlator"]:
                data["correlator"]["rule_sets"] = {
                    x["name"]: x for x in data["correlator"]["rule_sets"]
                }

        if "context" in data:
            data["context"] = {x: {"name": x} for x in data["context"]}
        if "mib_object_lists" in data:
            data["mib_object_lists"] = {x: {"mib_object": x} for x in data["mib_object_lists"]}
        if "targets" in data:
            data["targets"] = {
                x["name"] + x.get("vrf", "") + x.get("host", ""): x for x in data["targets"]
            }
        if "hosts" in data:
            data["hosts"] = self._host_list_to_dict(data)
        return data
