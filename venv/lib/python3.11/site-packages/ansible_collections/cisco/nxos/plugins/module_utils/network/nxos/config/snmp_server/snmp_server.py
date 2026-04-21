#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos_snmp_server config file.
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
    get_from_dict,
)

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.facts import Facts
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.snmp_server import (
    Snmp_serverTemplate,
)


class Snmp_server(ResourceModule):
    """
    The nxos_snmp_server config class
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
            "aaa_user.cache_timeout",
            "contact",
            "context",
            "counter.enable",
            "counter.cache.timeout",
            "drop.unknown_engine_id",
            "drop.unknown_user",
            "traps.aaa",
            "traps.bgp",
            "traps.bridge.newroot",
            "traps.bridge.topologychange",
            "traps.callhome.event_notify",
            "traps.callhome.smtp_send_fail",
            "traps.cfs.merge_failure",
            "traps.cfs.state_change_notif",
            "traps.config.ccmCLIRunningConfigChanged",
            "traps.entity.cefcMIBEnableStatusNotification",
            "traps.entity.entity_fan_status_change",
            "traps.entity.entity_mib_change",
            "traps.entity.entity_module_inserted",
            "traps.entity.entity_module_status_change",
            "traps.entity.entity_power_out_change",
            "traps.entity.entity_power_status_change",
            "traps.entity.entity_sensor",
            "traps.entity.entity_unrecognised_module",
            "traps.feature_control.featureOpStatusChange",
            "traps.feature_control.ciscoFeatOpStatusChange",
            "traps.generic.coldStart",
            "traps.generic.warmStart",
            "traps.license.notify_license_expiry",
            "traps.license.notify_license_expiry_warning",
            "traps.license.notify_licensefile_missing",
            "traps.license.notify_no_license_for_feature",
            "traps.link.cErrDisableInterfaceEventRev1",
            "traps.link.cieLinkDown",
            "traps.link.cieLinkUp",
            "traps.link.cisco_xcvr_mon_status_chg",
            "traps.link.cmn_mac_move_notification",
            "traps.link.delayed_link_state_change",
            "traps.link.extended_linkDown",
            "traps.link.extended_linkUp",
            "traps.link.linkDown",
            "traps.link.linkUp",
            "traps.mmode.cseMaintModeChangeNotify",
            "traps.mmode.cseNormalModeChangeNotify",
            "traps.ospf",
            "traps.ospfv3",
            "traps.rf.redundancy_framework",
            "traps.rmon.fallingAlarm",
            "traps.rmon.hcFallingAlarm",
            "traps.rmon.hcRisingAlarm",
            "traps.rmon.risingAlarm",
            "traps.snmp.authentication",
            "traps.storm_control.cpscEventRev1",
            "traps.storm_control.trap_rate",
            "traps.stpx.inconsistency",
            "traps.stpx.root_inconsistency",
            "traps.stpx.loop_inconsistency",
            "traps.syslog.message_generated",
            "traps.sysmgr.cseFailSwCoreNotifyExtended",
            "traps.system.clock_change_notification",
            "traps.upgrade.upgradeJobStatusNotify",
            "traps.upgrade.upgradeOpNotifyOnCompletion",
            "traps.vtp.notifs",
            "traps.vtp.vlancreate",
            "traps.vtp.vlandelete",
            "engine_id.local",
            "global_enforce_priv",
            "location",
            "mib.community_map",
            "packetsize",
            "protocol.enable",
            "source_interface.informs",
            "source_interface.traps",
            "system_shutdown",
            "tcp_session",
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
        wantd = self._list_to_dict(self.want)
        haved = self._list_to_dict(self.have)

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        # this ensures that if user sets `enable: True` for a trap
        # all suboptions for that trap are set to True
        for x in [
            "traps.aaa",
            "traps.bridge",
            "traps.callhome",
            "traps.cfs",
            "traps.config",
            "traps.entity",
            "traps.feature_control",
            "traps.generic",
            "traps.license",
            "traps.link",
            "traps.mmode",
            "traps.rf",
            "traps.rmon",
            "traps.snmp",
            "traps.storm_control",
            "traps.stpx",
            "traps.syslog",
            "traps.sysmgr",
            "traps.system",
            "traps.upgrade",
            "traps.vtp",
        ]:
            entry = get_from_dict(wantd, x)
            if entry and entry.get("enable", False):
                key = x.split(".")
                wantd[key[0]][key[1]].pop("enable")
                for i in self.parsers:
                    if i.startswith(x):
                        key = i.split(".")
                        wantd[key[0]][key[1]][key[2]] = True

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "deleted":
            wantd = {}

        self._compare(want=wantd, have=haved)

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Snmp_server network resource.
        """
        self.compare(parsers=self.parsers, want=want, have=have)
        self._compare_lists(want=want, have=have)

    def _compare_lists(self, want, have):
        """
        Compare list of dictionaries
        """
        for x in ["users.auth", "users.use_acls", "hosts", "communities"]:
            wantx = get_from_dict(want, x) or {}
            havex = get_from_dict(have, x) or {}
            for wkey, wentry in wantx.items():
                hentry = havex.pop(wkey, {})
                if wentry != hentry:
                    self.addcmd(wentry, x)
            # remove superfluous items
            for _k, hv in havex.items():
                self.addcmd(hv, x, negate=True)

    def _list_to_dict(self, data):
        def _build_key(x):
            key = set()
            for k, v in x.items():
                if isinstance(v, dict):
                    for sk, sv in v.items():
                        if isinstance(sv, dict):
                            for ssk, ssv in sv.items():
                                key.add(sk + "_" + ssk + "_" + str(ssv))
                        else:
                            key.add(sk + "_" + str(sv))
                else:
                    key.add(k + "_" + str(v))
            return tuple(sorted(key))

        tmp = deepcopy(data)
        if "communities" in tmp:
            tmp["communities"] = {_build_key(entry): entry for entry in tmp["communities"]}
        if "users" in tmp:
            if "auth" in tmp["users"]:
                tmp["users"]["auth"] = {_build_key(entry): entry for entry in tmp["users"]["auth"]}
            if "use_acls" in tmp["users"]:
                tmp["users"]["use_acls"] = {
                    entry["user"]: entry for entry in tmp["users"]["use_acls"]
                }
        if "hosts" in tmp:
            tmp["hosts"] = {_build_key(entry): entry for entry in tmp["hosts"]}
        return tmp
