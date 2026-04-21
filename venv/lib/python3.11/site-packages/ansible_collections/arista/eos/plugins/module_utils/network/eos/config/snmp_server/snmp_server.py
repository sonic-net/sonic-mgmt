#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The eos_snmp_server config file.
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to its desired end-state is
created.
"""

import re

from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.resource_module import (
    ResourceModule,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    dict_merge,
    get_from_dict,
)

from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.facts import Facts
from ansible_collections.arista.eos.plugins.module_utils.network.eos.rm_templates.snmp_server import (
    Snmp_serverTemplate,
)


class Snmp_server(ResourceModule):
    """
    The eos_snmp_server config class
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
            "contact",
            "traps.bgp",
            "traps.bridge",
            "traps.capacity",
            "traps.entity",
            "traps.external_alarm",
            "traps.isis",
            "traps.lldp",
            "traps.mpls_ldp",
            "traps.msdp",
            "traps.ospf",
            "traps.ospfv3",
            "traps.pim",
            "traps.snmp",
            "traps.snmpConfigManEvent",
            "traps.switchover",
            "traps.test",
            "traps.vrrp",
            "engineid",
            "extension",
            "local_interface",
            "location",
            "notification",
            "objects.mac",
            "objects.route",
            "qos",
            "qosmib",
            "transmit",
            "transport",
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

        wantd = {"snmp_server": self.want}
        haved = {"snmp_server": self.have}

        # turn all lists of dicts into dicts prior to merge
        for entry in wantd["snmp_server"], haved["snmp_server"]:
            self._snmp_server_list_to_dict(entry)

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "deleted":
            haved = {k: v for k, v in iteritems(haved) if k in wantd or not wantd}
            wantd = {}

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "deleted":
            wantd = {}
            for k, have in iteritems(haved):
                self._compare(want={}, have=have)

        for k, want in iteritems(wantd):
            self._compare(want=want, have=haved.pop(k, {}))

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Snmp_server network resource.
        """
        self._compare_hosts(want, have)
        self._compare_lists(want, have)
        for name, entry in iteritems(want):
            self.compare(
                parsers=self.parsers,
                want={name: entry},
                have={name: have.pop(name, {})},
            )
        for name, entry in iteritems(have):
            self.compare(parsers=self.parsers, want={}, have={name: entry})

        self._modify_traps_negate()

    def _modify_traps_negate(self):
        command_set = []
        for cmd in self.commands:
            if re.search("no snmp-server enable traps", cmd):
                command_set.append(cmd.replace("no ", "default "))
            else:
                command_set.append(cmd)
        self.commands = command_set

    def _compare_lists(self, want, have):
        parsers = [
            "communities_ipv6_acl",
            "communities_ipv4_acl",
            "groups",
            "acls",
            "views",
            "users.auth",
            "users.localized",
            "vrfs",
        ]
        for attrib in [
            "communities",
            "groups",
            "acls",
            "users",
            "views",
            "vrfs",
        ]:
            wdict = get_from_dict(want, attrib) or {}
            hdict = get_from_dict(have, attrib) or {}
            for key, entry in iteritems(wdict):
                # self.addcmd(entry, attrib, False)
                self.compare(
                    parsers=parsers,
                    want={attrib: entry},
                    have={attrib: hdict.pop(key, {})},
                )
            # remove remaining items in have for replaced
            for entry in hdict.values():
                self.compare(parsers=parsers, want={}, have={attrib: entry})

    def _compare_hosts(self, want, have):
        wdict = get_from_dict(want, "hosts") or {}
        hdict = get_from_dict(have, "hosts") or {}
        for key, entry in iteritems(wdict):
            # self.addcmd(entry, attrib, False)
            self.compare(
                parsers="hosts",
                want={"hosts": {key: entry}},
                have={"hosts": {key: hdict.pop(key, {})}},
            )
        # remove remaining items in have for replaced
        for key, entry in iteritems(hdict):
            self.compare(
                parsers="hosts",
                want={},
                have={"hosts": {key: entry}},
            )

    def _snmp_server_list_to_dict(self, entry):
        param_dict = {
            "communities": "name",
            "groups": "group",
            "acls": "afi",
            "users": "user",
            "views": "view",
            "vrfs": "vrf",
        }
        for k, v in iteritems(param_dict):
            if k in entry:
                a_dict = {}
                for el in entry[k]:
                    a_dict.update({el[v]: el})
                entry[k] = a_dict
        if "hosts" in entry:
            host_dict = {}
            for el in entry["hosts"]:
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
                            el.get("user"),
                            el.get("version"),
                            inf,
                            tr,
                            el.get("udp_port"),
                        ): el,
                    },
                )
            entry["hosts"] = host_dict
