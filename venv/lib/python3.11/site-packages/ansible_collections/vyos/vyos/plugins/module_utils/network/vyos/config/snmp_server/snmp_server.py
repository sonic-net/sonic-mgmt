#
# -*- coding: utf-8 -*-
# Copyright 2022 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The vyos_snmp_server config file.
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

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.facts.facts import Facts
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.snmp_server import (
    Snmp_serverTemplate,
)


class Snmp_server(ResourceModule):
    """
    The vyos_snmp_server config class
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
            "contact",
            "description",
            "location",
            "smux_peer",
            "trap_source",
            "trap_target",
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
        wantd = self._snmp_server_list_to_dict(self.want)
        haved = self._snmp_server_list_to_dict(self.have)

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "deleted":
            if haved:
                self.commands.append("delete service snmp")

        if self.state != "deleted":
            self._compare(want=wantd, have=haved)

        if self.state not in ["merged", "deleted"]:
            self._move_negate_commands()

    def _move_negate_commands(self):
        command_set = []
        for cmd in self.commands:
            if re.search("delete service snmp", cmd):
                command_set.insert(0, cmd)
            else:
                command_set.append(cmd)
        self.commands = command_set

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Snmp_server network resource.
        """
        self._compare_lists(want, have)
        self._compare_snmp_v3(want, have)
        for key, value in iteritems(want):
            self.compare(
                parsers=self.parsers,
                want={key: value},
                have={key: have.pop(key, "")},
            )
        for key, entry in iteritems(have):
            if entry:
                self.compare(parsers=self.parsers, want={}, have={key: entry})

    def _compare_lists(self, want, have):
        parsers = [
            "communities",
            "listen_addresses",
        ]
        for attrib in parsers:
            wdict = get_from_dict(want, attrib) or {}
            hdict = get_from_dict(have, attrib) or {}
            for key, entry in iteritems(wdict):
                # self.addcmd(entry, attrib, False)
                if attrib == "communities":
                    for k, v in iteritems(entry):
                        if k in ["clients", "networks"]:
                            v.sort()
                        h = {}
                        if k != "name":
                            if hdict.get(key):
                                h = {
                                    "communities": {
                                        k: hdict[key].pop(k, ""),
                                        "name": key,
                                    },
                                }
                            self.compare(
                                parsers="communities",
                                want={"communities": {k: v, "name": key}},
                                have=h,
                            )
                else:
                    self.compare(
                        parsers="listen_addresses",
                        want={"listen_addresses": entry},
                        have={"listen_addresses": hdict.pop(key, {})},
                    )
                have.pop(attrib, {})
            # remove remaining items in have for replaced
            for key, entry in iteritems(hdict):
                if attrib == "communities":
                    for k, v in iteritems(entry):
                        if k != "name":
                            self.compare(
                                parsers="communities",
                                have={"communities": {k: v, "name": key}},
                                want={},
                            )
                else:
                    self.compare(parsers=parsers, want={}, have={attrib: entry})

    def _compare_snmp_v3(self, want, have):
        parsers = [
            "snmp_v3.groups",
            "snmp_v3.trap_targets.port",
            "snmp_v3.trap_targets.protocol",
            "snmp_v3.trap_targets.type",
            "snmp_v3.trap_targets.user",
            "snmp_v3.users.group",
            "snmp_v3.users.mode",
            "snmp_v3.views",
            "snmp_v3.engine_id",
        ]
        attribute_dict = {
            "groups": "group",
            "trap_targets": "address",
            "users": "user",
            "views": "view",
        }
        wdict = get_from_dict(want, "snmp_v3") or {}
        hdict = get_from_dict(have, "snmp_v3") or {}
        for attrib in attribute_dict.keys():
            wattrib = get_from_dict(wdict, attrib) or {}
            hattrib = get_from_dict(hdict, attrib) or {}
            for key, entry in iteritems(wattrib):
                self._compare_snmp_v3_auth_privacy(entry, hattrib.get(key, {}), attrib)
                for k, v in iteritems(entry):
                    if k != attribute_dict[attrib]:
                        h = {}
                        if hattrib.get(key):
                            h = {
                                "snmp_v3": {
                                    attrib: {
                                        k: hattrib[key].pop(k, ""),
                                        attribute_dict[attrib]: hattrib[key][
                                            attribute_dict[attrib]
                                        ],
                                    },
                                },
                            }
                        self.compare(
                            parsers=parsers,
                            want={
                                "snmp_v3": {
                                    attrib: {
                                        k: v,
                                        attribute_dict[attrib]: entry[attribute_dict[attrib]],
                                    },
                                },
                            },
                            have=h,
                        )
            # remove remaining items in have for replaced
            for key, entry in iteritems(hattrib):
                self._compare_snmp_v3_auth_privacy({}, entry, attrib)
                self.compare(parsers=parsers, want={}, have={"snmp_v3": {attrib: entry}})
            hdict.pop(attrib, {})
        for key, entry in iteritems(wdict):
            # self.addcmd(entry, attrib, False)
            self.compare(
                parsers="snmp_v3.engine_id",
                want={"snmp_v3": {key: entry}},
                have={"snmp_v3": {key: hdict.pop(key, {})}},
            )
        # remove remaining items in have for replaced
        for key, entry in iteritems(hdict):
            self.compare(parsers=parsers, want={}, have={"snmp_v3": {key: entry}})

    def _compare_snmp_v3_auth_privacy(self, wattrib, hattrib, attrib):
        parsers = [
            "snmp_v3.trap_targets.authentication",
            "snmp_v3.trap_targets.privacy",
            "snmp_v3.users.authentication",
            "snmp_v3.users.privacy",
        ]
        if attrib in ["trap_targets", "users"]:
            if attrib == "users":
                primary_key = "user"
            else:
                primary_key = "address"
            for key, entry in iteritems(wattrib):
                if key != primary_key and key in ["authentication", "privacy"]:
                    self.compare(
                        parsers=parsers,
                        want={
                            "snmp_v3": {
                                attrib: {
                                    key: entry,
                                    primary_key: wattrib[primary_key],
                                },
                            },
                        },
                        have={
                            "snmp_v3": {
                                attrib: {
                                    key: hattrib.pop(key, {}),
                                    primary_key: wattrib[primary_key],
                                },
                            },
                        },
                    )
            for key, entry in iteritems(hattrib):
                if key != primary_key and key in ["authentication", "privacy"]:
                    self.compare(
                        parsers=parsers,
                        want={},
                        have={
                            "snmp_v3": {
                                attrib: {
                                    key: entry,
                                    primary_key: hattrib[primary_key],
                                },
                            },
                        },
                    )

    def _snmp_server_list_to_dict(self, entry):
        param_dict = {
            "communities": "name",
            "listen_addresses": "address",
        }
        v3_param_dict = {
            "groups": "group",
            "users": "user",
            "views": "view",
            "trap_targets": "address",
        }
        for k, v in iteritems(param_dict):
            if k in entry:
                a_dict = {}
                for el in entry[k]:
                    a_dict.update({el[v]: el})
                entry[k] = a_dict
        for k, v in iteritems(v3_param_dict):
            if entry.get("snmp_v3") and k in entry.get("snmp_v3"):
                a_dict = {}
                for el in entry["snmp_v3"][k]:
                    a_dict.update({el[v]: el})
                entry["snmp_v3"][k] = a_dict
        return entry
