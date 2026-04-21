#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The iosxr_ntp_global config file.
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
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.rm_templates.ntp_global import (
    Ntp_globalTemplate,
)


class Ntp_global(ResourceModule):
    """
    The iosxr_ntp_global config class
    """

    def __init__(self, module):
        super(Ntp_global, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="ntp_global",
            tmplt=Ntp_globalTemplate(),
        )
        self.parsers = [
            "access_group.ipv4.peer",
            "access_group.ipv4.serve",
            "access_group.ipv4.serve_only",
            "access_group.ipv4.query_only",
            "access_group.ipv6.peer",
            "access_group.ipv6.serve",
            "access_group.ipv6.serve_only",
            "access_group.ipv6.query_only",
            "authenticate",
            "log_internal_sync",
            "broadcastdelay",
            "drift.aging_time",
            "drift.file",
            "ipv4.dscp",
            "ipv4.precedence",
            "ipv6.dscp",
            "ipv6.precedence",
            "max_associations",
            "master.stratum",
            "passive",
            "update_calendar",
            "source_interface",
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
        wantd = self._ntp_list_to_dict(self.want)
        haved = self._ntp_list_to_dict(self.have)

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        # if state is deleted, empty out wantd
        if self.state == "deleted":
            wantd = {}

        self._compare(want=wantd, have=haved)
        if self.state in ["overridden", "replaced"]:
            self.commands = [each for each in self.commands if "no" in each] + [
                each for each in self.commands if "no" not in each
            ]

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Ntp_global network resource.
        """
        self._compare_lists(want=want, have=have)
        self.compare(parsers=self.parsers, want=want, have=have)

    def _compare_lists(self, want, have):
        keys = [
            "authentication_keys",
            "peers",
            "servers",
            "trusted_keys",
            "interfaces",
            "source_vrfs",
            "access_group.vrfs",
        ]
        for x in keys:
            if "." in x:
                ag_vrf_list = x.split(".")
                wantx = want.get(ag_vrf_list[0], {}).get(ag_vrf_list[1], {})
                havex = have.get(ag_vrf_list[0], {}).get(ag_vrf_list[1], {})
                x = ag_vrf_list[1]
            else:
                wantx = want.get(x, {})
                havex = have.get(x, {})

            for wkey, wentry in wantx.items():
                hentry = havex.pop(wkey, {})
                if wentry != hentry:
                    if x == "interfaces":
                        updates = dict_diff(hentry, wentry)
                        updates.update(name=wentry.get("name"))
                        updates.update(vrf=wentry.get("vrf", ""))
                        self.addcmd(updates, x)
                    else:
                        self.addcmd(wentry, x)

            # remove superfluos config
            for _hkey, hentry in havex.items():
                if x == "interfaces":
                    if "vrf" in hentry:
                        self.commands.append(
                            "no ntp interface {0} vrf {1}".format(
                                _hkey.split("_")[0],
                                _hkey.split("_")[1],
                            ),
                        )
                    else:
                        self.commands.append(
                            "no ntp interface {0}".format(_hkey.split("_")[0]),
                        )
                else:
                    self.addcmd(hentry, x, negate=True)

    def _ntp_list_to_dict(self, data):
        """Convert all list to dicts to dicts
        of dicts
        """
        tmp = deepcopy(data)
        if "access_group" in tmp:
            if "vrfs" in tmp["access_group"]:
                tmp["access_group"]["vrfs"] = {i["name"]: i for i in tmp["access_group"]["vrfs"]}
        if "interfaces" in tmp:
            tmp["interfaces"] = {i["name"] + "_" + i.get("vrf", ""): i for i in tmp["interfaces"]}
        if "peers" in tmp:
            tmp["peers"] = {i["peer"] + "_" + i.get("vrf", ""): i for i in tmp["peers"]}
        if "servers" in tmp:
            tmp["servers"] = {i["server"] + "_" + i.get("vrf", ""): i for i in tmp["servers"]}

        pkey = {
            "authentication_keys": "id",
            "trusted_keys": "key_id",
            "source_vrfs": "vrf",
        }
        for k in pkey.keys():
            if k in tmp:
                tmp[k] = {i[pkey[k]]: i for i in tmp[k]}
        return tmp
