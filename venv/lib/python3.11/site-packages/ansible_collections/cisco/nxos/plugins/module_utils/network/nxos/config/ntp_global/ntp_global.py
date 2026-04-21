#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos_ntp_global config file.
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

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.facts import Facts
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.ntp_global import (
    Ntp_globalTemplate,
)


class Ntp_global(ResourceModule):
    """
    The nxos_ntp_global config class
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
            "access_group.match_all",
            "allow.control.rate_limit",
            "allow.private",
            "authenticate",
            "logging",
            "master.stratum",
            "passive",
            "source",
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

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Ntp_global network resource.
        """
        self.compare(parsers=self.parsers, want=want, have=have)
        self._compare_lists(want=want, have=have)
        self._compare_access_group(want=want, have=have)

    def _compare_lists(self, want, have):
        keys = ["authentication_keys", "peers", "servers", "trusted_keys"]
        for x in keys:
            wantx = want.get(x, {})
            havex = have.get(x, {})

            for wkey, wentry in wantx.items():
                hentry = havex.pop(wkey, {})

                # pop aliased keys to preserve idempotence
                if x in ["peers", "servers"]:
                    wentry.pop("use_vrf", None)

                if wentry != hentry:
                    if x in keys[1:3] and self.state in [
                        "overridden",
                        "replaced",
                    ]:
                        # remove existing config else it gets appeneded
                        self.addcmd(hentry, x, negate=True)
                    self.addcmd(wentry, x)

            # remove superfluos config
            for _hkey, hentry in havex.items():
                self.addcmd(hentry, x, negate=True)

    def _compare_access_group(self, want, have):
        want_ag = want.get("access_group", {})
        have_ag = have.get("access_group", {})

        for x in ["peer", "query_only", "serve", "serve_only"]:
            wx = want_ag.get(x, {})
            hx = have_ag.get(x, {})

            for wkey, wentry in wx.items():
                hentry = hx.pop(wkey, {})
                if wentry != hentry:
                    self.addcmd(wentry, x)

            # remove superfluos config
            for hentry in hx.values():
                self.addcmd(hentry, x, negate=True)

    def _ntp_list_to_dict(self, data):
        """Convert all list to dicts to dicts
        of dicts
        """
        tmp = deepcopy(data)
        if "access_group" in tmp:
            for x in ["peer", "query_only", "serve", "serve_only"]:
                if x in tmp["access_group"]:
                    tmp["access_group"][x] = {i["access_list"]: i for i in tmp["access_group"][x]}
        pkey = {
            "authentication_keys": "id",
            "peers": "peer",
            "servers": "server",
            "trusted_keys": "key_id",
        }
        for k in pkey.keys():
            if k in tmp:
                tmp[k] = {i[pkey[k]]: i for i in tmp[k]}
        return tmp
