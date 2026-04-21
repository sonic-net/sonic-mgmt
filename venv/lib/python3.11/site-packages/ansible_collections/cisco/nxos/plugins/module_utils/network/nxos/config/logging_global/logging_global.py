#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos_logging_global config file.
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
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.logging_global import (
    Logging_globalTemplate,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.utils.utils import (
    get_logging_sevmap,
)


class Logging_global(ResourceModule):
    """
    The nxos_logging_global config class
    """

    def __init__(self, module):
        super(Logging_global, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="logging_global",
            tmplt=Logging_globalTemplate(),
        )
        self._sev_map = get_logging_sevmap(invert=True)
        self._state_set = ("replaced", "deleted", "overridden")
        self.parsers = [
            "console",
            "module",
            "monitor",
            "logfile",
            "event.link_status.enable",
            "event.link_status.default",
            "event.trunk_status.enable",
            "event.trunk_status.default",
            "history.severity",
            "history.size",
            "ip.access_list.cache.entries",
            "ip.access_list.cache.interval",
            "ip.access_list.cache.threshold",
            "ip.access_list.detailed",
            "ip.access_list.include.sgt",
            "origin_id.hostname",
            "origin_id.ip",
            "origin_id.string",
            "rate_limit",
            "rfc_strict",
            "source_interface",
            "timestamp",
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
        wantd = self._logging_list_to_dict(self.want)
        haved = self._logging_list_to_dict(self.have)

        if self.state == "deleted":
            # empty out want (in case something was specified)
            # some items are populated later on for correct removal
            wantd = {}

        # pre-process `event.x.y` keys
        for x in self.parsers[4:7]:
            have_k = get_from_dict(haved, x)
            want_k = get_from_dict(wantd, x)
            if have_k is None and want_k is not None:
                # set have to True to mimic default state
                # this allows negate commands to be issued
                self.__update_dict(haved, x)
            if all(
                (
                    self.state in self._state_set,
                    have_k is False,
                    want_k is None,
                ),
            ):
                # if want is missing and have is negated
                # set want to True in order to revert to default state
                self.__update_dict(wantd, x)

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            for x in self.parsers[0:4]:
                hstate = haved.get(x, {}).get("state", "")
                wstate = wantd.get(x, {}).get("state", "")
                if hstate == "disabled" and not wstate:
                    # this ensures that updates are done
                    # with correct `state`
                    if wantd.get(x, {}):
                        wantd[x].update({"state": "enabled"})
            wantd = dict_merge(haved, wantd)

        if self.state in self._state_set:
            # set default states for keys that appear in negated form
            for x in self.parsers[0:3]:
                if x in haved and x not in wantd:
                    wantd[x] = {"state": "enabled"}
            if "rate_limit" in haved and "rate_limit" not in wantd:
                wantd["rate_limit"] = "enabled"
            if "logfile" in haved and "logfile" not in wantd:
                wantd["logfile"] = {"name": "messages", "severity": 5}

        self._compare(want=wantd, have=haved)

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Logging_global network resource.
        """
        self.compare(parsers=self.parsers, want=want, have=have)
        self._compare_lists(want, have)

    def _compare_lists(self, want, have):
        """Compare list of dictionaries"""
        for x in ["facilities", "hosts"]:
            wantx = want.get(x, {})
            havex = have.get(x, {})
            for key, wentry in wantx.items():
                hentry = havex.pop(key, {})
                if wentry != hentry:
                    if x == "hosts" and self.state in self._state_set:
                        # remove have config for hosts
                        # else want gets appended
                        self.addcmd(hentry, x, negate=True)
                    self.addcmd(wentry, x)
            for key, hentry in havex.items():
                self.addcmd(hentry, x, negate=True)

    def _logging_list_to_dict(self, data):
        """Convert all list to dicts to dicts
        of dicts and substitute severity values
        """
        tmp = deepcopy(data)
        pkey = {"hosts": "host", "facilities": "facility"}
        for k in ("hosts", "facilities"):
            if k in tmp:
                for x in tmp[k]:
                    if "severity" in x:
                        x["severity"] = self._sev_map[x["severity"]]
                tmp[k] = {i[pkey[k]]: i for i in tmp[k]}
        for k in ("console", "history", "logfile", "module", "monitor"):
            if "severity" in tmp.get(k, {}):
                tmp[k]["severity"] = self._sev_map[tmp[k]["severity"]]
        return tmp

    def __update_dict(self, datadict, key, nval=True):
        """Utility method that updates last subkey of
        `datadict` as identified by `key` to `nval`.
        """
        keys = key.split(".")
        if keys[0] not in datadict:
            datadict[keys[0]] = {}
        if keys[1] not in datadict[keys[0]]:
            datadict[keys[0]][keys[1]] = {}
        datadict[keys[0]][keys[1]].update({keys[2]: nval})
