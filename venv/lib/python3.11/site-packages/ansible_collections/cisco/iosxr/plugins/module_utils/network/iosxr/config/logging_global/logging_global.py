#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The iosxr_logging_global config file.
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
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.rm_templates.logging_global import (
    Logging_globalTemplate,
)


class Logging_global(ResourceModule):
    """
    The iosxr_logging_global config class
    """

    def __init__(self, module):
        super(Logging_global, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="logging_global",
            tmplt=Logging_globalTemplate(),
        )
        self.parsers = [
            "archive.device",
            "archive.frequency",
            "archive.severity",
            "archive.archive_size",
            "archive.archive_length",
            "archive.file_size",
            "buffered.size",
            "buffered.severity",
            "buffered.discriminator",
            "console.severity",
            "correlator.buffer_size",
            "events.threshold",
            "events.buffer_size",
            "events.display_location",
            "events.severity",
            "facility",
            "hostnameprefix",
            "format",
            "ipv4.dscp",
            "ipv6.dscp",
            "ipv4.precedence",
            "ipv6.precedence",
            "localfilesize",
            "suppress.duplicates",
            "suppress.apply_rule",
            "monitor.severity",
            "monitor.discriminator",
            "history.size",
            "history.severity",
            "trap.severity",
            "trap.state",
            "monitor.state",
            "history.state",
            "console.state",
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
        wantd = self.list_to_dict(self.want)
        haved = self.list_to_dict(self.have)

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        # if state is deleted, empty out wantd and set haved to wantd
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
        for the Logging_global network resource.
        """
        self.compare(parsers=self.parsers, want=want, have=have)
        self._compare_lists(want, have)

    def _compare_lists(self, want, have):
        """
        Handles list attributes from config_data
        """
        for x in [
            "hosts",
            "files",
            "source_interfaces",
            "tls_servers",
            "correlator.rule_sets",
            "correlator.rules",
            "events.filter_match",
            "buffered.discriminator",
            "monitor.discriminator",
            "console.discriminator",
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

            if x in ["tls_servers", "correlator.rules"]:
                # handling complex parsers for replaced and overridden state

                for key, wentry in wantx.items():
                    hentry = havex.pop(key, {})
                    updates = dict_diff(hentry, wentry)
                    if updates and x == "tls_servers":
                        updates.update(name=wentry["name"])
                        self.addcmd(updates, x)
                    elif updates and x == "correlator.rules":
                        updates.update(rule_type=wentry["rule_type"])
                        updates.update(rule_name=wentry["rule_name"])
                        self.addcmd(updates, x)
            else:
                for key, wentry in wantx.items():
                    hentry = havex.pop(key, {})
                    if wentry != hentry:
                        self.addcmd(wentry, x)

            for key, hentry in havex.items():
                self.addcmd(hentry, x, negate=True)

    def list_to_dict(self, config):
        data = deepcopy(config)
        if "tls_servers" in data:
            data["tls_servers"] = {x["name"]: x for x in data["tls_servers"]}

        if "source_interfaces" in data:
            data["source_interfaces"] = {
                x["interface"] + "_" + x.get("vrf", ""): x for x in data["source_interfaces"]
            }

        if "files" in data:
            data["files"] = {x["name"]: x for x in data["files"]}

        if "hosts" in data:
            data["hosts"] = {x["host"]: x for x in data["hosts"]}
        if "events" in data:
            if "filter_match" in data["events"]:
                data["events"]["filter_match"] = {
                    x: {"match": x} for x in data["events"]["filter_match"]
                }

        if "correlator" in data:
            if "rules" in data["correlator"]:
                data["correlator"]["rules"] = {
                    x["rule_name"]: x for x in data["correlator"]["rules"]
                }
            if "rule_sets" in data["correlator"]:
                rule_sets = deepcopy(data["correlator"]["rule_sets"])
                data["correlator"]["rule_sets"] = dict()
                for x in rule_sets:
                    if len(x.get("rulename", [])) > 0:
                        for y in x.get("rulename"):
                            new_data = {"rulename": y, "name": x["name"]}
                            data["correlator"]["rule_sets"].update(
                                {x["name"] + "_" + y: new_data},
                            )

                    else:
                        data["correlator"]["rule_sets"].update({x["name"]: x})

        for x in ["buffered", "monitor", "console"]:
            if x in data:
                if "discriminator" in data[x]:
                    data[x]["discriminator"] = {
                        x["match_params"] + "_" + x["name"]: x for x in data[x]["discriminator"]
                    }
        return data
