# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The iosxr_vrf_global config file.
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

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.facts.facts import Facts
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.rm_templates.vrf_global import (
    Vrf_globalTemplate,
)


class Vrf_global(ResourceModule):
    """
    The iosxr_vrf_global config class
    """

    def __init__(self, module):
        super(Vrf_global, self).__init__(
            empty_fact_val=[],
            facts_module=Facts(module),
            module=module,
            resource="vrf_global",
            tmplt=Vrf_globalTemplate(),
        )
        self.parsers = [
            "description",
            "evpn_route_sync",
            "fallback_vrf",
            "mhost.default_interface",
            "rd",
            "remote_route_filtering.disable",
            "vpn.id",
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
        wantd = self.want
        haved = self.have

        wantd = self._vrf_list_to_dict(wantd)
        haved = self._vrf_list_to_dict(haved)

        # if state is merged, merge want into have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "deleted":
            haved = {k: v for k, v in haved.items() if k in wantd or not wantd}
            wantd = {}

        # remove superfluous config for overridden and deleted
        if self.state in ["overridden", "deleted"]:
            for k, have in haved.items():
                if k not in wantd:
                    self._compare(want={}, have=have, vrf=k)

        if self.state == "purged":
            for k, have in haved.items():
                self.purge(have)

        for k, want in wantd.items():
            self._compare(want=want, have=haved.pop(k, {}), vrf=k)

    def _compare(self, want, have, vrf):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Vrf network resource.
        """
        begin = len(self.commands)
        self.compare(self.parsers, want=want, have=have)
        if len(self.commands) != begin:
            self.commands.insert(begin, self._tmplt.render({"name": vrf}, "name", False))

    def _vrf_list_to_dict(self, entry):
        """Convert list of items to dict of items
           for efficient diff calculation.
        :params entry: data dictionary
        """
        entry = {x["name"]: x for x in entry}
        return entry

    def purge(self, have):
        """Purge the VRF configuration"""
        self.commands.append("no vrf {0}".format(have["name"]))
