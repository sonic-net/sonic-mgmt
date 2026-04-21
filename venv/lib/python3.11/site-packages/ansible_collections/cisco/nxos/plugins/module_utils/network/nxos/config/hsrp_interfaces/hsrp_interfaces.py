#
# -*- coding: utf-8 -*-
# Copyright 2025 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos_hsrp_interfaces config file.
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

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.facts import (
    Facts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.hsrp_interfaces import (
    Hsrp_interfacesTemplate,
)


class Hsrp_interfaces(ResourceModule):
    """
    The nxos_hsrp_interfaces config class
    """

    def __init__(self, module):
        super(Hsrp_interfaces, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="hsrp_interfaces",
            tmplt=Hsrp_interfacesTemplate(),
        )
        self.parsers = [
            "standby.bfd",
            "standby.version",
            "standby.delay",
            "standby.mac_refresh",
            "standby.use_bia",
        ]
        self.complex_parsers = [
            "follow",
            "mac_address",
            "group_name",
            "preempt",
            "priority",
            "timer",
            "authentication",
        ]
        self.complex_list_parsers = [
            "ip",
            "track",
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
        if self.want:
            wantd = {}
            for each in self.want:
                wantd.update({each["name"]: each})
        else:
            wantd = {}
        if self.have:
            haved = {}
            for each in self.have:
                haved.update({each["name"]: each})
        else:
            haved = {}

        for each in wantd, haved:
            self.list_to_dict(each)

        # if state is merged, merge want onto have and then compare
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
                    self._compare(want={}, have=have)

        for k, want in wantd.items():
            self._compare(want=want, have=haved.pop(k, {}))

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Hsrp_interfaces network resource.
        """
        begin = len(self.commands)
        self.compare(parsers=self.parsers, want=want, have=have)
        self._compare_complex_attrs(
            want.get("standby_options", {}),
            have.get("standby_options", {}),
        )
        if len(self.commands) != begin:
            self.commands.insert(begin, self._tmplt.render(want or have, "name", False))

    def _compare_complex_attrs(self, want_group, have_group):
        for grp_no, standby_want in want_group.items():
            standby_have = have_group.pop(grp_no, {})
            begin_grp = len(self.commands)
            # compare non list attributes directly
            self.compare(parsers=self.complex_parsers, want=standby_want, have=standby_have)
            # compare list attributes directly
            for x in self.complex_list_parsers:
                for wkey, wentry in standby_want.get(x, {}).items():
                    hentry = standby_have.get(x, {}).pop(wkey, {})
                    if wentry != hentry:
                        self.compare(
                            parsers=self.complex_list_parsers,
                            want={x: wentry},
                            have={x: hentry},
                        )
                # remove extra ip or track
                for hkey, hentry in standby_have.get(x, {}).items():
                    self.compare(parsers=self.complex_list_parsers, want={}, have={x: hentry})
            # adds hsrp [number]
            if len(self.commands) != begin_grp:
                self.commands.insert(
                    begin_grp,
                    self._tmplt.render(standby_want or standby_have, "group_no", False),
                )
        # remove group via numbers
        for not_req_grp in have_group.values():
            self.commands.append(self._tmplt.render(not_req_grp, "group_no", True))

    def list_to_dict(self, param):
        if param:
            for _k, val in param.items():
                temp_standby_grp = {}

                # handle the deprecated attribute, only appliacble for want
                if val.get("bfd"):
                    if val.get("bfd") == "enable":
                        val["standby"] = {}
                        val["standby"]["bfd"] = True
                    else:
                        val["standby"] = {}
                        val["standby"]["bfd"] = False

                for standby_grp in val.get("standby_options", {}):
                    temp_ip = {}
                    if standby_grp.get("ip"):
                        for ips in standby_grp.get("ip", {}):
                            temp_ip[ips.get("virtual_ip")] = ips
                        standby_grp["ip"] = temp_ip
                    temp_track = {}
                    if standby_grp.get("track"):
                        for trk in standby_grp.get("track", {}):
                            temp_track[trk.get("object_no")] = trk
                        standby_grp["track"] = temp_track
                    temp_standby_grp[standby_grp.get("group_no")] = standby_grp

                if val.get("standby_options", {}):
                    val["standby_options"] = temp_standby_grp
