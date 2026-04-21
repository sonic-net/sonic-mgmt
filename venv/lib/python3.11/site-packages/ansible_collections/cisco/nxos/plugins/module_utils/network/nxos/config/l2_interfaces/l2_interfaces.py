#
# -*- coding: utf-8 -*-
# Copyright 2025 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos_l2_interfaces config file.
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
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.l2_interfaces import (
    L2_interfacesTemplate,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.utils.utils import (
    generate_switchport_trunk,
    normalize_interface,
    vlan_list_to_range,
    vlan_range_to_list,
)


class L2_interfaces(ResourceModule):
    """
    The nxos_l2_interfaces config class
    """

    def __init__(self, module):
        super(L2_interfaces, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="l2_interfaces",
            tmplt=L2_interfacesTemplate(),
        )
        self.parsers = [
            "mode",
            "access.vlan",
            "trunk.native_vlan",
            "beacon",
            "link_flap.error_disable",
            "cdp_enable",
            "no_cdp_enable",
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
        wantd = {entry["name"]: entry for entry in self.want}
        haved = {entry["name"]: entry for entry in self.have}

        for each in wantd, haved:
            self.process_list_attrs(each)

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
        for the L2_interfaces network resource.
        """
        begin = len(self.commands)
        want_without_name = want.copy()
        want_without_name.pop("name", None)
        pre_pop_want = bool(want_without_name)
        want_cdp = want.pop("cdp_enable", None)
        have_cdp = have.pop("cdp_enable", None)
        self.handle_cdp(want_cdp, have_cdp, "cdp_enable", pre_pop_want)
        self.compare(parsers=self.parsers, want=want, have=have)
        self._compare_lists(want, have)
        if len(self.commands) != begin:
            self.commands.insert(begin, self._tmplt.render(want or have, "name", False))

    def _compare_lists(self, want, have):
        """Compare list attributes"""
        trunk_want = want.get("trunk", {})
        trunk_have = have.get("trunk", {})

        for vlan in ["allowed_vlans"]:
            want_list = trunk_want.get(vlan, [])
            have_list = trunk_have.get(vlan, [])

            if want_list != "none" and have_list != "none":
                # Convert VLAN lists to sets for easier comparison
                want_set = set(want_list)
                have_set = set(have_list)

                # VLANs to be added (present in want, not in have)
                vlans_to_add = want_set - have_set

                # VLANs to be removed (present in have, not in want or not in add list)
                vlans_to_remove = [
                    vl_no
                    for vl_no in have_list
                    if vl_no not in vlans_to_add and vl_no not in want_set
                ]
            else:
                want_set = "none" if want_list == "none" else want_list
                have_set = "none" if have_list == "none" else have_list

                vlans_to_add = [] if want_set == "none" else want_set
                vlans_to_remove = [] if have_set == "none" else have_set

            vlan_name = vlan.split("_", maxsplit=1)[0]

            if self.state != "merged":
                if want_set == "none" and have_set != "none":
                    # if want is none, remove all vlans
                    self.commands.append(f"switchport trunk {vlan_name} vlan none")
                elif not want_list and vlans_to_remove:
                    # remove vlan all as want blank
                    self.commands.append(f"no switchport trunk {vlan_name} vlan")
                elif vlans_to_remove:
                    # remove excess vlans for replaced overridden with vlan entries
                    self.commands.append(
                        f"switchport trunk {vlan_name} vlan remove {vlan_list_to_range(sorted(vlans_to_remove))}",
                    )

            if self.state != "deleted" and vlans_to_add:
                self.commands.extend(
                    generate_switchport_trunk(
                        vlan_name,
                        have_list,
                        vlan_list_to_range(sorted(vlans_to_add)),
                    ),
                )

    def process_list_attrs(self, param):
        if param:
            for _k, val in param.items():
                val["name"] = normalize_interface(val["name"])
                if val.get("trunk"):
                    for vlan in ["allowed_vlans"]:
                        vlanList = val.get("trunk").get(vlan, [])
                        if vlanList and vlanList != "none":
                            val["trunk"][vlan] = vlan_range_to_list(val.get("trunk").get(vlan))

    def handle_cdp(self, want_cdp, have_cdp, parser, want):
        if want_cdp is None and have_cdp is None:
            if self.state == "replaced" or (self.state == "overridden" and want):
                self.addcmd({parser: True}, parser, True)
        else:
            if want_cdp is True and have_cdp is False:
                self.addcmd({parser: want_cdp}, parser, not want_cdp)
            elif want_cdp is False and have_cdp is None:
                self.addcmd({parser: not want_cdp}, parser, not want_cdp)
            elif want_cdp is None and have_cdp is False:
                if self.state in ["overridden", "deleted"] and not want:
                    self.addcmd({parser: not have_cdp}, parser, have_cdp)
