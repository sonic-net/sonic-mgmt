#
# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos_fc_interfaces config file.
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

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.facts import Facts
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.fc_interfaces import (
    Fc_interfacesTemplate,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.utils.utils import (
    normalize_interface,
)


class Fc_interfaces(ResourceModule):
    """
    The nxos_fc_interfaces config class
    """

    def __init__(self, module):
        super(Fc_interfaces, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module, chassis_type="mds"),
            module=module,
            resource="fc_interfaces",
            tmplt=Fc_interfacesTemplate(),
        )
        self.parsers = ["description", "speed", "mode", "trunk_mode", "analytics"]

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
            self.normalize_interface_names(each)

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

        modified_list = [
            "switchport trunk mode on" if item.startswith("no switchport trunk mode") else item
            for item in self.commands
        ]
        self.commands = modified_list

    def _calculate_ana_config(self, want_ana, have_ana):
        """
        get the cmds based on want_ana and have_ana and the state

        Args:
            want_ana (str): analytics type which you want
            have_ana (str): analytics type which you have

        +----------+----------+---------+
        |            MERGED             |
        |----------+----------+---------+
        | want_ana | have_ana | outcome |
        +----------+----------+---------+
        | ""       | *        | no op   |
        | fc-scsi  | *        | fc-scsi |
        | fc-scsi  | fc-all   | no op   |
        | fc-nvme  | *        | fc-nvme |
        | fc-nvme  | fc-all   | no op   |
        +----------+----------+---------+


        +----------+----------+-----------+
        |            DELETED              |
        |----------+----------+-----------+
        | want_ana | have_ana | outcome   |
        +----------+----------+-----------+
        | *        | fc-scsi  | no fc-all |
        | *        | fc-nvme  | no fc-all |
        | *        | fc-all   | no fc-all |
        | *        | ""       | no op     |
        +----------+----------+-----------+


        +----------+----------+---------------------+
        |            REPLACED/OVERRIDEN             |
        |----------+----------+---------------------+
        | want_ana | have_ana | outcome             |
        +----------+----------+---------------------+
        | ""       | *        | no fc-all           |
        | fc-scsi  | ""       | fc-scsi             |
        | fc-nvme  | ""       | fc-nvme             |
        | fc-all   | ""       | fc-all              |
        | fc-scsi  | *        | no fc-all ; fc-scsi |
        | fc-nvme  | *        | no fc-all ; fc-nvme |
        | fc-all   | *        | fc-all              |
        +----------+----------+---------------------+


        """

        if want_ana == have_ana:
            return []
        val = []
        if self.state in ["overridden", "replaced"]:
            if want_ana == "":
                val = ["no analytics type fc-all"]
            elif want_ana == "fc-all":
                val = ["analytics type fc-all"]
            elif have_ana == "":
                val = [f"analytics type {want_ana}"]
            else:
                val = ["no analytics type fc-all", f"analytics type {want_ana}"]
        elif self.state in ["deleted"]:
            if have_ana:
                val = ["no analytics type fc-all"]
        elif self.state in ["merged"]:
            if want_ana:
                if have_ana != "fc-all":
                    val = [f"analytics type {want_ana}"]
        return val

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Fc_interfaces network resource.
        """

        begin = len(self.commands)
        self.compare(parsers=self.parsers, want=want, have=have)
        if want.get("enabled") != have.get("enabled"):
            if want.get("enabled"):
                self.addcmd(want, "enabled", True)
            else:
                if want:
                    self.addcmd(want, "enabled", False)
                elif have.get("enabled"):
                    # handles deleted as want be blank and only
                    # negates if no shutdown
                    self.addcmd(have, "enabled", False)

        ana_cmds = self._calculate_ana_config(want.get("analytics", ""), have.get("analytics", ""))

        self.commands.extend(ana_cmds)

        if len(self.commands) != begin:
            self.commands.insert(begin, self._tmplt.render(want or have, "interface", False))

    def normalize_interface_names(self, param):
        if param:
            for _k, val in param.items():
                val["name"] = normalize_interface(val["name"])
        return param
