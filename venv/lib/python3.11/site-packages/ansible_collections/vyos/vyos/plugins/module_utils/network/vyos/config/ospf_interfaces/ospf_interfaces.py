#
# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type
"""
The vyos_ospf_interfaces config file.
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to its desired end-state is
created.
"""

from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.resource_module import (
    ResourceModule,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    dict_merge,
)

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.facts.facts import Facts
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.ospf_interfaces import (
    Ospf_interfacesTemplate
)

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.ospf_interfaces_14 import (
    Ospf_interfacesTemplate14
)

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.vyos import get_os_version

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.utils.version import LooseVersion


class Ospf_interfaces(ResourceModule):
    """
    The vyos_ospf_interfaces config class
    """

    def __init__(self, module):
        super(Ospf_interfaces, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="ospf_interfaces",
            tmplt=Ospf_interfacesTemplate(),
        )
        self.parsers = [
            "authentication_password",
            "authentication_md5",
            "bandwidth",
            "cost",
            "hello_interval",
            "dead_interval",
            "mtu_ignore",
            "network",
            "priority",
            "retransmit_interval",
            "transmit_delay",
            "ifmtu",
            "instance",
            "passive",
        ]

    def _validate_template(self):
        version = get_os_version(self._module)
        if LooseVersion(version) >= LooseVersion("1.4"):
            self._tmplt = Ospf_interfacesTemplate14()
        else:
            self._tmplt = Ospf_interfacesTemplate()

    def parse(self):
        """ override parse to check template """
        self._validate_template()
        return super().parse()

    def get_parser(self, name):
        """get_parsers"""
        self._validate_template()
        return super().get_parser(name)

    def execute_module(self):
        """Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        self._validate_template()
        if self.state not in ["parsed", "gathered"]:
            self.generate_commands()
            self.run_commands()
        return self.result

    def generate_commands(self):
        """Generate configuration commands to send based on
        want, have and desired state.
        """
        wantd = {}
        haved = {}
        for entry in self.want:
            wantd.update({entry["name"]: entry})
        for entry in self.have:
            haved.update({entry["name"]: entry})

        # turn all lists of dicts into dicts prior to merge
        for entry in wantd, haved:
            self._ospf_int_list_to_dict(entry)
        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "deleted":
            h_del = {}
            for k, v in iteritems(haved):
                if k in wantd or not wantd:
                    h_del.update({k: v})
            haved = h_del
            have_int = []
            for k, have in iteritems(haved):
                if k in wantd:
                    have_int.append(k)
                    self._remove_ospf_int(have)
            wantd = {}

        if self.state == "overridden":
            have_int = []
            for k, have in iteritems(haved):
                if k not in wantd:
                    have_int.append(k)
                    self._remove_ospf_int(have)

        # remove superfluous config for overridden and deleted
        if self.state in ["overridden", "deleted"]:
            # removing the interfaces from haved that are already negated
            for interface in have_int:
                haved.pop(interface)
            for k, have in iteritems(haved):
                if k not in wantd:
                    self._compare(want={}, have=have)

        for k, want in iteritems(wantd):
            self._compare(want=want, have=haved.pop(k, {}))

    def _remove_ospf_int(self, entry):
        int_name = entry.get("name", {})
        int_addr = entry.get("address_family", {})
        for k, addr in iteritems(int_addr):
            rem_entry = {"name": int_name, "address_family": {"afi": k}}
            self.addcmd(rem_entry, "ip_ospf", True)

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Ospf_interfaces network resource.
        """
        self._compare_addr_family(want=want, have=have)

    def _compare_addr_family(self, want, have):
        wdict = want.get("address_family", {})
        hdict = have.get("address_family", {})
        wname = want.get("name")
        hname = have.get("name")
        for name, entry in iteritems(wdict):
            for key, param in iteritems(entry):
                w_addr = {"afi": name, key: param}
                h_addr = {}
                if hdict.get(name):
                    h_addr = {"afi": name, key: hdict[name].pop(key, {})}
                w = {"name": wname, "address_family": w_addr}
                h = {"name": hname, "address_family": h_addr}
                self.compare(parsers=self.parsers, want=w, have=h)
        for name, entry in iteritems(hdict):
            for key, param in iteritems(entry):
                h_addr = {"afi": name, key: param}
                w_addr = {}
                w = {"name": wname, "address_family": w_addr}
                h = {"name": hname, "address_family": h_addr}
                self.compare(parsers=self.parsers, want=w, have=h)

    def _ospf_int_list_to_dict(self, entry):
        for name, family in iteritems(entry):
            if "address_family" in family:
                addr_dict = {}
                for entry in family.get("address_family", []):
                    addr_dict.update({entry["afi"]: entry})
                family["address_family"] = addr_dict
                self._ospf_int_list_to_dict(family["address_family"])
