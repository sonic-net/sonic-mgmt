#
# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The iosxr_ospf_interfaces config file.
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
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.rm_templates.ospf_interfaces import (
    Ospf_interfacesTemplate,
)


class Ospf_interfaces(ResourceModule):
    """
    The iosxr_ospf_interfaces config class
    """

    gather_subset = ["!all", "!min"]

    gather_network_resources = ["ospf_interfaces"]

    def __init__(self, module):
        super(Ospf_interfaces, self).__init__(
            empty_fact_val=[],
            facts_module=Facts(module),
            module=module,
            resource="ospf_interfaces",
            tmplt=Ospf_interfacesTemplate(),
        )
        self.parsers = [
            "authentication.message_digest",
            "authentication.null_auth",
            "authentication.message_digest.keychain",
            "authentication_key",
            "bfd.minimum_interval",
            "bfd.multiplier",
            "bfd.fast_detect.set",
            "bfd.fast_detect.disable",
            "bfd.fast_detect.strict_mode",
            "cost",
            "cost_fallback",
            "dead_interval",
            "demand_circuit",
            "flood_reduction",
            "hello_interval",
            "link_down.set",
            "link_down.disable",
            "message_digest_key",
            "mpls.set_ldp",
            "mpls.ldp_sync",
            "mpls.ldp_sync_disable",
            "mtu_ignore",
            "network",
            "packet_size",
            "passive",
            "prefix_suppression.disable",
            "prefix_suppression.secondary_address",
            "priority",
            "retransmit_interval",
            "security.ttl_hops",
            "security.ttl",
            "transmit_delay",
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

        # turn all lists of dicts into dicts prior to merge
        for entry in wantd, haved:
            self._ospf_int_list_to_dict(entry)

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "deleted":
            haved = {k: v for k, v in haved.items() if k in wantd or not wantd}
            have_int = []
            if wantd == {}:
                for k, have in haved.items():
                    self._remove_ospf_int(have)

            for k, have in haved.items():
                if k in wantd:
                    have_int.append(k)
                    self._remove_ospf_int(have)
            wantd = {}

        # remove superfluous config for overridden and deleted
        if self.state == "overridden":
            for k, have in haved.items():
                if k not in wantd:
                    self._remove_ospf_int(have)
        if self.state != "deleted":
            for k, want in wantd.items():
                self._compare(want=want, have=haved.pop(k, {}))

    def _remove_ospf_int(self, entry):
        int_name = entry.get("name", {})
        int_addr = entry.get("address_family", {})
        for k, addr in int_addr.items():
            for key, value in addr["processes"].items():
                rem_entry = {
                    "name": int_name,
                    "afi": addr["afi"],
                    "process": value["process_id"],
                    "area": value["area"],
                }
            self.addcmd(rem_entry, "name", True)

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Ospf_interfaces network resource.
        """
        self._compare_interface(want=want, have=have)

        self._compare_addr_family(want=want, have=have)

    def _compare_interface(self, want, have):
        wdict = want.get("address_family", {})
        hdict = have.get("address_family", {})
        wname = want.get("name")
        hname = have.get("name")
        h_value = {}

        for key, w_value in wdict.items():
            if hdict and hdict.get(key):
                h_value = hdict[key]
            else:
                h_value = None
            w = {
                "name": wname,
                "type": w_value["afi"],
                "address_family": w_value,
            }
            if h_value is not None:
                h = {
                    "name": hname,
                    "type": h_value["afi"],
                    "address_family": h_value,
                }
            else:
                h = {}
            self.compare(parsers="name", want=w, have=h)

    def _compare_addr_family(self, want, have):
        wdict = want.get("address_family", {})
        hdict = have.get("address_family", {})
        wname = want.get("name")
        hname = have.get("name")
        # Fetch the area info as that would be common to all the attributes per interface
        for name, entry in wdict.items():
            w_process = {}
            h_process = {}
            for key, value in entry.items():
                if key == "processes":
                    for pname, pentry in value.items():
                        w_process = pentry
            for key, param in entry.items():
                w_addr = {"afi": name, key: param, "processes": w_process}
                h_addr = {}
                if hdict.get(name):
                    hdict_entry = hdict.get(name)
                    for item, value in hdict_entry.items():
                        if item == "processes":
                            for pname, pentry in value.items():
                                h_process = pentry
                    h_addr = {
                        "afi": name,
                        key: hdict[name].pop(key, {}),
                        "processes": h_process,
                    }
                w = {"name": wname, "address_family": w_addr}
                h = {"name": hname, "address_family": h_addr}
                self.compare(parsers=self.parsers, want=w, have=h)
        for name, entry in hdict.items():
            for key, param in entry.items():
                h_addr = {"afi": name, key: param}
                w_addr = {}
                w = {"name": wname, "address_family": w_addr}
                h = {"name": hname, "address_family": h_addr}
                self.compare(parsers=self.parsers, want=w, have=h)

    def _ospf_int_list_to_dict(self, entry):
        for name, family in entry.items():
            if "address_family" in family:
                family["address_family"] = {
                    entry["afi"]: entry for entry in family.get("address_family", [])
                }
                self._ospf_int_list_to_dict(family["address_family"])
        for name, ospf_processes in entry.items():
            if "processes" in ospf_processes:
                ospf_processes["processes"] = {
                    entry["process_id"]: entry for entry in ospf_processes.get("processes", [])
                }
                self._ospf_int_list_to_dict(ospf_processes["processes"])
