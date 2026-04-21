#
# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos_vrf_global config file.
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
    get_from_dict,
)

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.facts import Facts
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.vrf_global import (
    Vrf_globalTemplate,
)


class Vrf_global(ResourceModule):
    """
    The nxos_vrf_global config class
    """

    def __init__(self, module):
        super(Vrf_global, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="vrf_global",
            tmplt=Vrf_globalTemplate(),
        )
        self.parsers = [
            "description",
            "rd",
            "ip.auto_discard",
            "ip.domain_name",
            "ip.name_server.address_list",
            "ip.icmp_err.source_interface",
            "ip.multicast.group_range_prefix_list",
            "ip.multicast.multipath.resilient",
            "ip.multicast.multipath.splitting_type.none",
            "ip.multicast.multipath.splitting_type.legacy",
            "ip.multicast.multipath.splitting_type.nbm",
            "ip.multicast.multipath.splitting_type.sg_hash",
            "ip.multicast.multipath.splitting_type.sg_hash_next_hop",
            "ip.name_server.use_vrf",
            "vni",
            "ipv6.multicast.group_range_prefix_list",
            "ipv6.multicast.multipath.resilient",
            "ipv6.multicast.multipath.splitting_type.none",
            "ipv6.multicast.multipath.splitting_type.sg_hash",
            "ipv6.multicast.multipath.splitting_type.sg_hash_next_hop",
        ]

        self.list_parsers = [
            "ip.domain_list",
            "ip.igmp.ssm_translate",
            "ip.mroutes",
            "ip.multicast.rpf",
            "ip.route",
            "multicast.service_reflect",
            "ipv6.mld_ssm_translate",
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

        wantd = self._vrf_list_to_dict(self.want)
        haved = self._vrf_list_to_dict(self.have)

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

        if self.state == "purged":
            purge_list = wantd or haved
            for k, item in purge_list.items():
                self.purge(item)
        else:
            for k, want in wantd.items():
                self._compare(want=want, have=haved.pop(k, {}))

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Vrf_global network resource.
        """
        begin = len(self.commands)
        self.compare(parsers=self.parsers, want=want, have=have)
        self._compare_lists(want=want, have=have)
        if len(self.commands) != begin or (not have and want):
            self.commands.insert(
                begin,
                self._tmplt.render(
                    want or have,
                    "name",
                    False,
                ),
            )

    def _compare_lists(self, want, have):
        """Compares the list parsers for the Vrf_global network resource
        and populates the list of commands to be run.
        """
        for attrib in self.list_parsers:
            wdict = get_from_dict(want, attrib) or {}
            hdict = get_from_dict(have, attrib) or {}

            for key, entry in wdict.items():
                if entry != hdict.pop(key, {}):
                    self.addcmd(entry, attrib, False)
            # remove remaining items in have for replaced
            for entry in hdict.values():
                self.addcmd(entry, attrib, True)

    def purge(self, have):
        """Purge the VRF configuration"""
        self.commands.append("no vrf context {0}".format(have["name"]))

    def _vrf_list_to_dict(self, vrf_list):
        """Converts a list of VRFs to a dictionary with the VRF name as the key.

        :param list vrf_list: A list of VRFs
        :rtype: dict
        :returns: A dictionary of VRFs with the VRF name as the key
        """
        vrfitems = dict()
        for entry in vrf_list.get("vrfs", []):
            vrfitems.update({(entry["name"]): entry})

        for vrf, value in vrfitems.items():
            domain_list = value.get("ip", {}).get("domain_list", [])
            if domain_list:
                value["ip"]["domain_list"] = {
                    entry: {"domain_list": entry} for entry in domain_list
                }
            ip_ssm = value.get("ip", {}).get("igmp", {}).get("ssm_translate", [])
            if ip_ssm:
                value["ip"]["igmp"]["ssm_translate"] = {
                    (entry.get("group"), entry.get("source")): entry for entry in ip_ssm
                }
            ip_mroutes = value.get("ip", {}).get("mroutes", [])
            if ip_mroutes:
                value["ip"]["mroutes"] = {
                    (entry.get("group"), entry.get("source")): entry for entry in ip_mroutes
                }
            ip_rpf = value.get("ip", {}).get("multicast", {}).get("rpf", [])
            if ip_rpf:
                value["ip"]["multicast"]["rpf"] = {
                    (entry.get("vrf_name"), entry.get("group_list_range")): entry
                    for entry in ip_rpf
                }
            ip_route = value.get("ip", {}).get("route", [])
            if ip_route:
                temp_route = {}
                for entry in ip_route:
                    if entry.get("vrf"):
                        temp_route[
                            (entry.get("vrf"), entry.get("source"), entry.get("destination"))
                        ] = entry
                    elif entry.get("tags"):
                        tagv = entry.get("tags")
                        temp_route[
                            (
                                f"{tagv.get('tag_value')}_{tagv.get('route_pref', '')}",
                                entry.get("source"),
                                entry.get("destination"),
                            )
                        ] = entry
                    elif entry.get("track"):
                        temp_route[
                            (entry.get("track"), entry.get("source"), entry.get("destination"))
                        ] = entry
                    else:
                        temp_route[(entry.get("source"), entry.get("destination"))] = entry
                value["ip"]["route"] = temp_route

            service_reflect = value.get("multicast", {}).get("service_reflect", [])
            if service_reflect:
                value["multicast"]["service_reflect"] = {
                    (entry.get("service_interface"), entry.get("map_to")): entry
                    for entry in service_reflect
                }
            ipv6_ssm = value.get("ipv6", {}).get("mld_ssm_translate", [])
            if ipv6_ssm:
                value["ipv6"]["mld_ssm_translate"] = {
                    (entry.get("group"), entry.get("source")): entry for entry in ipv6_ssm
                }
            address_list = value.get("ip", {}).get("name_server", {}).get("address_list", [])
            if address_list:
                value["ip"]["name_server"]["address_list"] = " ".join(address_list)
        return vrfitems
