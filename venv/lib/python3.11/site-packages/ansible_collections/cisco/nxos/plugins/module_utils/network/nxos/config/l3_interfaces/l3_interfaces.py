#
# -*- coding: utf-8 -*-
# Copyright 2025 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos_l3_interfaces config file.
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
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.l3_interfaces import (
    L3_interfacesTemplate,
)


class L3_interfaces(ResourceModule):
    """
    The nxos_l3_interfaces config class
    """

    def __init__(self, module):
        super(L3_interfaces, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="l3_interfaces",
            tmplt=L3_interfacesTemplate(),
        )
        self.parsers = [
            "mac_address",
            "bandwidth",
            "dot1q",
            "evpn_multisite_tracking",
            "redirects",
            "unreachables",
            "proxy_arp",
            "port_unreachable",
            "verify",
            "dhcp.ipv4",
            "dhcp.ipv4.option82",
            "dhcp.ipv4.information",
            "dhcp.ipv4.subnet_selection",
            "dhcp.ipv4.source_interface",
            "ipv6_redirects",
            "ipv6_unreachables",
            "ipv6_verify",
            "dhcp.ipv6",
            "dhcp.ipv6.source_interface",
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

        wantd = self.convert_list_to_dict(self.want)
        haved = self.convert_list_to_dict(self.have)

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
        for the L3_interfaces network resource.
        """
        begin = len(self.commands)
        want_without_name = want.copy()
        want_without_name.pop("name", None)
        pre_pop_want = bool(want_without_name)
        want_redirects = want.pop("redirects", None)
        have_redirects = have.pop("redirects", None)
        self.handle_redirects(want_redirects, have_redirects, "redirects", pre_pop_want)
        want_redirects = want.pop("ipv6_redirects", None)
        have_redirects = have.pop("ipv6_redirects", None)
        self.handle_redirects(want_redirects, have_redirects, "ipv6_redirects", pre_pop_want)
        self.compare(parsers=self.parsers, want=want, have=have)
        self._compare_complex_attrs(want, have)
        if len(self.commands) != begin:
            self.commands.insert(begin, self._tmplt.render(want or have, "name", False))

    def convert_list_to_dict(self, data):
        def list_to_dict(dict_list, outer_key_priority):
            output = {}
            for entry in dict_list:
                if not isinstance(entry, dict) or not entry:
                    continue

                outer_key = None

                for k in outer_key_priority:
                    if k in entry:
                        val = entry[k]
                        outer_key = k if isinstance(val, bool) else str(val)
                        break

                if outer_key is not None:
                    output[outer_key] = entry

            return output

        result = {}

        iterable = ((entry["name"], entry) for entry in data if "name" in entry)

        for iface_name, iface_data in iterable:
            iface_result = iface_data.copy()

            ipv4_value_addresses = iface_result.get("ipv4", [])
            ipv6_value_addresses = iface_result.get("ipv6", [])

            ipv4_value_dhcp_relay_address = (
                iface_result.get("dhcp", {}).get("ipv4", {}).get("relay", {}).get("address", [])
            )
            ipv6_value_dhcp_relay_address = (
                iface_result.get("dhcp", {}).get("ipv6", {}).get("relay", {}).get("address", [])
            )

            if ipv4_value_addresses:
                iface_result["ipv4"] = list_to_dict(
                    ipv4_value_addresses,
                    ["address", "ip_network_mask"],
                )
            if ipv4_value_dhcp_relay_address:
                iface_result["dhcp"]["ipv4"]["relay"]["address"] = list_to_dict(
                    ipv4_value_dhcp_relay_address,
                    ["relay_ip"],
                )
            if ipv6_value_addresses:
                iface_result["ipv6"] = list_to_dict(
                    ipv6_value_addresses,
                    [
                        "address",
                    ],
                )
            if ipv6_value_dhcp_relay_address:
                iface_result["dhcp"]["ipv6"]["relay"]["address"] = list_to_dict(
                    ipv6_value_dhcp_relay_address,
                    ["relay_ip"],
                )

            result[iface_name] = iface_result

        return result

    def _compare_complex_attrs(self, want, have):
        """Compare complex attributes"""
        want_ipv4_value_address = want.get("ipv4", {})
        have_ipv4_value_address = have.get("ipv4", {})
        want_ipv6_value_address = want.get("ipv6", {})
        have_ipv6_value_address = have.get("ipv6", {})

        self.compare_lists(want_ipv4_value_address, have_ipv4_value_address, "ipv4.address")
        self.compare_lists(want_ipv6_value_address, have_ipv6_value_address, "ipv6.address")

        want_ipv4_value_relay_address = (
            want.get("dhcp", {}).get("ipv4", {}).get("relay", {}).get("address", {})
        )
        have_ipv4_value_relay_address = (
            have.get("dhcp", {}).get("ipv4", {}).get("relay", {}).get("address", {})
        )
        self.compare_lists(
            want_ipv4_value_relay_address,
            have_ipv4_value_relay_address,
            "dhcp.ipv4.address",
        )

        want_ipv6_value_relay_address = (
            want.get("dhcp", {}).get("ipv6", {}).get("relay", {}).get("address", {})
        )
        have_ipv6_value_relay_address = (
            have.get("dhcp", {}).get("ipv6", {}).get("relay", {}).get("address", {})
        )
        self.compare_lists(
            want_ipv6_value_relay_address,
            have_ipv6_value_relay_address,
            "dhcp.ipv6.address",
        )

    def compare_lists(self, wanted, haved, parser):
        """Compare list items in ipv4 and ipv6"""
        ip_key = parser.split(".")[0]
        parser_key = parser.split(".")[1]
        for key, want_value in wanted.items():
            have_value = haved.pop(key, {})
            self.compare(
                parsers=[parser],
                want={ip_key: {parser_key: want_value}},
                have={ip_key: {parser_key: have_value}},
            )
        for key, have_value in haved.items():
            self.compare(parsers=[parser], want={}, have={ip_key: {parser_key: have_value}})

    def handle_redirects(self, want_redirects, have_redirects, parser, want):
        if want_redirects is None and have_redirects is None:
            if self.state == "replaced" or (self.state == "overridden" and want):
                self.addcmd({parser: True}, parser, True)
        else:
            if want_redirects is True and have_redirects is False:
                self.addcmd({parser: want_redirects}, parser, not want_redirects)
            elif want_redirects is False and have_redirects is None:
                self.addcmd({parser: not want_redirects}, parser, not want_redirects)
            elif want_redirects is None and have_redirects is False:
                if self.state in ["overridden", "deleted"] and not want:
                    self.addcmd({parser: not have_redirects}, parser, have_redirects)
