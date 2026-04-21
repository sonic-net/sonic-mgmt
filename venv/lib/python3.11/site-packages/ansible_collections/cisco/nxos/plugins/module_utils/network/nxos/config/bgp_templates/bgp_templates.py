#
# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos_bgp_templates config file.
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
)

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.facts import Facts
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.bgp_templates import (
    Bgp_templatesTemplate,
)


class Bgp_templates(ResourceModule):
    """
    The nxos_bgp_templates config class
    """

    def __init__(self, module):
        super(Bgp_templates, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="bgp_templates",
            tmplt=Bgp_templatesTemplate(),
        )
        self.parsers = [
            "bfd",
            "bfd.multihop.interval",
            "bmp_activate_server",
            "capability",
            "description",
            "disable_connected_check",
            "dont_capability_negotiate",
            "dscp",
            "dynamic_capability",
            "ebgp_multihop",
            "graceful_shutdown",
            "inherit.peer_session",
            "local_as",
            "log_neighbor_changes",
            "low_memory",
            "password",
            "remote_as",
            "remove_private_as",
            "shutdown",
            "timers",
            "transport",
            "ttl_security",
            "update_source",
        ]
        self.af_parsers = [
            "advertise_map.exist_map",
            "advertise_map.non_exist_map",
            "advertisement_interval",
            "allowas_in",
            "as_override",
            "capability.additional_paths.receive",
            "capability.additional_paths.send",
            "default_originate",
            "disable_peer_as_check",
            "filter_list.inbound",
            "inherit.peer_policy",
            "filter_list.outbound",
            "maximum_prefix",
            "next_hop_self",
            "next_hop_third_party",
            "prefix_list.inbound",
            "prefix_list.outbound",
            "route_map.inbound",
            "route_map.outbound",
            "send_community_standard",
            "send_community_extended",
            "route_reflector_client",
            "soft_reconfiguration_inbound",
            "soo",
            "suppress_inactive",
            "unsuppress_map",
            "weight",
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
        wantd = self._list_to_dict(deepcopy(self.want))
        haved = self._list_to_dict(deepcopy(self.have))

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        w_asn = wantd.pop("as_number", "")
        h_asn = haved.pop("as_number", "")

        asn = w_asn or h_asn

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "deleted":
            haved = {k: v for k, v in haved.items() if k in wantd or not wantd}
            wantd = {}

        # remove superfluous config for overridden and deleted
        if self.state in ["overridden", "deleted"]:
            cmds = []
            for k, have in haved.items():
                if k not in wantd:
                    cmds.append("no template peer {0}".format(have["name"]))
            self.commands.extend(cmds)

        for k, want in wantd.items():
            begin = len(self.commands)
            self._compare(want=want, have=haved.pop(k, {}))
            if len(self.commands) != begin:
                self.commands.insert(begin, "template peer {0}".format(want["name"]))

        if self.commands:
            self.commands.insert(0, "router bgp {0}".format(asn))

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Bgp_templates network resource.
        """
        self.compare(parsers=self.parsers, want=want, have=have)
        self._compare_path_attribute(want=want, have=have)

        w_af = want.get("address_family", {})
        h_af = have.get("address_family", {})
        self._afs_compare(want=w_af, have=h_af)

    def _compare_path_attribute(self, want, have):
        """Custom handling of neighbor path_attribute
           option.

        :params want: the want neighbor dictionary
        :params have: the have neighbor dictionary
        """
        w_p_attr = want.get("path_attribute", {})
        h_p_attr = have.get("path_attribute", {})

        for wkey, wentry in w_p_attr.items():
            if wentry != h_p_attr.pop(wkey, {}):
                self.addcmd(wentry, "path_attribute", False)

        # remove remaining items in have for replaced
        for hkey, hentry in h_p_attr.items():
            self.addcmd(hentry, "path_attribute", True)

    def _afs_compare(self, want, have):
        for name, wentry in want.items():
            begin = len(self.commands)
            self._af_compare(want=wentry, have=have.pop(name, {}))
            if begin != len(self.commands):
                self.commands.insert(begin, self._tmplt.render(wentry, "address_family", False))
        for name, hentry in have.items():
            self.commands.append(self._tmplt.render(hentry, "address_family", True))

    def _af_compare(self, want, have):
        # "unpack" send_community
        for item in [want, have]:
            send_comm_val = item.get("send_community", "")
            if send_comm_val:
                if send_comm_val == "both":
                    item["send_community_extended"] = True
                    item["send_community_standard"] = True
                else:
                    key = "send_community_%s" % send_comm_val
                    item[key] = True
        self.compare(parsers=self.af_parsers, want=want, have=have)

    def _list_to_dict(self, data):
        def _build_key(x):
            """Build primary key for path_attribute
               option.
            :params x: path_attribute dictionary
            :returns: primary key as tuple
            """
            key_1 = "start_{0}".format(x.get("range", {}).get("start", ""))
            key_2 = "end_{0}".format(x.get("range", {}).get("end", ""))
            key_3 = "type_{0}".format(x.get("type", ""))
            key_4 = x["action"]

            return (key_1, key_2, key_3, key_4)

        new_data = {}
        new_data["as_number"] = data.pop("as_number", None)

        for k, v in data.items():
            for entry in v:
                if "address_family" in entry:
                    entry["address_family"] = {
                        (x["afi"], x.get("safi")): x for x in entry["address_family"]
                    }
                if "path_attribute" in entry:
                    entry["path_attribute"] = {
                        _build_key(x): x for x in entry.get("path_attribute", [])
                    }

            # attach top-level keys with their values
            tmp = {(k + "_" + x["name"]): x for x in v}
            new_data.update(tmp)

        return new_data
