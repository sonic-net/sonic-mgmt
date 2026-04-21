#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The eos_ntp_global config file.
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

from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.facts import Facts
from ansible_collections.arista.eos.plugins.module_utils.network.eos.rm_templates.ntp_global import (
    Ntp_globalTemplate,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.utils.utils import (
    normalize_interface,
)


class Ntp_global(ResourceModule):
    """
    The eos_ntp_global config class
    """

    def __init__(self, module):
        super(Ntp_global, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="ntp_global",
            tmplt=Ntp_globalTemplate(),
        )
        self.parsers = [
            "authenticate",
            "local_interface",
            "qos_dscp",
            "trusted_key",
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
        wantd = {"ntp_global": self.want}
        haved = {"ntp_global": self.have}
        # turn all lists of dicts into dicts prior to merge
        for entry in wantd["ntp_global"], haved["ntp_global"]:
            self._ntp_global_list_to_dict(entry)

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "deleted":
            wantd = {}
            for k, have in iteritems(haved):
                if k not in wantd:
                    self._compare(want={}, have=have)

        for k, want in iteritems(wantd):
            self._compare(want=want, have=haved.pop(k, {}))

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Ntp_global network resource.
        """
        self._serve_compare(want=want, have=have)
        self._authentication_keys_compare(want=want, have=have)
        self._servers_compare(want=want, have=have)
        self.compare(parsers=self.parsers, want=want, have=have)
        add_cmd = []
        del_cmd = []
        if self.commands:
            for cmd in self.commands:
                if "no ntp" in cmd:
                    del_cmd.append(cmd)
                else:
                    add_cmd.append(cmd)
            self.commands = del_cmd + add_cmd

    def _authentication_keys_compare(self, want, have):
        w = want.pop("authentication_keys", {})
        h = have.pop("authentication_keys", {})
        for name, entry in iteritems(w):
            h_key = {}
            if h.get(name):
                h_key = {"authentication_keys": h.pop(name)}
            self.compare(
                parsers="authentication_keys",
                want={"authentication_keys": entry},
                have=h_key,
            )
        for name, entry in iteritems(h):
            self.compare(
                parsers="authentication_keys",
                want={},
                have={"authentication_keys": entry},
            )

    def _servers_compare(self, want, have):
        w = want.pop("servers", {})
        h = have.pop("servers", {})
        for name, entry in iteritems(w):
            if entry.get("source"):
                entry["source"] = normalize_interface(entry["source"])
            h_key = {}
            if h.get(name):
                h_key = {"servers": h.pop(name)}
            self.compare(
                parsers="servers",
                want={"servers": entry},
                have=h_key,
            )
        for name, entry in iteritems(h):
            self.compare(parsers="servers", want={}, have={"servers": entry})

    def _serve_compare(self, want, have):
        serve_want = want.pop("serve", {})
        serve_have = have.pop("serve", {})
        for name, entry in iteritems(serve_want):
            if name == "all" and entry:
                w = {"serve": {"all": True}}
                self.compare(
                    parsers="serve_all",
                    want=w,
                    have={"serve": {"all": serve_have.pop("all", False)}},
                )
            else:
                for k_afi, v_afi in iteritems(entry):
                    for k, v in iteritems(v_afi):
                        afi = v_afi["afi"]
                        if k == "afi":
                            continue
                        h = {}
                        if k == "acls":
                            for ace, ace_entry in iteritems(v):
                                if serve_have.get("access_lists"):
                                    for hk, hv in iteritems(
                                        serve_have["access_lists"],
                                    ):
                                        for h_k, h_v in iteritems(hv):
                                            h_afi = hv["afi"]
                                            if h_k == "afi":
                                                continue
                                            if h_afi == afi:
                                                if ace in h_v:
                                                    h_acc = {
                                                        "afi": h_afi,
                                                        "acls": h_v.pop(ace),
                                                    }
                                                    h = {
                                                        "serve": {
                                                            "access_lists": h_acc,
                                                        },
                                                    }
                                w = {
                                    "serve": {
                                        "access_lists": {
                                            "afi": afi,
                                            "acls": ace_entry,
                                        },
                                    },
                                }
                                self.compare(parsers="serve", want=w, have=h)
        for k, v in iteritems(serve_have):
            if k == "all" and v:
                h = {"serve": {"all": True}}
                self.compare(parsers="serve_all", want={}, have=h)
            else:
                for k_afi, v_afi in iteritems(v):
                    for k, v in iteritems(v_afi):
                        hafi = v_afi["afi"]
                        if k == "afi":
                            continue
                        for k_acl, v_acl in iteritems(v):
                            h = {
                                "serve": {
                                    "access_lists": {
                                        "afi": hafi,
                                        "acls": v_acl,
                                    },
                                },
                            }
                            self.compare(parsers="serve", want={}, have=h)

    def _ntp_global_list_to_dict(self, entry):
        if "authentication_keys" in entry:
            key_dict = {}
            for el in entry["authentication_keys"]:
                key_dict.update({el["id"]: el})
            entry["authentication_keys"] = key_dict

        if "servers" in entry:
            server_dict = {}
            for el in entry["servers"]:
                server_dict.update({el["server"]: el})
            entry["servers"] = server_dict

        if "serve" in entry:
            serve_dict = {}
            main_dict = {}
            if entry["serve"].get("all"):
                main_dict.update({"all": entry["serve"]["all"]})
            if entry["serve"].get("access_lists"):
                for el in entry["serve"].get("access_lists"):
                    if "acls" in el:
                        acl_dict = {}
                        for acl in el["acls"]:
                            acl_dict.update({acl["acl_name"]: acl})
                        el["acls"] = acl_dict
                    serve_dict.update({el["afi"]: el})
                if serve_dict:
                    main_dict.update({"access_lists": serve_dict})
            if serve_dict:
                entry["serve"] = main_dict
