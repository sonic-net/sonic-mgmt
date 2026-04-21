#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The vyos_logging_global config file.
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to its desired end-state is
created.
"""

from copy import deepcopy

from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.resource_module import (
    ResourceModule,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    dict_merge,
    get_from_dict,
)

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.facts.facts import Facts
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.logging_global import (
    Logging_globalTemplate,
)


class Logging_global(ResourceModule):
    """
    The vyos_logging_global config class
    """

    def __init__(self, module):
        super(Logging_global, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="logging_global",
            tmplt=Logging_globalTemplate(),
        )
        self.parsers = [
            "console.facilities",
            "global_params.archive.file_num",
            "global_params.archive.size",
            "global_params.marker_interval",
            "global_params.preserve_fqdn",
            "global_params.facilities",
            "files.archive.size",
            "files.archive.file_num",
            "files",
            "hosts.port",
            "hosts.facility.protocol",  # 1.3 and below
            "hosts.protocol",
            "hosts",
            "users",
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
            wantd = self.list_to_dict(self.want, "want")
        else:
            wantd = dict()
        if self.have:
            haved = self.list_to_dict(self.have, "have")
        else:
            haved = dict()

        if self.state in ["overridden", "replaced"]:
            if wantd != haved:
                wantx, havex = self.call_op(wantd, haved, "overridden")
                for k, have in iteritems(havex):
                    if k not in wantx:
                        self._compare(want={}, have=have)

        if not self.state == "deleted":
            wantd, haved = self.call_op(wantd, haved)

        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        for k, want in iteritems(wantd):
            self._compare(want=want, have=haved.pop(k, {}))

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Logging_global network resource.
        """
        self.compare(parsers=self.parsers, want=want, have=have)
        self.handleStates(want=want, have=have)

    def operation_rep(self, params):
        op_val = dict()
        for k, val in iteritems(params):
            if k in ["console", "global_params"]:
                mod_val = deepcopy(val)
                op_val.update(self.flatten_facility({k: mod_val}))
            elif k in ["files", "hosts", "users"]:
                for m, n in iteritems(val):
                    mod_n = deepcopy(n)
                    if mod_n.get("archive"):
                        del mod_n["archive"]
                    if mod_n.get("facilities"):
                        del mod_n["facilities"]
                    if mod_n.get("port"):
                        del mod_n["port"]
                    tm = self.flatten_facility({k: {m: mod_n}})
                    op_val.update(tm)
        return op_val

    def call_op(self, _want, _have, mode=None):
        if mode == "overridden":
            w = self.operation_rep(_want)
            h = self.operation_rep(_have)
        else:
            w = self.flatten_facility(_want)
            h = self.flatten_facility(_have)
        return w, h

    def handleStates(self, want=None, have=None):
        stateparsers = [
            "syslog.state",
            "console.state",
            "global_params.state",
            "global_params.archive.state",
            "files.archive.state",
        ]
        for par in stateparsers:
            op = get_from_dict(want, par)
            if op == "enabled":
                self.addcmd(want, par)
            elif op == "disabled":
                self.addcmd(want, par, True)
                break

    def flatten_facility(self, param):
        temp_param = dict()
        for element, val in iteritems(param):
            if element in ["console", "global_params", "syslog"]:
                if element != "syslog" and val.get("facilities"):
                    for k, v in iteritems(val.get("facilities")):
                        temp_param[k + element] = {element: {"facilities": v}}
                    del val["facilities"]
                if val:
                    temp_param[element] = {element: val}
            if element in ["files", "hosts", "users"]:
                for k, v in iteritems(val):
                    if v.get("facilities"):
                        for pk, dat in iteritems(v.get("facilities")):
                            temp_param[pk + k] = {
                                element: {
                                    "facilities": dat,
                                    self.pkey.get(element): v.get(self.pkey.get(element)),
                                },
                            }
                        del v["facilities"]
                        if len(list(v.keys())) > 1:
                            temp_param[k] = {element: v}
                    else:
                        temp_param[k] = {element: v}
        return temp_param

    def list_to_dict(self, param, op=None):
        updated_param = dict()
        if self.state == "deleted":
            if op == "have" and param:
                self.handleStates({"syslog": {"state": "disabled"}})
            updated_param == {}
        else:
            self.pkey = {
                "files": "path",
                "hosts": "hostname",
                "users": "username",
            }
            for element, val in iteritems(param):
                if element == "facilities":  # only with recursion call
                    _tem_par = {}
                    for par in val:
                        if par.get("facility") and par.get("severity"):
                            _tem_par.update({par.get("facility") + par.get("severity"): par})
                        elif par.get("facility") and par.get("protocol"):
                            _tem_par.update({par.get("facility") + par.get("protocol"): par})
                        else:
                            _tem_par.update({par.get("facility"): par})
                    return _tem_par
                elif element in ["console", "global_params", "syslog"]:
                    if element != "syslog" and val.get("facilities"):
                        val["facilities"] = self.list_to_dict(val)
                    updated_param[element] = val
                elif element in ["hosts", "users", "files"]:
                    for v in val:
                        if v.get("facilities"):
                            v["facilities"] = self.list_to_dict(v)
                        if updated_param.get(element):
                            updated_param[element].update({v.get(self.pkey.get(element)): v})
                        else:
                            updated_param[element] = {v.get(self.pkey.get(element)): v}
            return updated_param
