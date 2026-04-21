#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The vyos_ntp config file.
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
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.ntp_global import (
    NtpTemplate,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.utils.version import (
    LooseVersion,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.vyos import get_os_version


class Ntp_global(ResourceModule):
    """
    The vyos_ntp config class
    """

    def __init__(self, module):
        super(Ntp_global, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="ntp_global",
            tmplt=NtpTemplate(),
        )
        self.parsers = [
            "allow_clients",
            "listen_addresses",
            "server",
            "options",
            "allow_clients_delete",
            "listen_addresses_delete",
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

        if LooseVersion(get_os_version(self._module)) >= LooseVersion("1.4"):
            path = "service"
            ac = "allow-client"
        else:
            path = "system"
            ac = "allow-clients"

        self._tmplt.set_ntp_path(path)
        self._tmplt.set_ntp_ac(ac)

        wantd = self._ntp_list_to_dict(self.want)
        haved = self._ntp_list_to_dict(self.have)

        # if state is merged, merge want onto have and then compare
        if self.state == "merged":
            wantd = dict_merge(haved, wantd)

        # if state is deleted, empty out wantd and set haved to wantd
        if self.state == "deleted":
            haved = {k: v for k, v in iteritems(haved) if k in wantd or not wantd}
            wantd = {}

            commandlist = self._commandlist(haved)
            servernames = self._servernames(haved)
            # removing the servername and commandlist from the list after deleting it from haved
            # iterate through the top-level items to delete
            for k, have in iteritems(haved):
                if k not in wantd:
                    for hk, hval in iteritems(have):
                        if hk == "allow_clients" and hk in commandlist:
                            self.commands.append(
                                self._tmplt.render({"": hk}, "allow_clients_delete", True),
                            )
                            commandlist.remove(hk)
                        elif hk == "listen_addresses" and hk in commandlist:
                            self.commands.append(
                                self._tmplt.render({"": hk}, "listen_addresses_delete", True),
                            )
                            commandlist.remove(hk)
                        elif hk == "server" and have["server"] in servernames:
                            self._compareoverride(want={}, have=have)
                            servernames.remove(have["server"])
            # if everything is deleted add the delete command for {path} ntp
            # this should be equiv: servernames == [] and commandlist == ["server"]:
            if wantd == {} and haved != {}:
                self.commands.append(
                    self._tmplt.render({}, "service_delete", True),
                )

        # remove existing config for overridden and replaced
        # Getting the list of the server names from haved
        #   to avoid the duplication of overridding/replacing the servers
        if self.state in ["overridden", "replaced"]:
            commandlist = self._commandlist(haved)
            servernames = self._servernames(haved)

            for k, have in iteritems(haved):
                if k not in wantd:
                    if "server" not in have:
                        self._compareoverride(want={}, have=have)
                        # removing the servername from the list after deleting it from haved
                    elif have["server"] in servernames:
                        self._compareoverride(want={}, have=have)
                        servernames.remove(have["server"])

        for k, want in iteritems(wantd):
            self._compare(want=want, have=haved.pop(k, {}))

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Ntp network resource.
        """
        if "options" in want:
            self.compare(parsers="options", want=want, have=have)
        else:
            self.compare(parsers=self.parsers, want=want, have=have)

    def _compareoverride(self, want, have):
        # do not delete configuration with options level
        for i, val in iteritems(have):
            if i == "options":
                pass
            else:
                self.compare(parsers=i, want={}, have=have)

    def _ntp_list_to_dict(self, entry):
        servers_dict = {}
        for k, data in iteritems(entry):
            if k == "servers":
                for value in data:
                    if "options" in value:
                        result = self._serveroptions_list_to_dict(value)
                        for res, resvalue in iteritems(result):
                            servers_dict.update({res: resvalue})
                    else:
                        servers_dict.update({value["server"]: value})
            else:
                for value in data:
                    servers_dict.update({"ip_" + value: {k: value}})
        return servers_dict

    def _serveroptions_list_to_dict(self, entry):
        serveroptions_dict = {}
        for Opk, Op in iteritems(entry):
            if Opk == "options":
                for val in Op:
                    dict = {}
                    dict.update({"server": entry["server"]})
                    dict.update({Opk: val})
                    serveroptions_dict.update({entry["server"] + "_" + val: dict})
        return serveroptions_dict

    def _commandlist(self, haved):
        commandlist = []
        for k, have in iteritems(haved):
            for ck, cval in iteritems(have):
                if ck != "options" and ck not in commandlist:
                    commandlist.append(ck)
        return commandlist

    def _servernames(self, haved):
        servernames = []
        for k, have in iteritems(haved):
            for sk, sval in iteritems(have):
                if sk != "options" and sval not in servernames:
                    servernames.append(sval)
        return servernames
