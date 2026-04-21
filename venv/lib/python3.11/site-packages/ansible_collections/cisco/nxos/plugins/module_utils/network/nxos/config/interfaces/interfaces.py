#
# -*- coding: utf-8 -*-
# Copyright 2025 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos_interfaces config file.
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to its desired end-state is
created.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.resource_module import (
    ResourceModule,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    dict_merge,
)

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.facts import (
    Facts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.interfaces import (
    InterfacesTemplate,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.utils.utils import (
    normalize_interface,
)


class Interfaces(ResourceModule):
    """
    The nxos_interfaces config class
    """

    def __init__(self, module):
        super(Interfaces, self).__init__(
            empty_fact_val={},
            facts_module=Facts(module),
            module=module,
            resource="interfaces",
            tmplt=InterfacesTemplate(),
        )
        self.parsers = [
            "description",
            "speed",
            "mtu",
            "duplex",
            "ip_forward",
            "fabric_forwarding_anycast_gateway",
            "mac_address",
            "logging.link_status",
            "logging.trunk_status",
            "snmp.trap.link_status",
            "service_policy.input",
            "service_policy.output",
            "service_policy.type_options.qos.input",
            "service_policy.type_options.qos.output",
            "service_policy.type_options.queuing.input",
            "service_policy.type_options.queuing.output",
        ]
        if self.state not in ["parsed", "rendered"]:
            self.defaults = self.get_interface_defaults()
        else:
            # For parsed/rendered state, we assume defaults
            self.defaults = {
                "default_mode": "layer3",
                "L2_enabled": True,
            }

    def execute_module(self):
        """Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        if self.state not in ["parsed", "gathered"]:
            self.generate_commands()
            self.run_commands()
        return self.result

    def get_switchport_defaults(self):
        """Wrapper method for `_connection.get()`
        This method exists solely to allow the unit test framework to mock device connection calls.
        """
        return self._connection.get(
            "show running-config all | incl 'system default switchport'",
        )

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

        if self.state == "purged":
            self.purge(wantd, haved)
        else:
            for k, want in wantd.items():
                self._compare(want=want, have=haved.pop(k, {}))

    def _compare(self, want, have):
        """Leverages the base class `compare()` method and
        populates the list of commands to be run by comparing
        the `want` and `have` data with the `parsers` defined
        for the Interfaces network resource.
        """
        begin = len(self.commands)
        self.compare(parsers=self.parsers, want=want, have=have)

        # Handle the 'enabled' state separately
        want_enabled = want.get("enabled")
        have_enabled = have.get("enabled")
        if want_enabled is not None:
            if want_enabled != have_enabled:
                if want_enabled is True:
                    self.addcmd(want, "enabled", True)
                else:
                    self.addcmd(want, "enabled", False)
        elif not want and self.state == "overridden":
            if have_enabled is not None:
                self.addcmd(have, "enabled", False)
        elif not want and self.state == "deleted":
            if have_enabled:
                self.addcmd(have, "enabled", False)

        # Handle the 'mode' state separately
        want_mode = want.get("mode")
        have_mode = have.get("mode", self.defaults.get("default_mode"))
        if want_mode is not None:
            if want_mode != have_mode:
                if want_mode == "layer3":
                    self.addcmd(want, "mode", True)
                else:
                    if want:
                        self.addcmd(want, "mode", False)
                    elif have.get("mode"):  # can oly have layer2 as switchport no show cli
                        # handles deleted as want be blank and only
                        self.addcmd(have, "mode", False)
        elif not want and self.state == "deleted":
            if have.get("mode") and have_mode != self.defaults.get("default_mode"):
                no_cmd = True if self.defaults.get("default_mode") == "layer3" else False
                self.addcmd(have, "mode", no_cmd)

        if len(self.commands) != begin:
            self.commands.insert(begin, self._tmplt.render(want or have, "name", False))

    def purge(self, wantd, haved):
        """Handle operation for purged state"""
        if wantd:
            for k, want in wantd.items():
                have = haved.pop(k, {})
                if have:
                    self.commands.append(self._tmplt.render(have, "name", True))

    def normalize_interface_names(self, param):
        if param:
            for _k, val in param.items():
                val["name"] = normalize_interface(val["name"])
        return param

    def get_interface_defaults(self):
        """Collect user-defined-default states for 'system default switchport'
        configurations. These configurations determine default L2/L3 modes
        and enabled/shutdown states. The default values for user-defined-default
        configurations may be different for legacy platforms.
        Notes:
        - L3 enabled default state is False on N9K,N7K,N3K but True for N5K,N6K
        - Changing L2-L3 modes may change the default enabled value.
        - '(no) system default switchport shutdown' only applies to L2 interfaces.
        Run through the gathered interfaces and tag their default enabled state.
        """
        interface_defs = {}
        switchport_data = self.get_switchport_defaults()

        # Layer 2/3 mode defaults
        pat = "(no )*system default switchport$"
        default_mode = re.search(pat, switchport_data, re.MULTILINE)
        if default_mode:
            interface_defs["default_mode"] = (
                "layer3" if "no " in default_mode.groups() else "layer2"
            )

        # Interface enabled state defaults
        pat = "(no )*system default switchport shutdown$"
        default_enabled = re.search(pat, switchport_data, re.MULTILINE)
        if default_enabled:
            interface_defs["L2_enabled"] = True if "no " in default_enabled.groups() else False

        return interface_defs
