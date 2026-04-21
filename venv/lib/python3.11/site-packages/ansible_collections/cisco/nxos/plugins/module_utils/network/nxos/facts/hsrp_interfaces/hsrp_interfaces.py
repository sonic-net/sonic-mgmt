# -*- coding: utf-8 -*-
# Copyright 2025 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos hsrp_interfaces fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.hsrp_interfaces.hsrp_interfaces import (
    Hsrp_interfacesArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.hsrp_interfaces import (
    Hsrp_interfacesTemplate,
)


class Hsrp_interfacesFacts(object):
    """The nxos hsrp_interfaces facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Hsrp_interfacesArgs.argument_spec

    def get_hsrp_data(self, connection):
        return connection.get("show running-config | section ^interface")

    def flatten_config(self, config):
        dataLines = config.split("\n")
        finalConfig = []
        hsrp_line = ""
        for line in dataLines:
            if (
                line.startswith("  hsrp ")
                and len(line.split()) == 2
                and (line.split()[1]).isdigit()
                or line.startswith("interface ")
            ):
                if line.startswith("  hsrp "):
                    hsrp_line = line
                finalConfig.append(line)
                if line.startswith("interface "):
                    hsrp_line = ""
            else:
                if not line.startswith("hsrp "):
                    finalConfig.append(hsrp_line + line)
        return "\n".join(finalConfig)

    def handle_grp_options(self, objs):

        hsrp_objs = []
        for cf in objs:
            hsrp_conf = []

            intf_conf = {
                "name": cf.get("name"),
            }
            if cf.get("standby"):
                intf_conf["standby"] = cf.get("standby")

            for grp, standby_options in cf.items():
                if grp.startswith("group_"):
                    hsrp_conf.append(standby_options)
            if hsrp_conf:
                intf_conf["standby_options"] = hsrp_conf
            hsrp_objs.append(intf_conf)
        return hsrp_objs

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Hsrp_interfaces network resource

        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf

        :rtype: dictionary
        :returns: facts
        """
        facts = {}
        objs = []

        if not data:
            data = self.get_hsrp_data(connection)

        data = self.flatten_config(data)
        # parse native config using the Hsrp_interfaces template
        hsrp_interfaces_parser = Hsrp_interfacesTemplate(
            lines=data.splitlines(),
            module=self._module,
        )
        objs = list(hsrp_interfaces_parser.parse().values())

        hsrp_objs = self.handle_grp_options(objs)

        ansible_facts["ansible_network_resources"].pop("hsrp_interfaces", None)
        params = utils.remove_empties(
            hsrp_interfaces_parser.validate_config(
                self.argument_spec,
                {"config": hsrp_objs},
                redact=True,
            ),
        )
        facts["hsrp_interfaces"] = params.get("config", [])
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
