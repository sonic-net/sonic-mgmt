# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos ospf_interfaces fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.ospf_interfaces.ospf_interfaces import (
    Ospf_interfacesArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.ospf_interfaces import (
    Ospf_interfacesTemplate,
)


class Ospf_interfacesFacts(object):
    """The nxos ospf_interfaces facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Ospf_interfacesArgs.argument_spec

    def get_config(self, connection):
        """Wrapper method for `connection.get()`
        This method exists solely to allow the unit test framework to mock device connection calls.
        """
        return connection.get("show running-config | section '^interface'")

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Ospf_interfaces network resource

        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf

        :rtype: dictionary
        :returns: facts
        """
        facts = {}
        objs = []

        if not data:
            data = self.get_config(connection)

        # parse native config using the Ospf_interfaces template
        ospf_interfaces_parser = Ospf_interfacesTemplate(
            lines=data.splitlines(),
            module=self._module,
        )
        objs = list(ospf_interfaces_parser.parse().values())
        if objs:
            for item in objs:
                item["address_family"] = list(item["address_family"].values())
                if "address_family" in item:
                    for af in item["address_family"]:
                        if af.get("processes"):
                            af["processes"] = list(af["processes"].values())
                        if af.get("multi_areas"):
                            af["multi_areas"].sort()
                    item["address_family"] = sorted(item["address_family"], key=lambda i: i["afi"])

            objs = sorted(
                objs,
                key=lambda i: [
                    int(k) if k.isdigit() else k for k in i["name"].replace(".", "/").split("/")
                ],
            )

        ansible_facts["ansible_network_resources"].pop("ospf_interfaces", None)

        params = utils.remove_empties(
            ospf_interfaces_parser.validate_config(
                self.argument_spec,
                {"config": objs},
                redact=True,
            ),
        )

        facts["ospf_interfaces"] = params.get("config", [])
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
