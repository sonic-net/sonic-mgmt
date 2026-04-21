# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos vrf_address_family fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.vrf_address_family.vrf_address_family import (
    Vrf_address_familyArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.vrf_address_family import (
    Vrf_address_familyTemplate,
)


class Vrf_address_familyFacts(object):
    """The nxos vrf_address_family facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Vrf_address_familyArgs.argument_spec

    def get_config(self, connection):
        """Get the configuration from the device"""

        return connection.get("show running-config | section ^vrf")

    def _flatten_config(self, data):
        """Flatten contexts in the vrf address family
            running-config for easier parsing.
        :param data: string running-config
        :returns: flattened running config
        """

        dataLines = data.split("\n")
        curData = ""

        for line in dataLines:
            if "vrf context" in line:
                curData = line
            elif "address-family" in line:
                dataLines[dataLines.index(line)] = curData + " " + line

        return "\n".join(dataLines)

    def _parse_vrf_af(self, data: dict):
        """Parse the vrf address family data
        :param data: dict of vrf address family data
        :returns: argspec compliant list
        """
        if not data:
            return []

        vrf_lists = list(data.values())
        for item in vrf_lists:
            if "address_families" in item:
                item["address_families"] = list(item["address_families"].values())
        return vrf_lists

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Vrf_address_family network resource

        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf

        :rtype: dictionary
        :returns: facts
        """
        facts = {}
        vrfObjs = []

        if not data:
            data = self.get_config(connection)

        flattened_data = self._flatten_config(data)

        # parse native config using the Vrf_address_family template
        vrf_address_family_parser = Vrf_address_familyTemplate(
            lines=flattened_data.splitlines(),
            module=self._module,
        )
        parsed_data = vrf_address_family_parser.parse()
        vrfObjs = self._parse_vrf_af(parsed_data)

        ansible_facts["ansible_network_resources"].pop("vrf_address_family", None)

        params = utils.remove_empties(
            vrf_address_family_parser.validate_config(
                self.argument_spec,
                {"config": vrfObjs},
                redact=True,
            ),
        )
        facts["vrf_address_family"] = params.get("config", [])
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
