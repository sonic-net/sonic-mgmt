# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos vrf_global fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""


from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.vrf_global.vrf_global import (
    Vrf_globalArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.vrf_global import (
    Vrf_globalTemplate,
)


class Vrf_globalFacts(object):
    """The nxos vrf_global facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Vrf_globalArgs.argument_spec

    def get_config(self, connection):
        """Get the configuration from the device"""

        return connection.get("show running-config | section ^vrf")

    def _dict_to_list(self, data):
        """Convert a dictionary to a list of dictionaries"""
        objs = dict()
        objs["vrfs"] = list(data.get("vrfs", {}).values()) if "vrfs" in data else []

        for item in objs["vrfs"]:
            name_server = item.get("ip", {}).get("name_server", {}).get("address_list", [])
            if name_server:
                item["ip"]["name_server"]["address_list"] = name_server.split()
        return objs

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Vrf_global network resource

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

        # parse native config using the Vrf_global template
        vrf_global_parser = Vrf_globalTemplate(lines=data.splitlines(), module=self._module)
        objs = vrf_global_parser.parse()

        facts_output = self._dict_to_list(objs)

        ansible_facts["ansible_network_resources"].pop("vrf_global", None)

        params = vrf_global_parser.validate_config(
            self.argument_spec,
            {"config": facts_output},
            redact=True,
        )
        params = utils.remove_empties(params)
        facts["vrf_global"] = params.get("config", {})
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
