# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The iosxr snmp_server fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.snmp_server.snmp_server import (
    Snmp_serverArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.rm_templates.snmp_server import (
    Snmp_serverTemplate,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.utils.utils import (
    flatten_config,
)


class Snmp_serverFacts(object):
    """The iosxr snmp_server facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Snmp_serverArgs.argument_spec

    def get_config(self, connection):
        return connection.get("show running-config snmp-server")

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Snmp_server network resource

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

        flatten_context_list = [
            "snmp-server vrf",
            "snmp-server mib bulkstat schema",
            "snmp-server mib bulkstat transfer-id",
            "snmp-server correlator rule",
            "snmp-server interface",
            "snmp-server correlator rule",
            "snmp-server correlator ruleset",
        ]

        for x in flatten_context_list:
            data = flatten_config(data, x)
        # parse native config using the Snmp_server template
        snmp_server_parser = Snmp_serverTemplate(
            lines=data.splitlines(),
            module=self._module,
        )
        objs = snmp_server_parser.parse()

        dict_to_list = [
            "context",
            "mib_object_lists",
            "mib_schema",
            "mib_bulkstat_transfer_ids",
            "vrfs",
            "interfaces",
        ]
        for i in dict_to_list:
            if i in objs:
                objs[i] = list(objs[i].values())
                if i == "vrfs":
                    for j in objs[i]:
                        j["hosts"].remove({})
                        j["context"] = list(j["context"].values())

        ansible_facts["ansible_network_resources"].pop("snmp_server", None)

        params = utils.remove_empties(
            snmp_server_parser.validate_config(
                self.argument_spec,
                {"config": objs},
                redact=True,
            ),
        )
        facts["snmp_server"] = params.get("config", {})
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
