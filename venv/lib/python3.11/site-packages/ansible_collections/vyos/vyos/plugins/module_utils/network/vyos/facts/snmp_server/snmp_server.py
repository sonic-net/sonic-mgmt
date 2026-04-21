# -*- coding: utf-8 -*-
# Copyright 2022 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The vyos snmp_server fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

import re

from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.argspec.snmp_server.snmp_server import (
    Snmp_serverArgs,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.snmp_server import (
    Snmp_serverTemplate,
)


class Snmp_serverFacts(object):
    """The vyos snmp_server facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Snmp_serverArgs.argument_spec

    def get_config(self, connection):
        return connection.get("show configuration commands | grep snmp")

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
        config_lines = []

        if not data:
            data = self.get_config(connection)
        for resource in data.splitlines():
            config_lines.append(re.sub("'", "", resource))

        # parse native config using the Snmp_server template
        snmp_server_parser = Snmp_serverTemplate(lines=config_lines, module=self._module)
        objs = snmp_server_parser.parse()
        if objs:
            if "communities" in objs:
                for k in objs["communities"].values():
                    for param, val in iteritems(k):
                        if param in ["clients", "networks"]:
                            if None in val:
                                val.remove(None)
                            val.sort()

                objs["communities"] = sorted(
                    list(objs["communities"].values()),
                    key=lambda k, sk="name": k[sk],
                )
            if "listen_addresses" in objs:
                objs["listen_addresses"] = sorted(
                    list(objs["listen_addresses"].values()),
                    key=lambda k, sk="address": k[sk],
                )
            if "snmp_v3" in objs:
                if "groups" in objs["snmp_v3"]:
                    objs["snmp_v3"]["groups"] = sorted(
                        list(objs["snmp_v3"]["groups"].values()),
                        key=lambda k, sk="group": k[sk],
                    )
                if "trap_targets" in objs["snmp_v3"]:
                    objs["snmp_v3"]["trap_targets"] = sorted(
                        list(objs["snmp_v3"]["trap_targets"].values()),
                        key=lambda k, sk="address": k[sk],
                    )
                if "users" in objs["snmp_v3"]:
                    objs["snmp_v3"]["users"] = sorted(
                        list(objs["snmp_v3"]["users"].values()),
                        key=lambda k, sk="user": k[sk],
                    )
                if "views" in objs["snmp_v3"]:
                    objs["snmp_v3"]["views"] = sorted(
                        list(objs["snmp_v3"]["views"].values()),
                        key=lambda k, sk="view": k[sk],
                    )
        else:
            objs = {}

        ansible_facts["ansible_network_resources"].pop("snmp_server", None)

        params = utils.remove_empties(
            snmp_server_parser.validate_config(self.argument_spec, {"config": objs}, redact=True),
        )

        facts["snmp_server"] = params.get("config", {})
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
