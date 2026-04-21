# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The vyos ntp fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.argspec.ntp_global.ntp_global import (
    Ntp_globalArgs,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.ntp_global import (
    NtpTemplate,
)


class Ntp_globalFacts(object):
    """The vyos ntp facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Ntp_globalArgs.argument_spec

    def get_config(self, connection):
        return connection.get("show configuration commands | grep ntp")

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Ntp network resource

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
        # parse native config using the Ntp template
        ntp_parser = NtpTemplate(lines=config_lines, module=self._module)

        objs = ntp_parser.parse()

        if objs:
            if "allow_clients" in objs:
                objs["allow_clients"] = sorted(list(objs["allow_clients"]))

            if "listen_addresses" in objs:
                objs["listen_addresses"] = sorted(list(objs["listen_addresses"]))

            """ if "options" in objs["servers"].values():
                val = objs["servers"].values()
                val["options"] = sorted(val["options"]) """

            if "servers" in objs:
                objs["servers"] = list(objs["servers"].values())
                objs["servers"] = sorted(objs["servers"], key=lambda k: k["server"])
                for i in objs["servers"]:
                    if "options" in i:
                        i["options"] = sorted(list(i["options"]))

        ansible_facts["ansible_network_resources"].pop("ntp_global", None)

        params = utils.remove_empties(
            ntp_parser.validate_config(self.argument_spec, {"config": objs}, redact=True),
        )

        if params.get("config"):
            facts["ntp_global"] = params["config"]
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
