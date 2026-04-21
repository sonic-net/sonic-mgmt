# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos ntp_global fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.ntp_global.ntp_global import (
    Ntp_globalArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.ntp_global import (
    Ntp_globalTemplate,
)


class Ntp_globalFacts(object):
    """The nxos ntp_global facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Ntp_globalArgs.argument_spec

    def get_config(self, connection):
        """Wrapper method for `connection.get()`
        This method exists solely to allow the unit test framework to mock device connection calls.
        """
        return connection.get("show running-config ntp")

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Ntp_global network resource

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

        # parse native config using the Ntp_global template
        ntp_global_parser = Ntp_globalTemplate(lines=data.splitlines(), module=self._module)
        objs = ntp_global_parser.parse()

        if "access_group" in objs:
            for x in ["peer", "query_only", "serve", "serve_only"]:
                if x in objs["access_group"]:
                    objs["access_group"][x] = sorted(
                        objs["access_group"][x],
                        key=lambda k: k["access_list"],
                    )

        pkey = {
            "authentication_keys": "id",
            "peers": "peer",
            "servers": "server",
            "trusted_keys": "key_id",
        }

        for x in pkey.keys():
            if x in objs:
                objs[x] = sorted(objs[x], key=lambda k: k[pkey[x]])

        ansible_facts["ansible_network_resources"].pop("ntp_global", None)

        params = utils.remove_empties(
            ntp_global_parser.validate_config(self.argument_spec, {"config": objs}, redact=True),
        )

        facts["ntp_global"] = params.get("config", {})
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
