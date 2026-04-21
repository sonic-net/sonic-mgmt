# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The iosxr ntp_global fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.ntp_global.ntp_global import (
    Ntp_globalArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.rm_templates.ntp_global import (
    Ntp_globalTemplate,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.utils.utils import (
    flatten_config,
)


class Ntp_globalFacts(object):
    """The iosxr ntp_global facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Ntp_globalArgs.argument_spec

    def get_config(self, connection):
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

        flatten_context_list = ["interface", "ntp"]

        for x in flatten_context_list:
            data = flatten_config(data, x)
        # parse native config using the Ntp_global template
        ntp_global_parser = Ntp_globalTemplate(
            lines=data.splitlines(),
            module=self._module,
        )
        objs = ntp_global_parser.parse()
        if "access_group" in objs:
            objs["access_group"]["vrfs"] = list(
                objs.get("access_group", {}).get("vrfs", {}).values(),
            )
            objs["access_group"]["vrfs"] = sorted(
                objs["access_group"]["vrfs"],
                key=lambda k: k["name"],
            )
        if "interfaces" in objs:
            objs["interfaces"] = list(objs.get("interfaces", {}).values())
        if "peers" in objs:
            objs["peers"] = list(objs.get("peers", {}).values())
        if "servers" in objs:
            objs["servers"] = list(objs.get("servers", {}).values())
        if "source_vrfs" in objs:
            objs["source_vrfs"] = list(objs.get("source_vrfs", {}).values())

        pkey = {
            "authentication_keys": "id",
            "peers": "peer",
            "servers": "server",
            "trusted_keys": "key_id",
            "source_vrfs": "name",
            "interfaces": "name",
        }

        for x in pkey.keys():
            if x in objs:
                objs[x] = sorted(objs[x], key=lambda k: k[pkey[x]])

        ansible_facts["ansible_network_resources"].pop("ntp_global", None)

        params = utils.remove_empties(
            ntp_global_parser.validate_config(
                self.argument_spec,
                {"config": objs},
                redact=True,
            ),
        )

        facts["ntp_global"] = params.get("config", {})
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
