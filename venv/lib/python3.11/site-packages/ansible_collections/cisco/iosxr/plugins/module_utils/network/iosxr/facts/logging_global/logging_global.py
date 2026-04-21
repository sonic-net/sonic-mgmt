# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The iosxr logging_global fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""


from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.logging_global.logging_global import (
    Logging_globalArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.rm_templates.logging_global import (
    Logging_globalTemplate,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.utils.utils import (
    flatten_config,
)


class Logging_globalFacts(object):
    """The iosxr logging_global facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Logging_globalArgs.argument_spec

    def get_config(self, connection):
        return connection.get("show running-config logging")

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Logging_global network resource

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
            "logging archive",
            "logging tls-server",
            "logging correlator rule",
            "logging correlator ruleset",
            "logging events filter",
            "logging buffered discriminator",
            "logging monitor discriminator",
            "logging console discriminator",
        ]

        for x in flatten_context_list:
            data = flatten_config(data, x)
        # parse native config using the Logging_global template
        logging_global_parser = Logging_globalTemplate(
            lines=data.splitlines(),
            module=self._module,
        )
        objs = logging_global_parser.parse()
        objs["tls_servers"] = list(objs.get("tls_servers", {}).values())
        if objs.get("correlator"):
            objs["correlator"]["rules"] = list(
                objs.get("correlator", {}).get("rules", {}).values(),
            )
            objs["correlator"]["rule_sets"] = list(
                objs.get("correlator", {}).get("rule_sets", {}).values(),
            )
            for i, x in enumerate(objs["correlator"]["rule_sets"]):
                if None in x["rulename"]:
                    objs["correlator"]["rule_sets"][i]["rulename"].remove(None)

        ansible_facts["ansible_network_resources"].pop("logging_global", None)

        params = utils.remove_empties(
            logging_global_parser.validate_config(
                self.argument_spec,
                {"config": objs},
                redact=True,
            ),
        )

        facts["logging_global"] = params.get("config", {})
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
