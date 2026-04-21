# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos logging_global fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.logging_global.logging_global import (
    Logging_globalArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.logging_global import (
    Logging_globalTemplate,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.utils.utils import (
    get_logging_sevmap,
)


class Logging_globalFacts(object):
    """The nxos logging_global facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Logging_globalArgs.argument_spec

    def get_config(self, connection):
        """Wrapper method for `connection.get()`
        This method exists solely to allow the unit test framework to mock device connection calls.
        """
        return connection.get("show running-config | include logging")

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
        sev_map = get_logging_sevmap()

        if not data:
            data = self.get_config(connection)

        # parse native config using the Logging_global template
        logging_global_parser = Logging_globalTemplate(lines=data.splitlines(), module=self._module)
        objs = logging_global_parser.parse()

        if objs:
            for k in ("console", "history", "logfile", "module", "monitor"):
                if "severity" in objs.get(k, {}):
                    objs[k]["severity"] = sev_map[objs[k]["severity"]]
            # pre-sort list of dictionaries
            pkey = {"hosts": "host", "facilities": "facility"}
            for x in ("hosts", "facilities"):
                if x in objs:
                    for item in objs[x]:
                        if "severity" in item:
                            item["severity"] = sev_map[item["severity"]]
                    objs[x] = sorted(objs[x], key=lambda k: k[pkey[x]])

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
