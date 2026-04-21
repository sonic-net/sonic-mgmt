# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The eos logging_global fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.arista.eos.plugins.module_utils.network.eos.argspec.logging_global.logging_global import (
    Logging_globalArgs,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.rm_templates.logging_global import (
    Logging_globalTemplate,
)


class Logging_globalFacts(object):
    """The eos logging_global facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Logging_globalArgs.argument_spec

    def get_config(self, connection):
        """Wrapper method for `connection.get()`
        This method exists solely to allow the unit test framework to mock device connection calls.
        """
        return connection.get("show running-config | section logging")

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Logging_global network resource

        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf

        :rtype: dictionary
        :returns: facts
        """
        facts = {}
        objs = {}

        if not data:
            data = self.get_config(connection)

        # parse native config using the Prefix_lists template
        logging_parser = Logging_globalTemplate(
            lines=data.splitlines(),
            module=self._module,
        )
        objs = logging_parser.parse()
        if objs:
            if "hosts" in objs:
                objs["hosts"] = sorted(
                    list(objs["hosts"].values()),
                    key=lambda k, sk="name": k[sk],
                )
            if "vrfs" in objs:
                for k, v in iteritems(objs["vrfs"]):
                    if "hosts" in v:
                        v["hosts"] = sorted(
                            list(v["hosts"].values()),
                            key=lambda k, sk="name": k[sk],
                        )
                objs["vrfs"] = sorted(
                    list(objs["vrfs"].values()),
                    key=lambda k, sk="name": k[sk],
                )
        else:
            objs = {}
        ansible_facts["ansible_network_resources"].pop("logging_global", None)

        params = utils.remove_empties(
            logging_parser.validate_config(
                self.argument_spec,
                {"config": objs},
                redact=True,
            ),
        )

        facts["logging_global"] = params.get("config", {})
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
