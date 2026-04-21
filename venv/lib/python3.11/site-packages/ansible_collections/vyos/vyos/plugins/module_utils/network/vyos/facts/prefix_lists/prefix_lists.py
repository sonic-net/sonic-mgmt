# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The vyos prefix_lists fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""


from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.argspec.prefix_lists.prefix_lists import (
    Prefix_listsArgs,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.prefix_lists import (
    Prefix_listsTemplate,
)


class Prefix_listsFacts(object):
    """The vyos prefix_lists facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Prefix_listsArgs.argument_spec

    def get_config(self, connection):
        return connection.get("show configuration commands | grep prefix-list")

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Prefix_lists network resource

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

        # parse native config using the Prefix_lists template
        prefix_lists_parser = Prefix_listsTemplate(lines=data.splitlines(), module=self._module)

        objs = prefix_lists_parser.parse()
        objs = sorted(
            list(objs.values()),
            key=lambda k: k["afi"],
        )

        if objs:
            for item in objs:
                item["prefix_lists"] = sorted(
                    list(item["prefix_lists"].values()),
                    key=lambda k: k["name"],
                )
                for pl in item["prefix_lists"]:
                    if "entries" in pl:
                        pl["entries"] = sorted(
                            list(pl["entries"].values()),
                            key=lambda k: k["sequence"],
                        )

        ansible_facts["ansible_network_resources"].pop("prefix_lists", None)

        params = utils.remove_empties(
            prefix_lists_parser.validate_config(self.argument_spec, {"config": objs}, redact=True),
        )

        if params.get("config"):
            facts["prefix_lists"] = params["config"]
        else:
            facts["prefix_lists"] = []
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
