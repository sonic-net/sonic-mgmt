# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The iosxr bgp_templates fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.bgp_templates.bgp_templates import (
    Bgp_templatesArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.rm_templates.bgp_templates import (
    Bgp_templatesTemplate,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.utils.utils import (
    flatten_config,
)


class Bgp_templatesFacts(object):
    """The iosxr bgp_templates facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Bgp_templatesArgs.argument_spec

    def get_config(self, connection):
        return connection.get("show running-config router bgp")

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Bgp_templates network resource

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
        data = flatten_config(data, "neighbor-group")
        # parse native config using the Bgp_templates template
        bgp_templates_parser = Bgp_templatesTemplate(lines=data.splitlines(), module=self._module)
        objs = bgp_templates_parser.parse()
        if objs:
            objs["neighbor"] = self._post_parse(objs).get(
                "neighbor",
                [],
            )
        ansible_facts["ansible_network_resources"].pop("bgp_templates", None)

        params = utils.remove_empties(
            bgp_templates_parser.validate_config(self.argument_spec, {"config": objs}, redact=True),
        )

        facts["bgp_templates"] = params.get("config", {})
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts

    def _post_parse(self, data):
        """Converts the intermediate data structure
            to valid format as per argspec.
        :param obj: dict
        """
        if "neighbor" in data:
            data["neighbor"] = sorted(
                list(data["neighbor"].values()),
                key=lambda k, s="name": k[s],
            )
            for nbrg in data["neighbor"]:
                if nbrg.get("address_family"):
                    nbrg["address_family"] = list(nbrg["address_family"].values())
        return data
