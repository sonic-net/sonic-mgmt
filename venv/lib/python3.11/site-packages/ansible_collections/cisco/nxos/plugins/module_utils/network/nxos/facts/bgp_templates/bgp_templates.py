# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos bgp_templates fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.bgp_templates.bgp_templates import (
    Bgp_templatesArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.bgp_templates import (
    Bgp_templatesTemplate,
)


class Bgp_templatesFacts(object):
    """The nxos bgp_templates facts class"""

    def __init__(self, module):
        self._module = module
        self.argument_spec = Bgp_templatesArgs.argument_spec

    def get_config(self, connection):
        """Wrapper method for `connection.get()`
        This method exists solely to allow the unit test framework to mock device connection calls.
        """
        as_number = connection.get("show running-config | include 'router bgp'")
        templates = connection.get("show running-config | section 'template'")

        return as_number + "\n" + templates

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Bgp_templates network resource

        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf

        :rtype: dictionary
        :returns: facts
        """
        facts = {}

        if not data:
            data = self.get_config(connection)

        data = self._flatten_config(data)

        # parse native config using the Bgp_templates template
        bgp_templates_parser = Bgp_templatesTemplate(lines=data, module=self._module)
        parsed = bgp_templates_parser.parse()

        objs = {}
        # pop top-level keys and assign values to them
        for k, v in parsed.items():
            if k == "as_number":
                objs[k] = v
            else:
                objs[k] = list(v.values())
                for x in objs[k]:
                    if "address_family" in x:
                        x["address_family"] = list(x["address_family"].values())

        for nbr in objs.get("neighbor", []):
            for af in nbr.get("address_family", []):
                std = af.pop("send_community_std", False)
                ext = af.pop("send_community_ext", False)
                if std and ext:
                    af["send_community"] = "both"
                elif std:
                    af["send_community"] = "standard"
                elif ext:
                    af["send_community"] = "extended"

        ansible_facts["ansible_network_resources"].pop("bgp_templates", None)

        params = utils.remove_empties(
            bgp_templates_parser.validate_config(self.argument_spec, {"config": objs}, redact=True),
        )

        facts["bgp_templates"] = params.get("config", {})
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts

    def _flatten_config(self, data):
        flattened_data = []
        cur_peer = ""
        data = data.split("\n")

        for x in data:
            x = x.strip()
            if x.startswith("template peer"):
                cur_peer = x + " "
            elif x.startswith("address-family"):
                # a template peer <> line has to preceed AF line
                x = cur_peer + x
            flattened_data.append(x)

        return flattened_data
