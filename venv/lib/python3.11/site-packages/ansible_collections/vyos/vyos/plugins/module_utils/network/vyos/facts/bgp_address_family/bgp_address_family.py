# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The vyos bgp_address_family fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.argspec.bgp_address_family.bgp_address_family import (
    Bgp_address_familyArgs,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.bgp_address_family import (
    Bgp_address_familyTemplate,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.bgp_address_family_14 import (
    Bgp_address_familyTemplate14,
)

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.vyos import get_os_version

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.utils.version import LooseVersion


class Bgp_address_familyFacts(object):
    """The vyos bgp_address_family facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Bgp_address_familyArgs.argument_spec

    def get_device_data(self, connection):
        return connection.get('show configuration commands |  match "set protocols bgp"')

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Bgp_address_family network resource

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
            data = self.get_device_data(connection)

        for resource in data.splitlines():
            if "address-family" in resource or "system-as" in resource:
                config_lines.append(re.sub("'", "", resource))

        # parse native config using the Bgp_address_family template based on version
        if LooseVersion(get_os_version(self._module)) >= LooseVersion("1.4"):
            bgp_address_family_parser = Bgp_address_familyTemplate14(lines=config_lines)
        else:
            bgp_address_family_parser = Bgp_address_familyTemplate(lines=config_lines)
        objs = bgp_address_family_parser.parse()
        if objs:
            if "address_family" in objs:
                objs["address_family"] = list(objs["address_family"].values())
                for af in objs["address_family"]:
                    if "networks" in af:
                        af["networks"] = sorted(af["networks"], key=lambda k: k["prefix"])
                    if "aggregate_address" in af:
                        af["aggregate_address"] = sorted(
                            af["aggregate_address"],
                            key=lambda k: k["prefix"],
                        )
            if "neighbors" in objs:
                objs["neighbors"] = list(objs["neighbors"].values())
                objs["neighbors"] = sorted(objs["neighbors"], key=lambda k: k["neighbor_address"])
                for neigh in objs["neighbors"]:
                    if "address_family" in neigh:
                        neigh["address_family"] = list(neigh["address_family"].values())

        ansible_facts["ansible_network_resources"].pop("bgp_address_family", None)

        params = utils.remove_empties(utils.validate_config(self.argument_spec, {"config": objs}))

        facts["bgp_address_family"] = params.get("config", [])
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
