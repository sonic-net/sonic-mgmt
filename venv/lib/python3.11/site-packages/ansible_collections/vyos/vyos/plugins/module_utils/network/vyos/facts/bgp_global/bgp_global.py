# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The vyos bgp_global fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.argspec.bgp_global.bgp_global import (
    Bgp_globalArgs,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.bgp_global import (
    Bgp_globalTemplate,
)

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.bgp_global_14 import (
    Bgp_globalTemplate14,
)

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.vyos import get_os_version

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.utils.version import LooseVersion


class Bgp_globalFacts(object):
    """The vyos bgp_global facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Bgp_globalArgs.argument_spec

    def get_device_data(self, connection):
        return connection.get('show configuration commands |  match "set protocols bgp"')

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Bgp_global network resource

        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf

        :rtype: dictionary
        :returns: facts
        """
        facts = {}
        objs = {}
        config_lines = []

        if not data:
            data = self.get_device_data(connection)

        for resource in data.splitlines():
            if "address-family" not in resource:
                config_lines.append(re.sub("'", "", resource))

        if LooseVersion(get_os_version(self._module)) >= LooseVersion("1.4"):
            bgp_global_parser = Bgp_globalTemplate14(lines=config_lines, module=self._module)
        else:
            bgp_global_parser = Bgp_globalTemplate(lines=config_lines, module=self._module)

        objs = bgp_global_parser.parse()

        if "neighbor" in objs:
            objs["neighbor"] = list(objs["neighbor"].values())
            objs["neighbor"] = sorted(objs["neighbor"], key=lambda k: k["address"])
        if "network" in objs:
            objs["network"] = sorted(objs["network"], key=lambda k: k["address"])
        if "aggregate_address" in objs:
            objs["aggregate_address"] = sorted(objs["aggregate_address"], key=lambda k: k["prefix"])

        ansible_facts["ansible_network_resources"].pop("bgp_global", None)

        params = utils.remove_empties(
            bgp_global_parser.validate_config(self.argument_spec, {"config": objs}, redact=True),
        )

        facts["bgp_global"] = params.get("config", [])
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
