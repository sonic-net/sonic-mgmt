# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The eos bgp_address_family fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

import re

from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.arista.eos.plugins.module_utils.network.eos.argspec.bgp_address_family.bgp_address_family import (
    Bgp_afArgs,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.rm_templates.bgp_address_family import (
    Bgp_afTemplate,
)


class Bgp_afFacts(object):
    """The eos bgp_address_family facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Bgp_afArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def get_config(self, connection):
        """Wrapper method for `connection.get()`
        This method exists solely to allow the unit test framework to mock device connection calls.
        """
        return connection.get("show running-config | section router\\sbgp ")

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Bgp_af network resource

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

        # remove global configs from bgp_address_family
        bgp_af_config = []
        vrf_set = ""
        start = False
        for bgp_line in data.splitlines():
            if "router bgp" in bgp_line:
                bgp_af_config.append(bgp_line)
            vrf_present = re.search(r"vrf\s\S+", bgp_line)
            if vrf_present:
                vrf_set = vrf_present.group(0)
            if start:
                bgp_af_config.append(bgp_line)
            if "address-family" in bgp_line:
                af_line = vrf_set + bgp_line
                bgp_af_config.append(af_line)
                start = True
            if start and "!" in bgp_line:
                start = False

        # parse native config using the Bgp_af template
        bgp_af_parser = Bgp_afTemplate(lines=bgp_af_config)
        objs = bgp_af_parser.parse()
        if objs:
            if "address_family" in objs:
                objs["address_family"] = list(objs["address_family"].values())
                for af in objs["address_family"]:
                    if "neighbor" in af:
                        af["neighbor"] = list(af["neighbor"].values())
                    if "network" in af:
                        af["network"] = list(af["network"].values())
                        af["network"] = sorted(
                            af["network"],
                            key=lambda k: k["address"],
                        )

        ansible_facts["ansible_network_resources"].pop(
            "bgp_address_family",
            None,
        )

        params = utils.remove_empties(
            utils.validate_config(self.argument_spec, {"config": objs}),
        )

        facts["bgp_address_family"] = params.get("config", [])
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
