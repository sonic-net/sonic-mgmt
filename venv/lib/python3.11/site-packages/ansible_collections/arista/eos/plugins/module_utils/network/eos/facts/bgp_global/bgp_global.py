# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The eos bgp_global fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.arista.eos.plugins.module_utils.network.eos.argspec.bgp_global.bgp_global import (
    Bgp_globalArgs,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.rm_templates.bgp_global import (
    Bgp_globalTemplate,
)


class Bgp_globalFacts(object):
    """The eos bgp_global facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Bgp_globalArgs.argument_spec

    def get_config(self, connection):
        """Wrapper method for `connection.get()`
        This method exists solely to allow the unit test framework to mock device connection calls.
        """
        return connection.get("show running-config | section router\\sbgp ")

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Bgp_global network resource

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

        # remove address_family configs from bgp_global
        bgp_global_config = []
        start = False
        self._af = False
        not_bgp = False
        for bgp_line in data.splitlines():
            if "router " in bgp_line:
                # Skip other protocol configs like router ospf etc
                if "router bgp" not in bgp_line:
                    not_bgp = True
                    continue
                not_bgp = False
            if not start and not not_bgp:
                bgp_global_config.append(bgp_line)
            if "address-family" in bgp_line:
                start = True
                self._af = True
            if start and "!" in bgp_line:
                start = False

        # parse native config using the Bgp_global template
        bgp_global_parser = Bgp_globalTemplate(
            lines=bgp_global_config,
            module=self._module,
        )
        objs = bgp_global_parser.parse()

        if objs:
            global_vals = objs.get("vrfs", {}).pop("vrf_", {})
            for key, value in iteritems(global_vals):
                objs[key] = value

            if "vrfs" in objs:
                objs["vrfs"] = list(objs["vrfs"].values())
                for vrf in objs["vrfs"]:
                    if "neighbor" in vrf:
                        vrf["neighbor"] = list(vrf["neighbor"].values())
                    if "network" in vrf:
                        vrf["network"] = list(vrf["network"].values())
                        vrf["network"] = sorted(
                            vrf["network"],
                            key=lambda k: k["address"],
                        )
                    if "aggregate_address" in vrf:
                        vrf["aggregate_address"] = sorted(
                            vrf["aggregate_address"],
                            key=lambda k: k["address"],
                        )

            if "neighbor" in objs:
                objs["neighbor"] = list(objs["neighbor"].values())

            if "network" in objs:
                objs["network"] = list(objs["network"].values())
                objs["network"] = sorted(
                    objs["network"],
                    key=lambda k: k["address"],
                )
            if "aggregate_address" in objs:
                objs["aggregate_address"] = sorted(
                    objs["aggregate_address"],
                    key=lambda k: k["address"],
                )

        ansible_facts["ansible_network_resources"].pop("bgp_global", None)

        params = utils.remove_empties(
            bgp_global_parser.validate_config(
                self.argument_spec,
                {"config": objs},
                redact=True,
            ),
        )

        facts["bgp_global"] = params.get("config", [])
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
