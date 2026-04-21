# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos bgp_neighbor_address_family fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.bgp_neighbor_address_family.bgp_neighbor_address_family import (
    Bgp_neighbor_address_familyArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.bgp_neighbor_address_family import (
    Bgp_neighbor_address_familyTemplate,
)


class Bgp_neighbor_address_familyFacts(object):
    """The nxos bgp_neighbor_address_family facts class"""

    def __init__(self, module):
        self._module = module
        self.argument_spec = Bgp_neighbor_address_familyArgs.argument_spec

    def get_config(self, connection):
        """Wrapper method for `connection.get()`
        This method exists solely to allow the unit test framework to mock device connection calls.
        """
        return connection.get("show running-config | section '^router bgp'")

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Bgp_neighbor_address_family network resource

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

        data = self._flatten_config(data)

        # parse native config using the Bgp_neighbor_address_family template
        bgp_neighbor_address_family_parser = Bgp_neighbor_address_familyTemplate(lines=data)
        objs = bgp_neighbor_address_family_parser.parse()

        if objs:
            top_lvl_nbrs = objs.get("vrfs", {}).pop("vrf_", {})
            objs["neighbors"] = self._post_parse(top_lvl_nbrs).get("neighbors", [])

            if "vrfs" in objs:
                for vrf in objs["vrfs"].values():
                    vrf["neighbors"] = self._post_parse(vrf)["neighbors"]
                objs["vrfs"] = list(objs["vrfs"].values())

        ansible_facts["ansible_network_resources"].pop("bgp_neighbor_address_family", None)

        params = utils.remove_empties(utils.validate_config(self.argument_spec, {"config": objs}))

        facts["bgp_neighbor_address_family"] = params.get("config", {})
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts

    def _post_parse(self, data):
        if "neighbors" in data:
            data["neighbors"] = sorted(
                list(data["neighbors"].values()),
                key=lambda k, s="neighbor_address": k[s],
            )
            for nbr in data["neighbors"]:
                nbr["address_family"] = sorted(
                    list(nbr["address_family"].values()),
                    key=lambda k: (k["afi"], k.get("safi", "")),
                )
        return data

    def _flatten_config(self, data):
        """Flatten contexts in the BGP
            running-config for easier parsing.
            Only neighbor AF contexts are returned.
        :param data: str
        :returns: flattened running config
        """
        data = data.split("\n")
        nbr_af_cxt = []
        context = ""
        cur_vrf = ""
        cur_nbr_indent = None
        in_nbr_cxt = False
        in_af = False

        # this is the "router bgp <asn>" line
        nbr_af_cxt.append(data[0])
        for x in data:
            cur_indent = len(x) - len(x.lstrip())
            x = x.strip()
            if x.startswith("vrf"):
                cur_vrf = x + " "
                in_nbr_cxt = False
            elif x.startswith("neighbor"):
                in_nbr_cxt = True
                in_af = False
                cur_nbr_indent = cur_indent
                context = x
                if cur_vrf:
                    context = cur_vrf + context
            elif in_nbr_cxt and cur_indent > cur_nbr_indent:
                if x.startswith("address-family"):
                    in_af = True
                    x = context + " " + x
                if in_af:
                    nbr_af_cxt.append(x)
            else:
                in_nbr_cxt = False

        return nbr_af_cxt
