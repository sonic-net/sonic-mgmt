# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos bgp_address_family fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.bgp_address_family.bgp_address_family import (
    Bgp_address_familyArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.bgp_address_family import (
    Bgp_address_familyTemplate,
)


class Bgp_address_familyFacts(object):
    """The nxos bgp_address_family facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Bgp_address_familyArgs.argument_spec

    def get_config(self, connection):
        """Wrapper method for `connection.get()`
        This method exists solely to allow the unit test framework to mock device connection calls.
        """
        return connection.get("show running-config | section '^router bgp'")

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

        if not data:
            data = self.get_config(connection)

        data = self._flatten_config(data)

        # parse native config using the Bgp_address_family template
        bgp_address_family_parser = Bgp_address_familyTemplate(lines=data.splitlines())
        objs = bgp_address_family_parser.parse()
        if objs:
            nbr = []
            if "address_family" in objs:
                # remove neighbor AF entries
                for k, v in objs["address_family"].items():
                    if not k.startswith("nbr_"):
                        nbr.append(k)
                for x in nbr:
                    del objs["address_family"][x]

                objs["address_family"] = list(objs["address_family"].values())
                # sort list of dictionaries
                for x in objs["address_family"]:
                    if "aggregate_address" in x:
                        x["aggregate_address"] = sorted(
                            x["aggregate_address"],
                            key=lambda k, s="prefix": k[s],
                        )
                    if "networks" in x:
                        x["networks"] = sorted(x["networks"], key=lambda k, s="prefix": k[s])
                    if "redistribute" in x:
                        x["redistribute"] = sorted(
                            x["redistribute"],
                            key=lambda k: (k.get("id", -1), k["protocol"]),
                        )
                objs["address_family"] = sorted(
                    objs["address_family"],
                    key=lambda k: (
                        k.get("afi", ""),
                        k.get("safi", ""),
                        k.get("vrf", ""),
                    ),
                )

        ansible_facts["ansible_network_resources"].pop("bgp_address_family", None)

        params = utils.remove_empties(utils.validate_config(self.argument_spec, {"config": objs}))

        facts["bgp_address_family"] = params.get("config", {})
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts

    def _flatten_config(self, data):
        """Flatten contexts in the BGP
            running-config for easier parsing.
        :param obj: dict
        :returns: flattened running config
        """
        data = data.split("\n")
        in_vrf_cxt = False
        in_nbr_cxt = False
        cur_vrf = {}

        for x in data:
            cur_indent = len(x) - len(x.lstrip())
            if x.strip().startswith("vrf"):
                in_vrf_cxt = True
                in_nbr_cxt = False
                cur_vrf["vrf"] = x
                cur_vrf["indent"] = cur_indent
            elif cur_vrf and (cur_indent <= cur_vrf["indent"]):
                in_vrf_cxt = False
            elif x.strip().startswith("neighbor"):
                # we entered a neighbor context which
                # also has address-family lines
                in_nbr_cxt = True
                nbr = x
            elif x.strip().startswith("address-family"):
                if in_vrf_cxt or in_nbr_cxt:
                    prepend = ""
                    if in_vrf_cxt:
                        prepend += cur_vrf["vrf"]
                    if in_nbr_cxt:
                        if in_vrf_cxt:
                            nbr = " " + nbr.strip()
                        prepend += nbr
                    data[data.index(x)] = prepend + " " + x.strip()

        return "\n".join(data)
