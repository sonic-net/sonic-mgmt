# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The Bgp_address_family parser templates file. This contains
a list of parser definitions and associated functions that
facilitates both facts gathering and native command generation for
the given network resource.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


def _tmplt_bgp_af_aggregate_address(config_data):
    afi = config_data["address_family"]["afi"] + "-unicast"
    command = "protocols bgp {as_number} address-family ".format(**config_data)
    config_data = config_data["address_family"]
    if config_data["aggregate_address"].get("as_set"):
        command += afi + " aggregate-address {prefix} as-set".format(
            **config_data["aggregate_address"],
        )
    if config_data["aggregate_address"].get("summary_only"):
        command += afi + " aggregate-address {prefix} summary-only".format(
            **config_data["aggregate_address"],
        )
    return command


def _tmplt_bgp_af_redistribute(config_data):
    afi = config_data["address_family"]["afi"] + "-unicast"
    command = "protocols bgp {as_number} address-family ".format(**config_data)
    config_data = config_data["address_family"]["redistribute"]
    command += afi + " redistribute {protocol}".format(**config_data)
    if config_data.get("metric"):
        command += " metric {metric}".format(**config_data)
    elif config_data.get("route_map"):
        command += " route-map {route_map}".format(**config_data)
    elif config_data.get("table"):
        command += " table {table}".format(**config_data)
    return command


def _tmplt_bgp_af_redistribute_delete(config_data):
    afi = config_data["address_family"]["afi"] + "-unicast"
    command = "protocols bgp {as_number} address-family ".format(**config_data)
    config_data = config_data["address_family"]["redistribute"]
    command += afi + " redistribute {protocol}".format(**config_data)
    if config_data.get("metric"):
        command += " metric"
    elif config_data.get("route_map"):
        command += " route-map"
    elif config_data.get("table"):
        command += " table"
    return command


def _tmplt_bgp_af_neighbor_distribute_list(config_data):
    command = []
    afi = config_data["neighbors"]["address_family"]["afi"] + "-unicast"
    cmd = "protocols bgp {as_number} neighbor ".format(**config_data)
    cmd += "{neighbor_address} address-family ".format(**config_data["neighbors"])
    config_data = config_data["neighbors"]["address_family"]
    for list_el in config_data["distribute_list"]:
        command.append(
            cmd + afi + " distribute-list " + list_el["action"] + " " + str(list_el["acl"]),
        )
    return command


def _tmplt_bgp_af_neighbor_route_map(config_data):
    command = []
    afi = config_data["neighbors"]["address_family"]["afi"] + "-unicast"
    cmd = "protocols bgp {as_number} neighbor ".format(**config_data)
    cmd += "{neighbor_address} address-family ".format(**config_data["neighbors"])
    config_data = config_data["neighbors"]["address_family"]
    for list_el in config_data["route_map"]:
        command.append(
            cmd + afi + " route-map " + list_el["action"] + " " + str(list_el["route_map"]),
        )
    return command


def _tmplt_bgp_af_neighbor_prefix_list(config_data):
    command = []
    afi = config_data["neighbors"]["address_family"]["afi"] + "-unicast"
    cmd = "protocols bgp {as_number} neighbor ".format(**config_data)
    cmd += "{neighbor_address} address-family ".format(**config_data["neighbors"])
    config_data = config_data["neighbors"]["address_family"]
    for list_el in config_data["prefix_list"]:
        command.append(
            cmd + afi + " prefix-list " + list_el["action"] + " " + str(list_el["prefix_list"]),
        )
    return command


def _tmplt_bgp_af_neighbor_filter_list(config_data):
    command = []
    afi = config_data["neighbors"]["address_family"]["afi"] + "-unicast"
    cmd = "protocols bgp {as_number} neighbor ".format(**config_data)
    cmd += "{neighbor_address} address-family ".format(**config_data["neighbors"])
    config_data = config_data["neighbors"]["address_family"]
    for list_el in config_data["filter_list"]:
        command.append(
            cmd + afi + " filter-list " + list_el["action"] + " " + str(list_el["path_list"]),
        )
    return command


def _tmplt_bgp_af_neighbor_attribute(config_data):
    command = []
    afi = config_data["neighbors"]["address_family"]["afi"] + "-unicast"
    cmd = "protocols bgp {as_number} neighbor ".format(**config_data)
    cmd += "{neighbor_address} address-family ".format(**config_data["neighbors"])
    config_data = config_data["neighbors"]["address_family"]
    for k in config_data["attribute_unchanged"].keys():
        if config_data["attribute_unchanged"][k]:
            k = re.sub("_", "-", k)
            c = cmd + afi + " attribute-unchanged " + k
            command.append(c)
    return command


def _tmplt_bgp_af_neighbor_delete(config_data):
    afi = config_data["neighbors"]["address_family"]["afi"] + "-unicast"
    command = "protocols bgp {as_number} ".format(**config_data)
    command += (
        "neighbor {neighbor_address} address-family ".format(**config_data["neighbors"]) + afi
    )
    config_data = config_data["neighbors"]["address_family"]
    if config_data.get("allowas_in"):
        command += " allowas-in"
    elif config_data.get("as_override"):
        command += " as-override"
    elif config_data.get("attribute_unchanged"):
        command += " attribute-unchanged"
    elif config_data.get("capability"):
        command += " capability"
    elif config_data.get("default_originate"):
        command += " default-originate"
    elif config_data.get("maximum_prefix"):
        command += " maximum-prefix"
    elif config_data.get("nexthop_local"):
        command += " nexthop-local"
    elif config_data.get("nexthop_self"):
        command += " nexthop-self"
    elif config_data.get("peer_group"):
        command += " peer-group"
    elif config_data.get("remote_private_as"):
        command += " remote-private-as"
    elif config_data.get("route_reflector_client"):
        command += " route-reflector-client"
    elif config_data.get("route_server_client"):
        command += " route-server-client"
    elif config_data.get("soft_reconfiguration"):
        command += " soft-reconfiguration"
    elif config_data.get("unsuppress_map"):
        command += " unsuppress-map"
    elif config_data.get("weight"):
        command += " weight"
    elif config_data.get("filter_list"):
        command += " filter-list"
    elif config_data.get("prefix_list"):
        command += " prefix-list"
    elif config_data.get("distribute_list"):
        command += " distribute-list"
    elif config_data.get("route_map"):
        command += " route-map"
    return command


def _tmplt_bgp_af_neighbor(config_data):
    afi = config_data["neighbors"]["address_family"]["afi"] + "-unicast"
    command = "protocols bgp {as_number} ".format(**config_data)
    command += (
        "neighbor {neighbor_address} address-family ".format(**config_data["neighbors"]) + afi
    )
    config_data = config_data["neighbors"]["address_family"]
    if config_data.get("allowas_in"):
        command += " allowas-in number {allowas_in}".format(**config_data)
    elif config_data.get("as_override"):
        command += " as-override"
    elif config_data.get("capability"):
        command += " capability "
        if config_data["capability"].get("dynamic"):
            command += "dynamic"
        elif config_data["capability"].get("orf"):
            command += " prefix-list {orf}".format(**config_data["capability"])
    elif config_data.get("default_originate"):
        command += " default-originate route-map {default_originate}".format(**config_data)
    elif config_data.get("maximum_prefix"):
        command += " maximum-prefix {maximum_prefix}".format(**config_data)
    elif config_data.get("nexthop_local"):
        command += " nexthop-local"
    elif config_data.get("nexthop_self"):
        command += " nexthop-self"
    elif config_data.get("peer_group"):
        command += " peer-group {peer_group}".format(**config_data)
    elif config_data.get("remote_private_as"):
        command += " remote-private-as"
    elif config_data.get("route_reflector_client"):
        command += " route-reflector-client"
    elif config_data.get("route_server_client"):
        command += " route-server-client"
    elif config_data.get("soft_reconfiguration"):
        command += " soft-reconfiguration inbound"
    elif config_data.get("unsuppress_map"):
        command += " unsuppress-map {unsuppress_map}".format(**config_data)
    elif config_data.get("weight"):
        command += " weight {weight}".format(**config_data)
    return command


def _tmplt_bgp_af_network(config_data):
    afi = config_data["address_family"]["afi"] + "-unicast"
    command = "protocols bgp {as_number} address-family ".format(**config_data)
    config_data = config_data["address_family"]["networks"]
    command += afi + " network {prefix}".format(**config_data)
    if config_data.get("backdoor"):
        command += " backdoor"
    elif config_data.get("route_map"):
        command += " route-map {route_map}".format(**config_data)
    return command


def _tmplt_bgp_af_network_delete(config_data):
    afi = config_data["address_family"]["afi"] + "-unicast"
    command = "protocols bgp {as_number} address-family ".format(**config_data)
    config_data = config_data["address_family"]["networks"]
    command += afi + " network {prefix}".format(**config_data)
    if config_data.get("backdoor"):
        command += " backdoor"
    elif config_data.get("route_map"):
        command += " route_map"
    return command


class Bgp_address_familyTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        prefix = {"set": "set", "remove": "delete"}
        super(Bgp_address_familyTemplate, self).__init__(
            lines=lines,
            tmplt=self,
            prefix=prefix,
            module=module,
        )

    # fmt: off
    PARSERS = [
        {
            "name": "address_family",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} address-family {{ address_family.afi }}-unicast",
            "compval": "as_number",
            "result": {
                "as_number": "{{ as_num }}",
                "address_family": {
                    "{{ afi }}": {
                        "afi": "{{ afi }}",
                    },
                },
            },
        },
        {
            "name": "aggregate_address",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+aggregate-address
                \s+(?P<address>\S+)
                \s*(?P<as_set>as-set)*
                \s*(?P<summary_only>summary-only)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_aggregate_address,
            "remval": "protocols bgp {{ as_number }} address-family {{ address_family.afi }}-unicast aggregate-address" +
                      " {{ address_family.aggregate_address.prefix }}",
            "compval": "address_family.aggregate_address",
            "result": {
                "as_number": "{{ as_num }}",
                "address_family": {
                    "{{ afi }}": {
                        "afi": "{{ afi }}",
                        "aggregate_address": [
                            {
                                "prefix": "{{ address }}",
                                "as_set": "{{ True if as_set is defined }}",
                                "summary_only": "{{ True if summary_only is defined }}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "network",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+network
                \s+(?P<address>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_network,
            "remval": "protocols bgp {{ as_number }} address-family {{ address_family.afi }}-unicast network {{ address_family.networks.prefix }}",
            "compval": "address_family.networks.prefix",
            "result": {
                "as_number": "{{ as_num }}",
                "address_family": {
                    "{{ afi }}": {
                        "afi": "{{ afi }}",
                        "networks": [
                            {
                                "prefix": "{{ address }}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "network.backdoor",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+network
                \s+(?P<address>\S+)
                \s+backdoor
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_network,
            "remval": _tmplt_bgp_af_network_delete,
            "compval": "address_family.networks.backdoor",
            "result": {
                "as_number": "{{ as_num }}",
                "address_family": {
                    "{{ afi }}": {
                        "afi": "{{ afi }}",
                        "networks": [
                            {
                                "prefix": "{{ address }}",
                                "backdoor": "{{ True }}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "network.path_limit",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+network
                \s+(?P<address>\S+)
                \s+path-limit
                \s+(?P<limit>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_network,
            "remval": _tmplt_bgp_af_network_delete,
            "compval": "address_family.networks.path_limit",
            "result": {
                "as_number": "{{ as_num }}",
                "address_family": {
                    "{{ afi }}": {
                        "afi": "{{ afi }}",
                        "networks": [
                            {
                                "prefix": "{{ address }}",
                                "path_limit": "{{ limit|int }}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "network.route_map",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+network
                \s+(?P<address>\S+)
                \s+route-map
                \s+(?P<map>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_network,
            "remval": _tmplt_bgp_af_network_delete,
            "compval": "address_family.networks.route_map",
            "result": {
                "as_number": "{{ as_num }}",
                "address_family": {
                    "{{ afi }}": {
                        "afi": "{{ afi }}",
                        "networks": [
                            {
                                "prefix": "{{ address }}",
                                "route_map": "{{ map }}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "redistribute",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+redistribute
                \s+(?P<proto>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_redistribute,
            "remval": "protocols bgp {{ as_number }} address-family {{ address_family.afi }}-unicast redistribute {{ address_family.redistribute.protocol }}",
            "compval": "address_family.redistribute.protocol",
            "result": {
                "as_number": "{{ as_num }}",
                "address_family": {
                    "{{ afi }}": {
                        "afi": "{{ afi }}",
                        "redistribute": [
                            {
                                "protocol": "{{ proto }}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "redistribute.metric",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+redistribute
                \s+(?P<proto>\S+)
                \s+metric
                \s+(?P<val>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_redistribute,
            "remval": _tmplt_bgp_af_redistribute_delete,
            "compval": "address_family.redistribute.metric",
            "result": {
                "as_number": "{{ as_num }}",
                "address_family": {
                    "{{ afi }}": {
                        "afi": "{{ afi }}",
                        "redistribute": [
                            {
                                "protocol": "{{ proto }}",
                                "metric": "{{ val|int }}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "redistribute.route_map",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+redistribute
                \s+(?P<proto>\S+)
                \s+route-map
                \s+(?P<map>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_redistribute,
            "remval": _tmplt_bgp_af_redistribute_delete,
            "compval": "address_family.redistribute.route_map",
            "result": {
                "as_number": "{{ as_num }}",
                "address_family": {
                    "{{ afi }}": {
                        "afi": "{{ afi }}",
                        "redistribute": [
                            {
                                "protocol": "{{ proto }}",
                                "route_map": "{{ map }}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "redistribute.table",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+redistribute
                \s+table
                \s+(?P<tab>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_redistribute,
            "remval": _tmplt_bgp_af_redistribute_delete,
            "compval": "address_family.redistribute.table",
            "result": {
                "as_number": "{{ as_num }}",
                "address_family": {
                    "{{ afi }}": {
                        "afi": "{{ afi }}",
                        "redistribute": [
                            {
                                "table": "{{ tab }}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "neighbors",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbors.neighbor_address }} address-family",
            "compval": "neighbors",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                    },
                },
            },
        },
        {
            "name": "neighbors.address_family",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                *$""",
                re.VERBOSE,
            ),
            "setval": "protocols bgp {{ as_number }} neighbor {{ neighbors.neighbor_address }} address-family {{ neighbors.address_family.afi }}-unicast",
            "compval": "neighbors",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.allowas_in",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+allowas-in
                \s+number
                \s+(?P<num>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.allowas_in",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "allowas_in": "{{ num }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.as_override",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+as-override
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.as_override",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "as_override": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.attribute_unchanged.as_path",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+attribute-unchanged
                \s+(?P<val>as-path)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor_attribute,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.attribute_unchanged.as_path",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "attribute_unchanged": {
                                    "as_path": "{{ True }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.attribute_unchanged.med",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+attribute-unchanged
                \s+(?P<val>med)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor_attribute,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.attribute_unchanged.med",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "attribute_unchanged": {
                                    "med": "{{ True }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.attribute_unchanged.next_hop",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+attribute-unchanged
                \s+(?P<val>next-hop)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor_attribute,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.attribute_unchanged.next_hop",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "attribute_unchanged": {
                                    "next_hop": "{{ True }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.capability_dynamic",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+capability
                \s+dynamic
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.capability.dynamic",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "capability": {
                                    "dynamic": "{{ true }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.capability_orf",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+capability
                \s+prefix-list
                \s+(?P<orf>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.capability.orf",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "capability": {
                                    "orf": "{{ orf }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.default_originate",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+default-originate
                \s+route-map
                \s+(?P<map>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.default_originate",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "default_originate": "{{ map }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.distribute_list",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+distribute-list
                \s+(?P<action>export|import)
                \s+(?P<list>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor_distribute_list,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.distribute_list",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "distribute_list": [
                                    {
                                        "action": "{{ action }}",
                                        "acl": "{{ list }}",
                                    },
                                ],
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.prefix_list",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+prefix-list
                \s+(?P<action>export|import)
                \s+(?P<list>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor_prefix_list,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.prefix_list",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "prefix_list": [
                                    {
                                        "action": "{{ action }}",
                                        "prefix_list": "{{ list }}",
                                    },
                                ],
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.filter_list",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+filter-list
                \s+(?P<action>export|import)
                \s+(?P<list>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor_filter_list,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.filter_list",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "filter_list": [
                                    {
                                        "action": "{{ action }}",
                                        "path_list": "{{ list }}",
                                    },
                                ],
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.maximum_prefix",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+maximum-prefix
                \s+(?P<num>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.maximum_prefix",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "maximum_prefix": "{{ num }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.nexthop_local",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+nexthop-local
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.nexthop_local",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "nexthop_local": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.nexthop_self",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+nexthop-self
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.nexthop_self",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "nexthop_self": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.peer_group",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+peer-group
                \s+(?P<name>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.peer_group",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "peer_group": "{{ name }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.remove_private_as",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+remove-private-as
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.remove_private_as",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "remove_private_as": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.route_map",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+route-map
                \s+(?P<action>export|import)
                \s+(?P<map>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor_route_map,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.route_map",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "route_map": [
                                    {
                                        "action": "{{ action }}",
                                        "route_map": "{{ map }}",
                                    },
                                ],
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.route_reflector_client",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+route-reflector-client
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.route_reflector_client",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "route_reflector_client": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.route_server_client",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+route-server-client
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.route_server_client",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "route_server_client": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.soft_reconfiguration",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+soft-reconfiguration
                \s+inbound
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.soft_reconfiguration",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "soft_reconfiguration": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.unsuppress_map",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+unsuppress-map
                \s+(?P<map>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.unsuppress_map",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "unsuppress_map": "{{ map }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbors.weight",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+bgp
                \s+(?P<as_num>\d+)
                \s+neighbor
                \s+(?P<address>\S+)
                \s+address-family
                \s+(?P<afi>\S+)-unicast
                \s+weight
                \s+(?P<num>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_af_neighbor,
            "remval": _tmplt_bgp_af_neighbor_delete,
            "compval": "neighbors.address_family.weight",
            "result": {
                "as_number": "{{ as_num }}",
                "neighbors": {
                    "{{ address }}": {
                        "neighbor_address": "{{ address }}",
                        "address_family": {
                            "{{ afi }}": {
                                "afi": "{{ afi }}",
                                "weight": "{{ num }}",
                            },
                        },
                    },
                },
            },
        },
    ]
    # fmt: on
