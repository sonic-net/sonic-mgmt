# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The Bgp_global parser templates file. This contains
a list of parser definitions and associated functions that
facilitates both facts gathering and native command generation for
the given network resource.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


def _tmplt_router_bgp_cmd(config_data):
    command = "router bgp {as_number}".format(**config_data)
    return command


def _tmplt_bgp_address_family(config_data):
    command = ""
    if config_data.get("vrf"):
        command = "vrf {vrf}\n".format(**config_data)
    command += "address-family {afi}".format(**config_data)
    if config_data.get("safi"):
        command += " {safi}".format(**config_data)
    return command


def _tmplt_bgp_params(config_data):
    command = "bgp"
    if config_data["bgp_params"].get("additional_paths"):
        command += " additional-paths {additional_paths}".format(**config_data["bgp_params"])
        if config_data["bgp_params"]["additional_paths"] == "send":
            command += " any"
    elif config_data["bgp_params"].get("next_hop_address_family"):
        command += " next-hop address-family ipv6"
    elif config_data["bgp_params"].get("next_hop_unchanged"):
        command += " next-hop-unchanged"
    elif config_data["bgp_params"].get("redistribute_internal"):
        command += " redistribute-internal"
    elif config_data["bgp_params"].get("route"):
        command += " route install-map {route}".format(**config_data["bgp_params"])
    return command


def _tmplt_bgp_graceful_restart(config_data):
    command = "graceful-restart"
    return command


def _tmplt_bgp_neighbor(config_data):
    command = "neighbor {peer}".format(**config_data["neighbor"])
    if config_data["neighbor"].get("additional_paths"):
        command += " additional-paths {additional_paths}".format(**config_data["neighbor"])
        if config_data["neighbor"]["additional_paths"] == "send":
            command += "any"
    elif config_data["neighbor"].get("activate"):
        command += " activate"
    elif config_data["neighbor"].get("default_originate"):
        command += " default-originate"
        if config_data["neighbor"]["default_originate"].get("route_map"):
            command += " route-map " + config_data["neighbor"]["default_originate"]["route_map"]
        if config_data["neighbor"]["default_originate"].get("always"):
            command += " always"
    elif config_data["neighbor"].get("graceful_restart"):
        command += " graceful-restart"
    elif config_data["neighbor"].get("next_hop_unchanged"):
        command += " next-hop-unchanged"
    elif config_data["neighbor"].get("next_hop_address_family"):
        command += " next-hop addres-family ipv6"
    elif config_data["neighbor"].get("prefix_list"):
        command += " prefix-list {name} {direction}".format(
            **config_data["neighbor"]["prefix_list"],
        )
    elif config_data["neighbor"].get("route_map"):
        command += " route-map {name} {direction}".format(**config_data["neighbor"]["route_map"])
    elif config_data["neighbor"].get("weight"):
        command += " weight {weight}".format(**config_data["neighbor"])
    elif config_data["neighbor"].get("encapsulation"):
        command += " encapsulation {transport}".format(**config_data["neighbor"])
        if config_data["neighbor"]["encapsulation"].get("source_interface"):
            command += " next-hop-self source-interface {source_interface}".format(
                **config_data["neighbor"],
            )
    return command


def _tmplt_bgp_network(config_data):
    command = "network {address}".format(**config_data)
    if config_data.get("route_map"):
        command += " route-map {route_map}".format(**config_data)
    return command


def _tmplt_bgp_redistribute(config_data):
    command = "redistribute {protocol}".format(**config_data)
    if config_data.get("isis_level"):
        command += " {isis_level}".format(**config_data)
    if config_data.get("ospf_route"):
        command += " match {ospf_route}".format(**config_data)
    if config_data.get("route_map"):
        command += " route-map {route_map}".format(**config_data)
    return command


def _tmplt_bgp_route_target(config_data):
    command = "route-target {action}".format(**config_data["route_target"])
    if config_data["route_target"].get("type"):
        command += " {type}".format(**config_data["route_target"])
    if config_data["route_target"].get("route_map"):
        command += " {route_map}".format(**config_data["route_target"])
    if config_data["route_target"].get("target"):
        command += " {target}".format(**config_data["route_target"])
    return command


class Bgp_afTemplate(NetworkTemplate):
    def __init__(self, lines=None):
        super(Bgp_afTemplate, self).__init__(lines=lines, tmplt=self)

    # fmt: off
    PARSERS = [
        {
            "name": "router",
            "getval": re.compile(
                r"""
                ^router\s
                bgp
                \s(?P<as_num>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_router_bgp_cmd,
            "compval": "as_number",
            "result": {"as_number": "{{ as_num }}"},
            "shared": True,
        },
        {
            "name": "address_family",
            "getval": re.compile(
                r"""
                \s*(?P<vrf>vrf\s\S+)*
                \s*address-family
                \s(?P<afi>ipv4|ipv6|evpn)
                \s*(?P<type>\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_address_family,
            "result": {
                "address_family": {
                    '{{ afi + "_" + vrf|d() }}': {
                        "afi": "{{ afi }}",
                        "safi": "{{ type }}",
                        "vrf": "{{ vrf.split(" ")[1] }}",
                    },
                },
            },
            "shared": True,
        },
        {
            "name": "bgp_params_additional_paths",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+additional-paths
                \s+(?P<action>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.additional_paths",
            "result": {
                "address_family": {
                    '{{ afi + "_" + vrf|d() }}': {
                        "bgp_params": {
                            "additional_paths": "{{ action }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params.nexthop_address_family",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+next-hop
                \s+address-family
                \s+ipv6
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.next_hop_address_family",
            "result": {
                "address_family": {
                    '{{ afi + "_" + vrf|d() }}': {
                        "bgp_params": {
                            "next_hop_unchanged": "{{ 'ipv6' }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params.nexthop_unchanged",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+next-hop-unchanged
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.next_hop_unchanged",
            "result": {
                "address_family": {
                    '{{ afi + "_" + vrf|d() }}': {
                        "bgp_params": {
                            "next_hop_unchanged": "{{ True }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params.redistribute_internal",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+redistribute-internal
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.redistribute_internal",
            "result": {
                "address_family": {
                    '{{ afi + "_" + vrf|d() }}': {
                        "bgp_params": {
                            "redistribute_internal": "{{ True }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_params.route",
            "getval": re.compile(
                r"""
                \s*bgp
                \s+route
                \s+install-map
                \s+(?P<route>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_params,
            "compval": "bgp_params.route",
            "result": {
                "address_family": {
                    '{{ afi + "_" + vrf|d() }}': {
                        "bgp_params": {
                            "route": "{{ route }}",
                        },
                    },
                },
            },
        },
        {
            "name": "graceful_restart",
            "getval": re.compile(
                r"""
                \s*graceful-restart
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_graceful_restart,
            "result": {
                "address_family": {
                    '{{ afi + "_" + vrf|d() }}': {
                        "graceful_restart": "{{ True }}",
                    },
                },
            },
        },
        {
            "name": "neighbor.activate",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+activate
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.activate",
            "result": {
                "address_family": {
                    '{{ afi + "_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "peer": "{{ peer }}",
                                "activate": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.additional_paths",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+additional-paths
                \s+(?P<action>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.additional_paths",
            "result": {
                "address_family": {
                    '{{ afi + "_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "peer": "{{ peer }}",
                                "additional_paths": "{{ action }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.default_originate",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+default-originate
                \s*(?P<route_map>route-map\s\S+)*
                \s*(?P<always>always)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.default_originate",
            "result": {
                "address_family": {
                    '{{ afi + "_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "peer": "{{ peer }}",
                                "default_originate": {
                                    "route_map": "{{ route_map.split(" ")[1] }}",
                                    "always": "{{ True if always is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.graceful_restart",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+graceful-restart
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.graceful_restart",
            "result": {
                "address_family": {
                    '{{ afi + "_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "peer": "{{ peer }}",
                                "graceful_restart": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.next_hop_unchanged",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+next-hop-unchanged
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.next_hop_unchanged",
            "result": {
                "address_family": {
                    '{{ afi + "_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "peer": "{{ peer }}",
                                "next_hop_unchanged": "{{ True }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.next_hop_address_family",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+next-hop
                \s+address-family
                \s+ipv6
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.next_hop_address_family",
            "result": {
                "address_family": {
                    '{{ afi + "_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "peer": "{{ peer }}",
                                "next_hop_address_family": "{{ 'ipv6' }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.prefix_list",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+prefix-list
                \s+(?P<name>\S+)
                \s+(?P<dir>in|out)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.prefix_list",
            "result": {
                "address_family": {
                    '{{ afi + "_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "peer": "{{ peer }}",
                                "prefix_list": {
                                    "name": "{{ name }}",
                                    "direction": "{{ dir }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.route_map",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+route-map
                \s+(?P<name>\S+)
                \s+(?P<dir>in|out)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.route_map",
            "result": {
                "address_family": {
                    '{{ afi + "_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "peer": "{{ peer }}",
                                "route_map": {
                                    "name": "{{ name }}",
                                    "direction": "{{ dir }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.weight",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+(?P<peer>\S+)
                \s+weight
                \s+(?P<weight>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.weight",
            "result": {
                "address_family": {
                    '{{ afi + "_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "peer": "{{ peer }}",
                                "weight": "{{ weight }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor.encapsulation",
            "getval": re.compile(
                r"""
                \s*neighbor
                \s+default
                \s+encapsulation
                \s+(?P<type>mpls|vxlan)
                \s*(next-hop-self)*
                \s*(source-interface)*
                \s*(?P<interface>\S+\s\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_neighbor,
            "compval": "neighbor.encapsulation",
            "result": {
                "address_family": {
                    '{{ afi + "_" + vrf|d() }}': {
                        "neighbor": {
                            "{{ peer }}": {
                                "peer": "{{ peer }}",
                                "encapsulation": {
                                    "transport": "{{ type }}",
                                    "source_interface": "{{ interface }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "network",
            "getval": re.compile(
                r"""
                \s*network
                \s+(?P<address>\S+)
                \s*(route-map)*
                \s*(?P<route_map>\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_network,
            "compval": "network",
            "result": {
                "address_family": {
                    '{{ afi + "_" + vrf|d() }}': {
                        "network": {
                            "{{ address }}": {
                                "address": "{{ address }}",
                                "route_map": "{{ route_map }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "redistribute",
            "getval": re.compile(
                r"""
                \s*redistribute
                \s+(?P<route>\S+)
                \s*(?P<level>level-1|level-2|level-1-2)*
                \s*(?P<match>match\s\S+)*
                \s*(?P<route_map>route-map\s\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_redistribute,
            "compval": "redistribute",
            "result": {
                "address_family": {
                    '{{ afi + "_" + vrf|d() }}': {
                        "redistribute": [
                            {
                                "protocol": "{{ route }}",
                                "route_map": "{{ route_map.split(" ")[1] }}",
                                "isis_level": "{{ level }}",
                                "ospf_route": "{{ match.split(" ")[1] }}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "route_target",
            "getval": re.compile(
                r"""
                \s*route-target
                \s+(?P<action>\S+)
                \s*(?P<type>evpn|vpn-ipv4|vpn-ipv6)*
                \s*(?P<map>route-map\s\S+)*
                \s+(?P<target>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_bgp_route_target,
            "compval": "route_target",
            "result": {
                "address_family": {
                    '{{ afi + "_" + vrf|d() }}': {
                        "route_target": {
                            "action": "{{ action }}",
                            "type": "{{ type }}",
                            "route_map": "{{ map.split(" ")[1] }}",
                            "target": "{{ target }}",
                        },
                    },
                },
            },
        },
    ]
    # fmt: on
