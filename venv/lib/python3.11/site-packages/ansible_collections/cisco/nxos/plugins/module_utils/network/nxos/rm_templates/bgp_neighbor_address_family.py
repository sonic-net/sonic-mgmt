# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The Bgp_neighbor_address_family parser templates file. This contains
a list of parser definitions and associated functions that
facilitates both facts gathering and native command generation for
the given network resource.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


def _tmplt_maximum_prefix(data):
    data = data["maximum_prefix"]
    cmd = "maximum-prefix {max_prefix_limit}".format(**data)
    if "generate_warning_threshold" in data:
        cmd += " {generate_warning_threshold}".format(**data)
    if "restart_interval" in data:
        cmd += " restart {restart_interval}".format(**data)
    if data.get("warning_only"):
        cmd += " warning-only"
    return cmd


class Bgp_neighbor_address_familyTemplate(NetworkTemplate):
    def __init__(self, lines=None):
        super(Bgp_neighbor_address_familyTemplate, self).__init__(lines=lines, tmplt=self)

    # fmt: off
    PARSERS = [
        {
            "name": "as_number",
            "getval": re.compile(
                r"""
                ^router\sbgp\s(?P<as_number>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "router bgp {{ as_number }}",
            "result": {
                "as_number": "{{ as_number }}",
            },
            "shared": True,
        },
        {
            "name": "address_family",
            "getval": re.compile(
                r"""
                (vrf\s(?P<vrf>\S+))?
                \s*neighbor\s(?P<neighbor>\S+)
                (\sremote-as\s\S+)?
                \saddress-family
                \s(?P<afi>\S+)
                (\s(?P<safi>\S+))?
                $""",
                re.VERBOSE,
            ),
            "setval": "address-family {{ afi }}{{ (' ' + safi) if safi is defined else '' }}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "neighbor_address": "{{ neighbor }}",
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "afi": "{{ afi }}",
                                        "safi": "{{ safi }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
            "shared": True,
        },
        {
            "name": "advertise_map.exist_map",
            "getval": re.compile(
                r"""
                advertise-map
                \s(?P<route_map>\S+)
                \sexist-map\s(?P<exist_map>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": "advertise-map {{ advertise_map.route_map }} exist-map {{ advertise_map.exist_map }}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "advertise_map": {
                                            "route_map": "{{ route_map }}",
                                            "exist_map": "{{ exist_map }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "advertise_map.non_exist_map",
            "getval": re.compile(
                r"""
                advertise-map
                \s(?P<route_map>\S+)
                \snon-exist-map\s(?P<non_exist_map>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": "advertise-map {{ advertise_map.route_map }} non-exist-map {{ advertise_map.non_exist_map }}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "advertise_map": {
                                            "route_map": "{{ route_map }}",
                                            "non_exist_map": "{{ non_exist_map }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "advertisement_interval",
            "getval": re.compile(
                r"""
                advertisement-interval
                \s(?P<advertisement_interval>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "advertisement-interval {{ advertisement_interval }}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "advertisement_interval": "{{ advertisement_interval }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "allowas_in",
            "getval": re.compile(
                r"""
                (?P<allowas_in>allowas-in)
                \s(?P<max_occurences>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "allowas-in{{ ' ' + allowas_in.max_occurences|string if allowas_in.max_occurences is defined else '' }}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "allowas_in": {
                                            "set": "{{ True if allowas_in is defined and max_occurences is undefined }}",
                                            "max_occurences": "{{ max_occurences }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "as_override",
            "getval": re.compile(
                r"""
                (?P<as_override>as-override)
                $""",
                re.VERBOSE,
            ),
            "setval": "as-override",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "as_override": "{{ not not as_override }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "capability.additional_paths.receive",
            "getval": re.compile(
                r"""
                capability\sadditional-paths
                \s(?P<receive>receive)
                (\s(?P<disable>disable))?
                $""",
                re.VERBOSE,
            ),
            "setval": "capability additional-paths receive{{ ' disable' if capability.additional_paths.receive == 'disable' else '' }}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "capability": {
                                            "additional_paths": {
                                                "receive": "{{ 'disable' if disable is defined else 'enable' }}",
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "capability.additional_paths.send",
            "getval": re.compile(
                r"""
                capability\sadditional-paths
                \s(?P<send>send)
                (\s(?P<disable>disable))?
                $""",
                re.VERBOSE,
            ),
            "setval": "capability additional-paths send{{ ' disable' if capability.additional_paths.send == 'disable' else '' }}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "capability": {
                                            "additional_paths": {
                                                "send": "{{ 'disable' if disable is defined else 'enable' }}",
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "default_originate",
            "getval": re.compile(
                r"""
                (?P<default_originate>default-originate)
                (\sroute-map\s(?P<route_map>\S+))?
                $""",
                re.VERBOSE,
            ),
            "setval": "default-originate{{ ' route-map ' + default_originate.route_map if default_originate.route_map is defined else '' }}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "default_originate": {
                                            "set": "{{ True if default_originate is defined and route_map is not defined }}",
                                            "route_map": "{{ route_map }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "disable_peer_as_check",
            "getval": re.compile(
                r"""
                (?P<disable_peer_as_check>disable-peer-as-check)
                $""",
                re.VERBOSE,
            ),
            "setval": "disable-peer-as-check",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "disable_peer_as_check": "{{ not not disable_peer_as_check }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "filter_list.inbound",
            "getval": re.compile(
                r"""
                filter-list
                \s(?P<in>\S+)\s(?:in)
                $""",
                re.VERBOSE,
            ),
            "setval": "filter-list {{ filter_list.inbound }} in",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "filter_list": {
                                            "inbound": "{{ in }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "filter_list.outbound",
            "getval": re.compile(
                r"""
                filter-list
                \s(?P<out>\S+)\s(?:out)
                $""",
                re.VERBOSE,
            ),
            "setval": "filter-list {{ filter_list.outbound }} out",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "filter_list": {
                                            "outbound": "{{ out }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "inherit",
            "getval": re.compile(
                r"""
                inherit\speer-policy
                \s(?P<template>\S+)
                \s(?P<sequence>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "inherit peer-policy {{ inherit.template }} {{ inherit.sequence }}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "inherit": {
                                            "template": "{{ template }}",
                                            "sequence": "{{ sequence }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "maximum_prefix",
            "getval": re.compile(
                r"""
                maximum-prefix
                \s(?P<max_prefix_limit>\d+)
                (\s(?P<generate_warning_threshold>\d+))?
                (\srestart\s(?P<restart_interval>\d+))?
                (\s(?P<warning_only>warning-only))?
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_maximum_prefix,
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "maximum_prefix": {
                                            "max_prefix_limit": "{{ max_prefix_limit }}",
                                            "generate_warning_threshold": "{{ generate_warning_threshold }}",
                                            "restart_interval": "{{ restart_interval }}",
                                            "warning_only": "{{ not not warning_only }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "next_hop_self",
            "getval": re.compile(
                r"""
                (?P<next_hop_self>next-hop-self)
                (\s(?P<all_routes>all))?
                $""",
                re.VERBOSE,
            ),
            "setval": "next-hop-self{{ ' all' if next_hop_self.all_routes|d(False) else '' }}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "next_hop_self": {
                                            "set": "{{ True if next_hop_self is defined and all_routes is not defined }}",
                                            "all_routes": "{{ not not all_routes }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "next_hop_third_party",
            "getval": re.compile(
                r"""
                no\s(?P<next_hop_third_party>next-hop-third-party)
                $""",
                re.VERBOSE,
            ),
            "setval": "next-hop-third-party",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "next_hop_third_party": "{{ not next_hop_third_party }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "prefix_list.inbound",
            "getval": re.compile(
                r"""
                prefix-list
                \s(?P<in>\S+)\s(?:in)
                $""",
                re.VERBOSE,
            ),
            "setval": "prefix-list {{ prefix_list.inbound }} in",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "prefix_list": {
                                            "inbound": "{{ in }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "prefix_list.outbound",
            "getval": re.compile(
                r"""
                prefix-list
                \s(?P<out>\S+)\s(?:out)
                $""",
                re.VERBOSE,
            ),
            "setval": "prefix-list {{ prefix_list.outbound }} out",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "prefix_list": {
                                            "outbound": "{{ out }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "rewrite_evpn_rt_asn",
            "getval": re.compile(
                r"""
                (?P<rewrite_evpn_rt_asn>rewrite-evpn-rt-asn)
                $""",
                re.VERBOSE,
            ),
            "setval": "rewrite-evpn-rt-asn",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "rewrite_evpn_rt_asn": "{{ not not rewrite_evpn_rt_asn }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "rewrite_rt_asn",
            "getval": re.compile(
                r"""
                (?P<rewrite_rt_asn>rewrite-rt-asn)
                $""",
                re.VERBOSE,
            ),
            "setval": "rewrite-rt-asn",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "rewrite_rt_asn": "{{ not not rewrite_rt_asn }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "route_map.inbound",
            "getval": re.compile(
                r"""
                route-map
                \s(?P<in>\S+)\s(?:in)
                $""",
                re.VERBOSE,
            ),
            "setval": "route-map {{ route_map.inbound }} in",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "route_map": {
                                            "inbound": "{{ in }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "route_map.outbound",
            "getval": re.compile(
                r"""
                route-map
                \s(?P<out>\S+)\s(?:out)
                $""",
                re.VERBOSE,
            ),
            "setval": "route-map {{ route_map.outbound }} out",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "route_map": {
                                            "outbound": "{{ out }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "route_reflector_client",
            "getval": re.compile(
                r"""
                (?P<route_reflector_client>route-reflector-client)
                $""",
                re.VERBOSE,
            ),
            "setval": "route-reflector-client",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "route_reflector_client": "{{ not not route_reflector_client }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "send_community.standard",
            "getval": re.compile(
                r"""
                (?P<send_community>send-community)
                $""",
                re.VERBOSE,
            ),
            "setval": "send-community",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "send_community": {
                                            "standard": "{{ True if send_community is defined }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "send_community.extended",
            "getval": re.compile(
                r"""
                send-community
                \s(?P<extended>extended)
                $""",
                re.VERBOSE,
            ),
            "setval": "send-community extended",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "send_community": {
                                            "extended": "{{ True if extended is defined }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "soft_reconfiguration_inbound",
            "getval": re.compile(
                r"""
                (?P<soft_reconfiguration_inbound>soft-reconfiguration\sinbound)
                (\s(?P<always>always))?
                $""",
                re.VERBOSE,
            ),
            "setval": "soft-reconfiguration inbound{{ ' always' if soft_reconfiguration_inbound.always|d(False) else '' }}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "soft_reconfiguration_inbound": {
                                            "set": "{{ True if soft_reconfiguration_inbound is defined and always is undefined }}",
                                            "always": "{{ not not always }}",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "soo",
            "getval": re.compile(
                r"""
                soo\s(?P<soo>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": "soo {{ soo }}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "soo": "{{ soo }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "suppress_inactive",
            "getval": re.compile(
                r"""
                (?P<suppress_inactive>suppress-inactive)
                $""",
                re.VERBOSE,
            ),
            "setval": "suppress-inactive",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "suppress_inactive": "{{ not not suppress_inactive }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "unsuppress_map",
            "getval": re.compile(
                r"""
                unsuppress-map\s(?P<unsuppress_map>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": "unsuppress-map {{ unsuppress_map }}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "unsuppress_map": "{{ unsuppress_map }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "weight",
            "getval": re.compile(
                r"""
                weight\s(?P<weight>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "weight {{ weight }}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{ neighbor }}": {
                                "address_family": {
                                    '{{ afi + "_" + safi|d() }}': {
                                        "weight": "{{ weight }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    ]
    # fmt: on
