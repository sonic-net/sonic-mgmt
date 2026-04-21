# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The Bgp_templates parser templates file. This contains
a list of parser definitions and associated functions that
facilitates both facts gathering and native command generation for
the given network resource.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


def _tmplt_bfd(proc):
    bfd = proc.get("bfd", {})
    cmd = None

    if bfd.get("set"):
        cmd = "bfd"
    if bfd.get("singlehop"):
        cmd = "bfd singlehop"
    elif bfd.get("multihop", {}).get("set"):
        cmd = "bfd multihop"

    return cmd


def _tmplt_path_attribute(proc):
    cmd = "path-attribute {action}".format(**proc)

    if "type" in proc:
        cmd += " {type}".format(**proc)
    elif "range" in proc:
        cmd += " range {start} {end}".format(**proc["range"])
    cmd += " in"
    return cmd


class Bgp_templatesTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(Bgp_templatesTemplate, self).__init__(lines=lines, tmplt=self, module=module)

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
        },
        {
            "name": "peer.name",
            "getval": re.compile(
                r"""
                template\speer\s(?P<name>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "template peer {{ name }}",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "name": "{{ name }}",
                    },
                },
            },
            "shared": True,
        },
        {
            "name": "bfd",
            "getval": re.compile(
                r"""
                (?P<bfd>bfd)
                (\s(?P<singlehop>singlehop))?
                (\s(?P<multihop>multihop))?
                $""", re.VERBOSE,
            ),
            "setval": _tmplt_bfd,
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "bfd": {
                            "set": "{{ True if bfd is defined and singlehop is undefined and multihop is undefined else None }}",
                            "singlehop": "{{ not not singlehop }}",
                            "multihop": {
                                "set": "{{ not not multihop }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bfd.multihop.interval",
            "getval": re.compile(
                r"""
                bfd\smultihop\sinterval
                \s(?P<tx_interval>\d+)
                \smin_rx\s(?P<min_rx_interval>\d+)
                \smultiplier\s(?P<multiplier>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "bfd multihop interval"
                      " {{ bfd.multihop.interval.tx_interval }}"
                      " min_rx {{ bfd.multihop.interval.min_rx_interval }}"
                      " multiplier {{ bfd.multihop.interval.multiplier }}",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "bfd": {
                            "multihop": {
                                "interval": {
                                    "tx_interval": "{{ tx_interval }}",
                                    "min_rx_interval": "{{ min_rx_interval }}",
                                    "multiplier": "{{ multiplier }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bmp_activate_server",
            "getval": re.compile(
                r"""
                bmp-activate-server\s(?P<bmp_activate_server>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "bmp-activate-server {{ bmp_activate_server }}",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "bmp_activate_server": "{{ bmp_activate_server }}",
                    },
                },
            },
        },
        {
            "name": "capability",
            "getval": re.compile(
                r"""
                capability\ssuppress\s(?P<suppress_4_byte_as>4-byte-as)
                $""", re.VERBOSE,
            ),
            "setval": "capability suppress 4-byte-as",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "capability": {
                            "suppress_4_byte_as": "{{ not not suppress_4_byte_as }}",
                        },
                    },
                },
            },
        },
        {
            "name": "description",
            "getval": re.compile(
                r"""
                description\s(?P<description>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "description {{ description }}",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "description": "{{ description }}",
                    },
                },
            },
        },
        {
            "name": "disable_connected_check",
            "getval": re.compile(
                r"""
                (?P<disable_connected_check>disable-connected-check)
                $""", re.VERBOSE,
            ),
            "setval": "disable-connected-check",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "disable_connected_check": "{{ not not disable_connected_check }}",
                    },
                },
            },
        },
        {
            "name": "dont_capability_negotiate",
            "getval": re.compile(
                r"""
                (?P<dont_capability_negotiate>dont-capability-negotiate)
                $""", re.VERBOSE,
            ),
            "setval": "dont-capability-negotiate",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "dont_capability_negotiate": "{{ not not dont_capability_negotiate }}",
                    },
                },
            },
        },
        {
            "name": "dscp",
            "getval": re.compile(
                r"""
                dscp\s(?P<dscp>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "dscp {{ dscp }}",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "dscp": "{{ dscp }}",
                    },
                },
            },
        },
        {
            "name": "dynamic_capability",
            "getval": re.compile(
                r"""
                (?P<dynamic_capability>dynamic-capability)
                $""", re.VERBOSE,
            ),
            "setval": "dynamic-capability",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "dynamic_capability": "{{ not not dynamic_capability }}",
                    },
                },
            },
        },
        {
            "name": "ebgp_multihop",
            "getval": re.compile(
                r"""
                ebgp-multihop\s(?P<ebgp_multihop>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "ebgp-multihop {{ ebgp_multihop }}",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "ebgp_multihop": "{{ ebgp_multihop }}",
                    },
                },
            },
        },
        {
            "name": "graceful_shutdown",
            "getval": re.compile(
                r"""
                graceful-shutdown
                \s(?P<activate>activate)
                (\sroute-map\s(?P<route_map>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "graceful-shutdown activate"
                      "{{ (' route-map ' + graceful_shutdown.activate.route_map) if graceful_shutdown.activate.route_map is defined }}",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "graceful_shutdown": {
                            "activate": {
                                "set": "{{ True if activate is defined and route_map is undefined else None }}",
                                "route_map": "{{ route_map }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "inherit.peer_session",
            "getval": re.compile(
                r"""
                inherit
                \speer-session\s(?P<peer_session>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "inherit peer-session {{ inherit.peer_session }}",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "inherit": {
                            "peer_session": "{{ peer_session }}",
                        },
                    },
                },
            },
        },
        {
            "name": "local_as",
            "getval": re.compile(
                r"""
                local-as\s(?P<local_as>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "local-as {{ local_as }}",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "local_as": "{{ local_as }}",
                    },
                },
            },
        },
        {
            "name": "log_neighbor_changes",
            "getval": re.compile(
                r"""
                (?P<log_neighbor_changes>log-neighbor-changes)
                (\s(?P<disable>disable))?
                $""", re.VERBOSE,
            ),
            "setval": "log-neighbor-changes{{ ' disable' if log_neighbor_changes.disable is defined }}",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "log_neighbor_changes": {
                            "set": "{{ True if log_neighbor_changes is defined and disable is undefined }}",
                            "disable": "{{ not not disable }}",
                        },
                    },
                },
            },
        },
        {
            "name": "low_memory",
            "getval": re.compile(
                r"""
                low-memory\s(?P<exempt>exempt)
                $""", re.VERBOSE,
            ),
            "setval": "low-memory exempt",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "low_memory": {
                            "exempt": "{{ not not exempt }}",
                        },
                    },
                },
            },
        },
        {
            "name": "password",
            "getval": re.compile(
                r"""
                password\s(?P<encryption>\d+)\s(?P<key>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "password{{ (' ' + password.encryption|string) if password.encryption is defined }} {{ password.key }}",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "password": {
                            "encryption": "{{ encryption }}",
                            "key": "{{ key }}",
                        },
                    },
                },
            },
        },
        {
            "name": "path_attribute",
            "getval": re.compile(
                r"""
                path-attribute\s(?P<action>\S+)\s
                (?P<type>\d+)?
                (range\s(?P<start>\d+)\s(?P<end>\d+))?
                \sin
                $""", re.VERBOSE,
            ),
            "setval": _tmplt_path_attribute,
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "path_attribute": [
                            {
                                "action": "{{ action }}",
                                "type": "{{ type if type is defined else None }}",
                                "range": {
                                    "start": "{{ start if start is defined }}",
                                    "end": "{{ end if end is defined }}",
                                },
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "remote_as",
            "getval": re.compile(
                r"""
                remote-as\s(?P<remote_as>.+)
                $""", re.VERBOSE,
            ),
            "setval": "remote-as {{ remote_as }}",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "remote_as": "{{ remote_as|string }}",
                    },
                },
            },
        },
        {
            "name": "remove_private_as",
            "getval": re.compile(
                r"""
                (?P<remove_private_as>remove-private-as)
                (\s(?P<all>all))?
                (\s(?P<replace_as>replace-as))?
                $""", re.VERBOSE,
            ),
            "setval": "remove-private-as"
                      "{{ ' replace-as' if remove_private_as.replace_as|d(False) else '' }}"
                      "{{ ' all' if remove_private_as.all|d(False) else '' }}",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "remove_private_as": {
                            "set": "{{ True if remove_private_as is defined and replace_as is undefined and all is undefined else None }}",
                            "replace_as": "{{ not not replace_as }}",
                            "all": "{{ not not all }}",
                        },
                    },
                },
            },
        },
        {
            "name": "shutdown",
            "getval": re.compile(
                r"""
                (?P<shutdown>shutdown)
                $""", re.VERBOSE,
            ),
            "setval": "shutdown",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "shutdown": "{{ not not shutdown }}",
                    },
                },
            },
        },
        {
            "name": "timers",
            "getval": re.compile(
                r"""
                timers\s(?P<keepalive>\d+)\s(?P<holdtime>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "timers {{ timers.keepalive }} {{ timers.holdtime }}",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "timers": {
                            "keepalive": "{{ keepalive }}",
                            "holdtime": "{{ holdtime }}",
                        },
                    },
                },
            },
        },
        {
            "name": "transport",
            "getval": re.compile(
                r"""
                transport\sconnection-mode
                \s(?P<passive>passive)
                $""", re.VERBOSE,
            ),
            "setval": "transport connection-mode passive",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "transport": {
                            "connection_mode": {
                                "passive": "{{ not not passive }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ttl_security",
            "getval": re.compile(
                r"""
                ttl-security\shops\s(?P<hops>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "ttl-security hops {{ ttl_security.hops|string }}",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "ttl_security": {
                            "hops": "{{ hops }}",
                        },
                    },
                },
            },
        },
        {
            "name": "update_source",
            "getval": re.compile(
                r"""
                update-source\s(?P<update_source>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "update-source {{ update_source }}",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "update_source": "{{ update_source }}",
                    },
                },
            },
        },
        # start template AF parsers
        {
            "name": "address_family",
            "getval": re.compile(
                r"""
                template\speer\s(?P<name>\S+)
                \saddress-family\s(?P<afi>\S+)\s(?P<safi>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": "address-family {{ afi }}{{ (' ' + safi) if safi is defined else '' }}",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "address_family": {
                            "{{ afi + '_' + safi|d() }}": {
                                "afi": "{{ afi }}",
                                "safi": "{{ safi }}",
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
                "neighbor": {
                    "{{ name }}": {
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
                "neighbor": {
                    "{{ name }}": {
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
                "neighbor": {
                    "{{ name }}": {
                        "address_family": {
                            '{{ afi + "_" + safi|d() }}': {
                                "advertisement_interval": "{{ advertisement_interval }}",
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
                (?P<allowas_in>allowas-in)\s(?P<max_occurences>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "allowas-in{{ ' ' + allowas_in.max_occurences|string if allowas_in.max_occurences is defined else '' }}",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "address_family": {
                            "{{ afi + '_' + safi|d() }}": {
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
                "neighbor": {
                    "{{ name }}": {
                        "address_family": {
                            "{{ afi + '_' + safi|d() }}": {
                                "as_override": "{{ not not as_override }}",
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
                "neighbor": {
                    "{{ name }}": {
                        "address_family": {
                            "{{ afi + '_' + safi|d() }}": {
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
                "neighbor": {
                    "{{ name }}": {
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
                "neighbor": {
                    "{{ name }}": {
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
                "neighbor": {
                    "{{ name }}": {
                        "address_family": {
                            '{{ afi + "_" + safi|d() }}': {
                                "disable_peer_as_check": "{{ not not disable_peer_as_check }}",
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
                "neighbor": {
                    "{{ name }}": {
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
                "neighbor": {
                    "{{ name }}": {
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
        {
            "name": "inherit.peer_policy",
            "getval": re.compile(
                r"""
                inherit\speer-policy
                \s(?P<peer_policy>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": "inherit peer-policy {{ inherit.peer_policy }}",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "address_family": {
                            '{{ afi + "_" + safi|d() }}': {
                                "inherit": {
                                    "peer_policy": "{{ peer_policy }}",
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
            "setval": "maximum-prefix"
                      "{{ ' ' + maximum_prefix.max_prefix_limit|string if maximum_prefix.max_prefix_limit|d(None) else '' }}"
                      "{{ ' ' + maximum_prefix.generate_warning_threshold|string if maximum_prefix.generate_warning_threshold|d(None) else '' }}"
                      "{{ ' restart ' + maximum_prefix.restart_interval|string if maximum_prefix.restart_interval|d(None) else '' }}"
                      "{{ ' warning-only' if maximum_prefix.warning_only|d(False) else '' }}",
            "result": {
                "neighbor": {
                    "{{ name }}": {
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
                "neighbor": {
                    "{{ name }}": {
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
                "neighbor": {
                    "{{ name }}": {
                        "address_family": {
                            '{{ afi + "_" + safi|d() }}': {
                                "next_hop_third_party": "{{ not next_hop_third_party }}",
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
                "neighbor": {
                    "{{ name }}": {
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
                "neighbor": {
                    "{{ name }}": {
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
                "neighbor": {
                    "{{ name }}": {
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
                "neighbor": {
                    "{{ name }}": {
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
                "neighbor": {
                    "{{ name }}": {
                        "address_family": {
                            '{{ afi + "_" + safi|d() }}': {
                                "route_reflector_client": "{{ not not route_reflector_client }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "send_community_standard",
            "getval": re.compile(
                r"""
                (?P<send_community_std>send-community)
                $""",
                re.VERBOSE,
            ),
            "setval": "send-community",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "address_family": {
                            '{{ afi + "_" + safi|d() }}': {
                                "send_community_std": "{{ not not send_community_std }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "send_community_extended",
            "getval": re.compile(
                r"""
                (?P<send_community_ext>send-community\sextended)
                $""",
                re.VERBOSE,
            ),
            "setval": "send-community extended",
            "result": {
                "neighbor": {
                    "{{ name }}": {
                        "address_family": {
                            '{{ afi + "_" + safi|d() }}': {
                                "send_community_ext": "{{ not not send_community_ext }}",
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
                "neighbor": {
                    "{{ name }}": {
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
                "neighbor": {
                    "{{ name }}": {
                        "address_family": {
                            '{{ afi + "_" + safi|d() }}': {
                                "soo": "{{ soo }}",
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
                "neighbor": {
                    "{{ name }}": {
                        "address_family": {
                            '{{ afi + "_" + safi|d() }}': {
                                "suppress_inactive": "{{ not not suppress_inactive }}",
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
                "neighbor": {
                    "{{ name }}": {
                        "address_family": {
                            '{{ afi + "_" + safi|d() }}': {
                                "unsuppress_map": "{{ unsuppress_map }}",
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
                "neighbor": {
                    "{{ name }}": {
                        "address_family": {
                            '{{ afi + "_" + safi|d() }}': {
                                "weight": "{{ weight }}",
                            },
                        },
                    },
                },
            },
        },
    ]
    # fmt: on
