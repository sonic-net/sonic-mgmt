# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The Route_maps parser templates file. This contains
a list of parser definitions and associated functions that
facilitates both facts gathering and native command generation for
the given network resource.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


def _tmplt_route_map_set_aspath_prepend(config_data):
    el = config_data["entries"]
    command = "set as-path prepend "
    c = el["set"]["as_path"]["prepend"]
    if c.get("last_as"):
        command += "last-as " + str(c["last_as"])
    if c.get("as_number"):
        num = " ".join(c["as_number"].split(","))
        command += num
    return command


def _tmplt_route_map_set_aspath_match(config_data):
    el = config_data["entries"]
    command = "set as-path match all replacement "
    c = el["set"]["as_path"]["match"]
    if c.get("none"):
        command += "none"
    if c.get("as_number"):
        num = str(c["as_number"])
        command += num
    return command


def _tmplt_route_map_extcommunity_lbw(config_data):
    config_data = config_data["entries"]["set"]["extcommunity"]["lbw"]
    command = "set extcommunity lbw "
    if config_data.get("aggregate"):
        command += "aggregate " + config_data["value"]
    if not config_data.get("aggregate") and config_data.get("value"):
        command += config_data["value"]
    if config_data.get("divide"):
        command += "divide " + config_data["divide"]
    return command


def _tmplt_route_map_extcommunity_rt(config_data):
    config_data = config_data["entries"]["set"]["extcommunity"]["rt"]
    command = "set extcommunity rt " + config_data["vpn"]
    if config_data.get("additive"):
        command += " additive"
    if config_data.get("delete"):
        command += " delete"
    return command


def _tmplt_route_maps_subroutemap(config_data):
    command = ""
    if config_data["entries"].get("sub_route_map"):
        command = "sub-route-map " + config_data["entries"]["sub_route_map"]["name"]
    if config_data["entries"]["sub_route_map"].get("invert_result"):
        command += " invert-result"
    return command


def _tmplt_route_map_extcommunity_soo(config_data):
    config_data = config_data["entries"]["set"]["extcommunity"]["soo"]
    command = "set extcommunity soo " + config_data["vpn"]
    if config_data.get("additive"):
        command += " additive"
    if config_data.get("delete"):
        command += " delete"
    return command


def _tmplt_route_map_ip(config_data):
    config_data = config_data["entries"]["set"]
    command = ""
    if config_data.get("ip"):
        command = "set ip next-hop "
        k = "ip"
    elif config_data.get("ipv6"):
        command = "set ipv6 next-hop "
        k = "ipv6"
    if config_data[k].get("address"):
        command += config_data[k]["address"]
    elif config_data[k].get("unchanged"):
        command += "unchanged"
    elif config_data[k].get("peer_address"):
        command += "peer-address"
    return command


def _tmplt_route_maps_metric(config_data):
    config_data = config_data["entries"]["set"]["metric"]
    command = "set metric"
    if config_data.get("value"):
        command += " " + config_data["value"]
    if config_data.get("add"):
        command += " +" + config_data["add"]
    if config_data.get("igp_param"):
        command += " " + config_data["igp_param"]
    return command


def _tmplt_route_maps_nexthop(config_data):
    config_data = config_data["entries"]["set"]["nexthop"]
    command = "set next-hop igp-metric "
    if config_data.get("max_metric"):
        command += "max-metric"
    if config_data.get("value"):
        command += config_data["value"]
    return command


def _tmplt_route_map_match_aggregator_role(config_data):
    config_data = config_data["entries"]["match"]["aggregator_role"]
    command = "match aggregator-role contributor"
    if config_data.get("route_map"):
        command += " aggregate-attributes " + config_data["route_map"]
    return command


def _tmplt_route_map_match_aspath(config_data):
    config_data = config_data["entries"]["match"]["as_path"]
    command = "match as-path "
    if config_data.get("length"):
        command += "length " + config_data["length"]
    if config_data.get("path_list"):
        command += config_data["path_list"]
    return command


def _tmplt_route_map_match_invert_aggregator_role(config_data):
    config_data = config_data["entries"]["match"]["invert_result"]["aggregate_role"]
    command = "match invert-result as-path aggregate-role contributor"
    if config_data.get("route_map"):
        command += " aggregator-attributes " + config_data["route_map"]
    return command


def _tmplt_route_map_match_invert_aspath(config_data):
    config_data = config_data["entries"]["match"]["invert_result"]["as_path"]
    command = "match invert-result as-path "
    if config_data.get("length"):
        command += "length " + config_data["length"]
    if config_data.get("path_list"):
        command += config_data["path_list"]
    return command


def _tmplt_route_map_match_ip_address(config_data):
    command = ""
    config_data = config_data["entries"]["match"]["ip"]
    if config_data.get("address"):
        config_data = config_data["address"]
        command = "match ip address "
        if config_data.get("dynamic"):
            command += "dynamic"
        if config_data.get("access_list"):
            command += "access-list " + config_data["access_list"]
        if config_data.get("prefix_list"):
            command += "prefix-list " + config_data["prefix_list"]
    return command


def _tmplt_route_map_match_ipv6_address(config_data):
    command = ""
    config_data = config_data["entries"]["match"]["ipv6"]
    if config_data.get("address"):
        config_data = config_data["address"]
        command = "match ipv6 address "
        if config_data.get("dynamic"):
            command += "dynamic"
        if config_data.get("access_list"):
            command += "access-list " + config_data["access_list"]
        if config_data.get("prefix_list"):
            command += "prefix-list " + config_data["prefix_list"]
    return command


def _tmplt_route_map_match_ip(config_data):
    command = ""
    config_data = config_data["entries"]["match"]["ip"]
    if "address" not in config_data:
        command = "match ip "
        if config_data.get("next_hop"):
            command += "next-hop prefix-list " + config_data["next_hop"]
        elif config_data.get("resolved_next_hop"):
            command += "resolved-next-hop prefix-list " + config_data["resolved_next_hop"]
    return command


def _tmplt_route_map_match_ipv6(config_data):
    command = ""
    config_data = config_data["entries"]["match"]["ipv6"]
    if "address" not in config_data:
        command = "match ipv6 "
        if config_data.get("next_hop"):
            command += "next-hop prefix-list " + config_data["next_hop"]
        elif config_data.get("resolved_next_hop"):
            command += "resolved-next-hop prefix-list " + config_data["resolved_next_hop"]
    return command


def _tmplt_route_maps_match_metric(config_data):
    config_data = config_data["entries"]["match"]["metric"]
    command = "match metric"
    if config_data.get("value"):
        command += " " + config_data["value"]
    return command


class Route_mapsTemplate(NetworkTemplate):
    def __init__(self, lines=None):
        super(Route_mapsTemplate, self).__init__(lines=lines, tmplt=self)

    # fmt: off
    PARSERS = [
        {
            "name": "route_map.entries",
            "getval": re.compile(
                r"""
                \s*route-map
                \s+(?P<map_name>\S+)
                \s+(?P<action>deny|permit)
                \s+(?P<seq>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "route-map {{ route_map }} {{ entries.action }} {{ entries.sequence }}",
            "compval": "entries",
            "result": {
                "route_map": "{{ map_name }}",
                "entries": [
                    {
                        "action": "{{ action }}",
                        "sequence": "{{ seq }}",
                    },
                ],
            },
            "shared": True,
        },
        {
            "name": "route_map.action",
            "getval": re.compile(
                r"""
                \s*route-map
                \s+(?P<map_name>\S+)
                \s+(?P<action>deny|permit)
                $""",
                re.VERBOSE,
            ),
            "setval": "route-map {{ route_map }} {{ entries.action }}",
            "compval": "entries.action",
            "result": {
                "route_map": "{{ map_name }}",
                "entries": [
                    {
                        "action": "{{ action }}",
                    },
                ],
            },
            "shared": True,
        },
        {
            "name": "route_map.name",
            "getval": re.compile(
                r"""
                \s*route-map
                \s+(?P<map_name>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": "route-map {{ route_map }}",
            "compval": "route_map",
            "result": {
                "route_map": "{{ map_name }}",
            },
            "shared": True,
        },
        {
            "name": "route_map.statement.entries",
            "getval": re.compile(
                r"""
                \s*route-map
                \s+(?P<map_name>\S+)
                \s+statement
                \s+(?P<statement>\S+)
                \s+(?P<action>deny|permit)
                \s+(?P<seq>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "route-map {{ route_map }} statement {{ entries.statement }}" +
                      " {{ entries.action }} {{ entries.sequence }}",
            "compval": "entries.statement",
            "result": {
                "route_map": "{{ map_name }}",
                "entries": [
                    {
                        "statement": "{{ statement }}",
                        "action": "{{ action }}",
                        "sequence": "{{ seq }}",
                    },
                ],
            },
            "shared": True,
        },
        {
            "name": "route_map.statement.action",
            "getval": re.compile(
                r"""
                \s*route-map
                \s+(?P<map_name>\S+)
                \s+statement
                \s+(?P<statement>\S+)
                \s+(?P<action>deny|permit)
                $""",
                re.VERBOSE,
            ),
            "setval": "route-map {{ route_map }} statement {{ entries.statement }} {{ entries.action }}",
            "compval": "entries.statement",
            "result": {
                "route_map": "{{ map_name }}",
                "entries": [
                    {
                        "statement": "{{ statement }}",
                        "action": "{{ action }}",
                    },
                ],
            },
            "shared": True,
        },
        {
            "name": "route_map.statement.name",
            "getval": re.compile(
                r"""
                \s*route-map
                \s+(?P<map_name>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": "route-map {{ route_map }} statement {{ entries.statement }}",
            "compval": "entries.statement",
            "result": {
                "route_map": "{{ map_name }}",
                "entries": [
                    {
                        "statement": "{{ statement }}",
                    },
                ],
            },
            "shared": True,
        },
        {
            "name": "continue",
            "getval": re.compile(
                r"""
                \s*continue
                \s+(?P<num>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "continue {{ entries.continue_sequence }}",
            "compval": "entries.continue_sequence",
            "result": {
                "entries": [
                    {
                        "continue_sequence": "{{ num }}",
                    },
                ],
            },
        },
        {
            "name": "route_map.copy",
            "getval": re.compile(
                r"""
                \s*route-map
                \s+(?P<map_name>\S+)
                \s+copy
                \s+(?P<name>\S+)
                \s*(?P<overwrite>overwrite)*
                $""",
                re.VERBOSE,
            ),
            "setval": "route-map {{ route_map }} copy {{ entries.source.source_map_name }}" +
                      "{{ (' ' + overwrite) if overwrite is defined }}",
            "compval": "entries.source",
            "result": {
                "route_map": "{{ map_name }}",
                "entries": [
                    {
                        "source": {
                            "action": "copy",
                            "source_map_name": "{{ name }}",
                            "overwrite": "{{ True if overwrite is defined }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "route_map.rename",
            "getval": re.compile(
                r"""
                \s*route-map
                \s+(?P<map_name>\S+)
                \s+rename
                \s+(?P<name>\S+)
                \s*(?P<overwrite>overwrite)*
                $""",
                re.VERBOSE,
            ),
            "setval": "route-map {{ route_map }} rename {{ entries.source.source_map_name }}" +
                      "{{ (' ' + overwrite) if overwrite is defined }}",
            "compval": "entries.source",
            "result": {
                "route_map": "{{ map_name }}",
                "entries": [
                    {
                        "source": {
                            "action": "rename",
                            "source_map_name": "{{ name }}",
                            "overwrite": "{{ True if overwrite is defined }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "description",
            "getval": re.compile(
                r"""
                \s*description
                \s+(?P<desc>.+)
                $""",
                re.VERBOSE,
            ),
            "setval": "description {{ entries.description }}",
            "compval": "entries.description",
            "remval": "description",
            "result": {
                "entries": [
                    {
                        "description": "{{ desc }}",
                    },
                ],
            },
        },
        {
            "name": "sub_route_map",
            "getval": re.compile(
                r"""
                \s*sub-route-map
                \s*(?P<invert>invert-result)*
                \s+(?P<map>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_route_maps_subroutemap,
            "compval": "entries.sub_route_map",
            "result": {
                "entries": [
                    {
                        "sub_route_map": {
                            "name": "{{ map }}",
                            "invert_result": "{{ True if invert is defined }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "set.as_path.prepend",
            "getval": re.compile(
                r"""
                \s*set\s+as-path\sprepend
                \s*(?P<lastas>last-as .+)*
                \s*(?P<as>[^a-zA-Z]+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_route_map_set_aspath_prepend,
            "compval": "entries.set.as_path.prepend",
            "result": {
                "entries": [
                    {
                        "set": {
                            "as_path": {
                                "prepend": {
                                    "last_as": "{{ lastas.split(" ")[1] if lastas is defined }}",
                                    "as_number": "{{ ','.join(as.split(' ')) if as is defined }}",
                                },
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "set.as_path.match",
            "getval": re.compile(
                r"""
                \s*set\s+as-path\smatch\sall\replacement
                \s*(?P<none>none)*
                \s*(?P<as>.+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_route_map_set_aspath_match,
            "compval": "entries.set.as_path.match",
            "result": {
                "entries": [
                    {
                        "set": {
                            "as_path": {
                                "match": {
                                    "none": "{{ True if none is defined }}",
                                    "as_number": "{{ as }}",
                                },
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "set.bgp",
            "getval": re.compile(
                r"""
                \s*set\sbgp\sbestpath\sas-path\sweight
                \s+(?P<weight>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "set bgp bestpath as-path weight {{ entries.set.bgp }}",
            "compval": "entries.set.bgp",
            "result": {
                "entries": [
                    {
                        "set": {
                            "bgp": "{{ weight }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "set.community.graceful_shutdown",
            "getval": re.compile(
                r"""
                \s*set\scommunity\sGSHUT
                *$""",
                re.VERBOSE,
            ),
            "setval": "set community GSHUT",
            "compval": "entries.set.graceful_shutdown",
            "result": {
                "entries": [
                    {
                        "set": {
                            "graceful_shutdown": "{{ True }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "set.community.none",
            "getval": re.compile(
                r"""
                \s*set\scommunity\snone
                *$""",
                re.VERBOSE,
            ),
            "setval": "set community none",
            "compval": "entries.set.none",
            "result": {
                "entries": [
                    {
                        "set": {
                            "none": "{{ True }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "set.community.number",
            "getval": re.compile(
                r"""
                \s*set\scommunity
                \s+(?P<num>(\d+(:\d+)?\s*))+
                \s*(?P<action>additive|delete)*
                \s*(?P<donot>local-as|no-advertise|no-export)*
                $""",
                re.VERBOSE,
            ),
            "setval": "set community {{ entries.set.community_attributes.community.number }}" +
                      "{{ (' ' + action) if action is defined }}{{  (' ' + donot) if donot is defined }}",
            "compval": "entries.set.community_attributes.community",
            "result": {
                "entries": [
                    {
                        "set": {
                            "community_attributes": {
                                "community": {
                                    "number": "{{ num }}",
                                    "additive": "{{ True if action == 'additive' }}",
                                    "delete": "{{ True if action == 'delete' }}",
                                    '{{ "donot" }}': "{{ True if donot is defined }}",
                                },
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "set.community.list",
            "getval": re.compile(
                r"""
                \s*set\scommunity\s+community-list
                \s+(?P<name>\S+\s*)+
                \s*(?P<action>additive|delete)*
                \s*(?P<donot>local-as|no-advertise|no-export)*
                $""",
                re.VERBOSE,
            ),
            "setval": "set community {{ entries.set.community.name }}" +
                      "{{ (' ' + action) if action is defined }}{{  (' ' + donot) if donot is defined }}",
            "compval": "entries.set.community",
            "result": {
                "entries": [
                    {
                        "set": {
                            "community": {
                                "community_list": "{{ name }}",
                                "additive": "{{ True if action == 'additive' }}",
                                "delete": "{{ True if action == 'delete' }}",
                                '{{ "donot" }}': "{{ True if donot is defined }}",
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "set.community.internet",
            "getval": re.compile(
                r"""
                \s*set\scommunity\s+internet
                \s*(?P<action>additive|delete)*
                \s*(?P<donot>local-as|no-advertise|no-export)*
                $""",
                re.VERBOSE,
            ),
            "setval": "set community internet" +
                      "{{ (' ' + action) if action is defined }}{{  (' ' + donot) if donot is defined }}",
            "compval": "entries.set.community",
            "result": {
                "entries": [
                    {
                        "set": {
                            "community": {
                                "internet": "{{ true }}",
                                "additive": "{{ True if action == 'additive' }}",
                                "delete": "{{ True if action == 'delete' }}",
                                '{{ "donot" }}': "{{ True if donot is defined }}",
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "set.distance",
            "getval": re.compile(
                r"""
                \s*set\sdistance
                \s+(?P<distance>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "set distance {{ entries.set.distance }}",
            "compval": "entries.set.distance",
            "result": {
                "entries": [
                    {
                        "set": {
                            "distance": "{{ distance }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "set.evpn",
            "getval": re.compile(
                r"""
                \s*set\sevpn\snext-hop\sunchanged
                $""",
                re.VERBOSE,
            ),
            "setval": "set evpn next-hop unchanged",
            "compval": "entries.set.evpn",
            "result": {
                "entries": [
                    {
                        "set": {
                            "evpn": "{{ True }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "set.extcommunity.lbw",
            "getval": re.compile(
                r"""
                \s*set\sextcommunity\slbw
                \s*(?P<agg>aggregate)*
                \s*(?P<divide>divide\s\S+)*
                \s*(?P<value>\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_route_map_extcommunity_lbw,
            "compval": "entries.set.extcommunity.lbw",
            "result": {
                "entries": [
                    {
                        "set": {
                            "extcommunity": {
                                "lbw": {
                                    "value": "{{ value if value is defined }}",
                                    "aggregate": "{{ True if agg is defined }}",
                                    "divide": "{{ divide.split(" ")[1] if divide is defined }}",
                                },
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "set.extcommunity.none",
            "getval": re.compile(
                r"""
                \s*set\sextcommunity\snone
                $""",
                re.VERBOSE,
            ),
            "setval": "{{ set extcommunity none }}",
            "compval": "entries.set.extcommunity.none",
            "result": {
                "entries": [
                    {
                        "set": {
                            "extcommunity": {
                                "none": "{{ True }}",
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "set.extcommunity.rt",
            "getval": re.compile(
                r"""
                \s*set\sextcommunity\srt
                \s+(?P<asn>\S+)
                \s*(?P<action_add>additive)*
                \s*(?P<action_del>delete)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_route_map_extcommunity_rt,
            "compval": "entries.set.extcommunity.rt",
            "result": {
                "entries": [
                    {
                        "set": {
                            "extcommunity": {
                                "rt": {
                                    "vpn": "{{ asn }}",
                                    "additive": "{{ True if action_add is defined }}",
                                    "delete": "{{ True if action_del is defined }}",
                                },
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "set.extcommunity.soo",
            "getval": re.compile(
                r"""
                \s*set\sextcommunity\ssoo
                \s+(?P<asn>\S+)
                \s+(?P<action>additive|delete)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_route_map_extcommunity_soo,
            "compval": "entries.set.extcommunity.soo",
            "result": {
                "entries": [
                    {
                        "set": {
                            "extcommunity": {
                                "soo": {
                                    "vpn": "{{ asn }}",
                                    "additive": "{{ True if action == 'additive' }}",
                                    "delete": "{{ True if action == 'delete' }}",
                                },
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "set.ip",
            "getval": re.compile(
                r"""
                \s*set\sip\snext-hop
                \s+(?P<attr>peer-address|unchanged|[\d\.]+)
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_route_map_ip,
            "compval": "entries.set.ip",
            "result": {
                "entries": [
                    {
                        "set": {
                            "ip": {
                                "unchanged": "{{ True if attr == 'unchanged' }}",
                                "peer_address": "{{ True if attr == 'peer-address' }}",
                                "address": "{{ attr if attr != 'unchanged' and attr != 'peer-address' }}",
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "set.ipv6",
            "getval": re.compile(
                r"""
                \s*set\sipv6\snext-hop
                \s+(?P<attr>peer-address|unchanged|[\d\.]+)
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_route_map_ip,
            "compval": "entries.set.ipv6",
            "result": {
                "entries": [
                    {
                        "set": {
                            "ipv6": {
                                "unchanged": "{{ True if attr == 'unchanged' }}",
                                "peer_address": "{{ True if attr == 'peer-address' }}",
                                "address": "{{ attr if attr != 'unchanged' and attr != 'peer-address' }}",
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "set.isis",
            "getval": re.compile(
                r"""
                \s*set\sisis\slevel
                \s+(?P<level>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": "set isis level {{ entries.set.isis_level }}",
            "compval": "entries.set.isis_level",
            "result": {
                "entries": [
                    {
                        "set": {
                            "isis_level": "{{ level }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "set.local_pref",
            "getval": re.compile(
                r"""
                \s*set\slocal-preference
                \s+(?P<as>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "set local-preference {{ entries.set.local_preference }}",
            "compval": "entries.set.local_preference",
            "result": {
                "entries": [
                    {
                        "set": {
                            "local_preference": "{{ as }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "set.metric.value",
            "getval": re.compile(
                r"""
                \s*set\smetric
                \s*(?P<val>[+-]?\d+)*
                \s*(?P<operation>\+\S+)*
                \s*(?P<param>igp-metric|igp-nexthop-cost)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_route_maps_metric,
            "compval": "entries.set.metric",
            "result": {
                "entries": [
                    {
                        "set": {
                            "metric": {
                                "value": "{{ val | default('') | tojson  }}",
                                "add": "{{ operation.strip('+') }}",
                                "igp_param": "{{ param }}",
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "set.metric_type",
            "getval": re.compile(
                r"""
                \s*set\smetric-type
                \s+(?P<type>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": "set metric-type {{ entries.set.metric_type }}",
            "compval": "entries.set.local_preference",
            "result": {
                "entries": [
                    {
                        "set": {
                            "metric_type": "{{ type }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "set.nexthop",
            "getval": re.compile(
                r"""
                \s*set\snext-hop\sigp-metric
                \s*(?P<hop>\d+)*
                \s*(?P<max>max-metric)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_route_maps_nexthop,
            "compval": "entries.set.nexthop",
            "result": {
                "entries": [
                    {
                        "set": {
                            "nexthop": {
                                "value": "{{ hop if hop is defined }}",
                                "max_metric": "{{ True if max is defined }}",
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "set.origin",
            "getval": re.compile(
                r"""
                \s*set\sorigin
                \s+(?P<param>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": "set origin {{ entries.set.origin }}",
            "compval": "entries.set.origin",
            "result": {
                "entries": [
                    {
                        "set": {
                            "origin": "{{ param }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "set.segment_index",
            "getval": re.compile(
                r"""
                \s*set\ssegment-index
                \s+(?P<index>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "set segment-index {{ entries.set.segment_index }}",
            "compval": "entries.set.segment_index",
            "result": {
                "entries": [
                    {
                        "set": {
                            "segment_index": "{{ index }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "set.tag",
            "getval": re.compile(
                r"""
                \s*set\stag
                \s+(?P<val>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "set tag {{ entries.set.tag }}",
            "compval": "entries.set.tag",
            "result": {
                "entries": [
                    {
                        "set": {
                            "tag": "{{ val }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "set.weight",
            "getval": re.compile(
                r"""
                \s*set\sweight
                \s+(?P<val>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "set local-preference {{ entries.set.weight }}",
            "compval": "entries.set.weight",
            "result": {
                "entries": [
                    {
                        "set": {
                            "weight": "{{ val }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "match.aggregate_role",
            "getval": re.compile(
                r"""
                \s*match\s+aggregator-role\scontributor
                \s*(?P<map>aggregate-attributes \S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_route_map_match_aggregator_role,
            "compval": "entries.match.aggregator_role",
            "result": {
                "entries": [
                    {
                        "match": {
                            "aggregator_role": {
                                "contributor": "{{ True if map is not defined }}",
                                "route_map": "{{ map.split(" ")[1] }}",
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "match.as",
            "getval": re.compile(
                r"""
                \s*match\s+as
                \s+(?P<as>\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": "match as {{ entries.match.as }}",
            "compval": "entries.match.as",
            "result": {
                "entries": [
                    {
                        "match": {
                            "as": "{{ as }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "match.as_path",
            "getval": re.compile(
                r"""
                \s*match\s+as-path
                \s*(?P<len>length .+)*
                \s*(?P<path>\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_route_map_match_aspath,
            "compval": "entries.match.as_path.prepend",
            "result": {
                "entries": [
                    {
                        "match": {
                            "as_path": {
                                "path_list": "{{ path }}",
                                "length": "{{ len[7:] }}",
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "match.community.instances",
            "getval": re.compile(
                r"""
                \s*match\scommunity\sinstances
                \s+(?P<inst>.+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "match community instances {{ entries.match.community.instances }}",
            "compval": "entries.match.community.instances",
            "result": {
                "entries": [
                    {
                        "match": {
                            "community": {
                                "instances": "{{ inst }}",
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "match.community.list",
            "getval": re.compile(
                r"""
                \s*match\scommunity
                \s+(?P<comm>\S+)
                \s*(?P<mat>exact-match)*
                $""",
                re.VERBOSE,
            ),
            "setval": "match community {{ entries.match.community.community_list }}{{  (' exact-match') if mat is defined }}",
            "compval": "entries.match.community",
            "result": {
                "entries": [
                    {
                        "match": {
                            "community": {
                                "community_list": "{{ comm.strip() }}",
                                "exact_match": "{{ True if mat is defined }}",
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "match.extcommunity",
            "getval": re.compile(
                r"""
                \s*match\sextcommunity
                \s+(?P<list>.+\s*)
                \s*(?P<mat>exact-match)*
                $""",
                re.VERBOSE,
            ),
            "setval": "match extcommunity {{ entries.match.extcommunity.community_list }}{{  (' exact-match') if mat is defined }}",
            "compval": "entries.match.extcommunity",
            "result": {
                "entries": [
                    {
                        "match": {
                            "extcommunity": {
                                "community_list": "{{ list }}",
                                "exact_match": "{{ True if mat is defined }}",
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "match.invert.aggregate_role",
            "getval": re.compile(
                r"""
                \s*match\sinvert-result\saggregate-role\scontributor
                \s*(?P<map>aggregate-attributes \S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_route_map_match_invert_aggregator_role,
            "compval": "entries.match.invert_result.aggregate_role",
            "result": {
                "entries": [
                    {
                        "match": {
                            "invert_result": {
                                "aggregate_role": {
                                    "contributor": "{{ True if map is not defined }}",
                                    "route_map": "{{ map.split(" ")[1] }}",
                                },
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "match.invert.as_path",
            "getval": re.compile(
                r"""
                \s*match\sinvert-result\sas-path
                \s*(?P<len>length .+)*
                \s*(?P<path>\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_route_map_match_invert_aspath,
            "compval": "entries.match.invert_result.as_path.prepend",
            "result": {
                "entries": [
                    {
                        "match": {
                            "invert_result": {
                                "as_path": {
                                    "path_list": "{{ path }}",
                                    "length": "{{ len[7:] }}",
                                },
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "match.invert.community.instances",
            "getval": re.compile(
                r"""
                \s*match\sinvert-result\scommunity\sinstances
                \s+(?P<inst>.+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "match invert-result community instances {{ entries.match.community.instances }}",
            "compval": "entries.match.invert_result.community.instances",
            "result": {
                "entries": [
                    {
                        "match": {
                            "invert_result": {
                                "community": {
                                    "instances": "{{ inst }}",
                                },
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "match.invert.community.list",
            "getval": re.compile(
                r"""
                \s*match\sinvert-result\scommunity
                \s+(?P<list>.+\s*)
                \s*(?P<mat>exact-match)
                *$""",
                re.VERBOSE,
            ),
            "setval": "match invert-result community {{ entries.match.community.community_list }}{{  (' exact-match') if mat is defined }}",
            "compval": "entries.match.invert_result.community",
            "result": {
                "entries": [
                    {
                        "match": {
                            "invert_result": {
                                "community": {
                                    "community_list": "{{ list }}",
                                    "exact_match": "{{ True if mat is defined }}",
                                },
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "match.invert.extcommunity",
            "getval": re.compile(
                r"""
                \s*match\sinvert-result\sextcommunity
                \s+(?P<list>.+\s*)
                \s*(?P<mat>exact-match)
                *$""",
                re.VERBOSE,
            ),
            "setval": "match invert-result extcommunity" +
                      " {{ entries.match.extcommunity.community_list }}{{ (' exact-match') if mat is defined }}",
            "compval": "entries.match.invert_result.extcommunity",
            "result": {
                "entries": [
                    {
                        "match": {
                            "invert_result": {
                                "extcommunity": {
                                    "community_list": "{{ list }}",
                                    "exact_match": "{{ True if mat is defined }}",
                                },
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "match.interface",
            "getval": re.compile(
                r"""
                \s*match\sinterface
                \s+(?P<int>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": "match interface {{ entries.match.interface }}",
            "compval": "entries.match.interface",
            "result": {
                "entries": [
                    {
                        "match": {
                            "interface": "{{ int }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "match.ipaddress",
            "getval": re.compile(
                r"""
                \s*match\sip\saddress
                \s*(?P<dyn>dynamic)*
                \s+(?P<attr>\S+\s\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_route_map_match_ip_address,
            "compval": "entries.match.ip.address",
            "shared": True,
            "result": {
                "entries": [
                    {
                        "match": {
                            "ip": {
                                "address": {
                                    "dynamic": "{{ True if dynamic is defined }}",
                                    "access_list": '{{ attr.split(" ")[1] if attr.split(" ")[0] == "access-list" }}',
                                    "prefix_list": '{{ attr.split(" ")[1] if attr.split(" ")[0] == "prefix-list" }}',
                                },
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "match.ip",
            "getval": re.compile(
                r"""
                \s*match\sip
                \s+(?P<param>next-hop|resolved-next-hop)
                \s+prefix-list
                \s+(?P<prefix>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_route_map_match_ip,
            "compval": "entries.match.ip",
            "result": {
                "entries": [
                    {
                        "match": {
                            "ip": {
                                "next_hop": "{{ prefix if param == 'next-hop' }}",
                                "resolved_next_hop": "{{ prefix if param == 'resolved-next-hop' }}",
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "match.ipv6address",
            "getval": re.compile(
                r"""
                \s*match\sipv6\saddress
                \s*(?P<dyn>dynamic)*
                \s+(?P<attr>\S+\s\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_route_map_match_ipv6_address,
            "compval": "entries.match.ipv6.address",
            "shared": True,
            "result": {
                "entries": [
                    {
                        "match": {
                            "ipv6": {
                                "address": {
                                    "dynamic": "{{ True if dynamic is defined }}",
                                    "access_list": '{{ attr.split(" ")[1] if attr.split(" ")[0] == "access-list" }}',
                                    "prefix_list": '{{ attr.split(" ")[1] if attr.split(" ")[0] == "prefix-list" }}',
                                },
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "match.ipv6",
            "getval": re.compile(
                r"""
                \s*match\sipv6
                \s*(?P<param>next-hop|resolved-next-hop)
                \s+prefix-list
                \s+(?P<prefix>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_route_map_match_ipv6,
            "compval": "entries.match.ipv6",
            "result": {
                "entries": [
                    {
                        "match": {
                            "ipv6": {
                                "next_hop": "{{ prefix if param == 'next-hop' }}",
                                "resolved_next_hop": "{{ prefix if param == 'resolved-next-hop' }}",
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "match.largecommunity",
            "getval": re.compile(
                r"""
                \s*match\slarge-community
                \s+(?P<list>.+\s*)
                \s*(?P<mat>exact-match)
                *$""",
                re.VERBOSE,
            ),
            "setval": "match large-community {{ entries.match.large_community.community_list }}{{ (' exact-match') if mat is defined }}",
            "compval": "entries.match.large_community",
            "result": {
                "entries": [
                    {
                        "match": {
                            "large_community": {
                                "community_list": "{{ list }}",
                                "exact_match": "{{ True if mat is defined }}",
                            },
                        },
                    },
                ],
            },
        },
        {
            "name": "match.isis",
            "getval": re.compile(
                r"""
                \s*match\sisis\slevel
                \s+(?P<level>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": "match isis level {{ entries.match.isis_level }}",
            "compval": "entries.match.isis_level",
            "result": {
                "entries": [
                    {
                        "match": {
                            "isis_level": "{{ level }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "match.local_pref",
            "getval": re.compile(
                r"""
                \s*match\slocal-preference
                \s+(?P<as>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "match local-preference {{ entries.match.local_preference }}",
            "compval": "entries.match.local_preference",
            "result": {
                "entries": [
                    {
                        "match": {
                            "local_preference": "{{ as }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "match.metric",
            "getval": re.compile(
                r"""
                \s*match\smetric
                \s+(?P<val>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_route_maps_match_metric,
            "compval": "entries.match.metric",
            "result": {
                "entries": [
                    {
                        "match": {
                            "metric": "{{ val }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "match.metric_type",
            "getval": re.compile(
                r"""
                \s*match\smetric-type
                \s+(?P<type>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": "match metric-type {{ entries.match.metric_type }}",
            "compval": "entries.match.local_preference",
            "result": {
                "entries": [
                    {
                        "match": {
                            "metric_type": "{{ type }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "match.route_type",
            "getval": re.compile(
                r"""
                \s*match\sroute-type
                \s+(?P<type>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "match route-type {{ entries.match.route_type }}",
            "compval": "entries.match.route_type",
            "result": {
                "entries": [
                    {
                        "match": {
                            "route_type": "{{ type }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "match.routerid",
            "getval": re.compile(
                r"""
                \s*match\srouter-id\sprefix-list
                \s+(?P<id>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": "match router-id prefix-list {{ entries.match.router_id }}",
            "compval": "entries.match.router_id",
            "result": {
                "entries": [
                    {
                        "match": {
                            "router_id": "{{ id }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "match.source_protocol",
            "getval": re.compile(
                r"""
                \s*match\ssource-protocol
                \s+(?P<proto>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "match source-protocol {{ entries.match.source_protocol }}",
            "compval": "entries.match.source_protocol",
            "result": {
                "entries": [
                    {
                        "match": {
                            "source_protocol": "{{ proto }}",
                        },
                    },
                ],
            },
        },
        {
            "name": "match.tag",
            "getval": re.compile(
                r"""
                \s*match\stag
                \s+(?P<val>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "match tag {{ entries.match.tag }}",
            "compval": "entries.match.tag",
            "result": {
                "entries": [
                    {
                        "match": {
                            "tag": "{{ val }}",
                        },
                    },
                ],
            },
        },
    ]
    # fmt: on
