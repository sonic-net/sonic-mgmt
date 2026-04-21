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


def _tmplt_set_extcomm_rt(data):
    cmd = "set extcommunity rt"
    extcomm_numbers = " ".join(data.get("extcommunity_numbers", []))
    if extcomm_numbers:
        cmd += " " + extcomm_numbers
    if data.get("additive"):
        cmd += " additive"

    return cmd


def _tmplt_match_ip_multicast(data):
    cmd = "match ip multicast"
    multicast = data["match"]["ip"]["multicast"]

    if "source" in multicast:
        cmd += " source {source}".format(**multicast)

    if "prefix" in multicast.get("group", {}):
        cmd += " group {prefix}".format(**multicast["group"])
    else:
        if "first" in multicast.get("group_range", {}):
            cmd += " group-range {first}".format(**multicast["group_range"])
        if "last" in multicast.get("group_range", {}):
            cmd += " to {last}".format(**multicast["group_range"])

    if "rp" in multicast:
        cmd += " rp {prefix}".format(**multicast["rp"])
        if "rp_type" in multicast["rp"]:
            cmd += " rp-type {rp_type}".format(**multicast["rp"])

    return cmd


def _tmplt_match_ipv6_multicast(data):
    cmd = "match ipv6 multicast"
    multicast = data["match"]["ipv6"]["multicast"]

    if "source" in multicast:
        cmd += " source {source}".format(**multicast)

    if "prefix" in multicast.get("group", {}):
        cmd += " group {prefix}".format(**multicast["group"])
    else:
        if "first" in multicast.get("group_range", {}):
            cmd += " group-range {first}".format(**multicast["group_range"])
        if "last" in multicast.get("group_range", {}):
            cmd += " to {last}".format(**multicast["group_range"])

    if "rp" in multicast:
        cmd += " rp {prefix}".format(**multicast["rp"])
        if "rp_type" in multicast["rp"]:
            cmd += " rp-type {rp_type}".format(**multicast["rp"])

    return cmd


def _tmplt_set_metric(data):
    cmd = "set metric"
    metric = data["set"]["metric"]

    for x in [
        "bandwidth",
        "igrp_delay_metric",
        "igrp_reliability_metric",
        "igrp_effective_bandwidth_metric",
        "igrp_mtu",
    ]:
        if x in metric:
            cmd += " {0}".format(metric[x])

    return cmd


def _tmplt_set_ip_next_hop_verify_availability(data):
    cmd = []
    for each in data["set"]["ip"]["next_hop"]["verify_availability"]:
        cmd_tmpl = "set ip next-hop verify-availability"
        cmd_tmpl += " {address} track {track}".format(**each)
        if "load_share" in each and each["load_share"]:
            cmd_tmpl += " load-share"
        if "force_order" in each and each["force_order"]:
            cmd_tmpl += " force-order"
        if "drop_on_fail" in each and each["drop_on_fail"]:
            cmd_tmpl += " drop-on-fail"
        cmd.append(cmd_tmpl)
    return cmd


class Route_mapsTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(Route_mapsTemplate, self).__init__(lines=lines, tmplt=self, module=module)

    # fmt: off
    PARSERS = [
        {
            "name": "route_map",
            "getval": re.compile(
                r"""
                ^route-map\s(?P<route_map>\S+)\s(?P<action>\S+)\s(?P<sequence>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "route-map {{ route_map }}"
                      "{{ ' ' + action if action is defined else '' }}"
                      "{{ ' ' + sequence|string if sequence is defined else '' }}",
            "result": {
                "{{ route_map }}": {
                    "route_map": "{{ route_map }}",
                    "entries": {
                        "{{ sequence }}": {
                            "sequence": "{{ sequence }}",
                            "action": "{{ action }}",
                        },
                    },
                },
            },
            "shared": True,
        },
        {
            "name": "continue_sequence",
            "getval": re.compile(
                r"""
                \s+continue\s(?P<continue_sequence>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "continue {{ continue_sequence }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "continue_sequence": "{{ continue_sequence }}",
                        },
                    },
                },
            },
        },
        {
            "name": "description",
            "getval": re.compile(
                r"""
                \s+description\s(?P<description>.+)
                $""", re.VERBOSE,
            ),
            "setval": "description {{ description }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "description": "{{ description }}",
                        },
                    },
                },
            },
        },
        {
            "name": "match.as_number.asn",
            "getval": re.compile(
                r"""
                \s+match\sas-number
                (?!\sas-path-list)
                \s(?P<asn>.+)\s*
                $""", re.VERBOSE,
            ),
            "setval": "match as-number {{ match.as_number.asn|join(', ') }}",
            "result": {
                "{{ route_map }}": {
                    "route_map": "{{ route_map }}",
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "as_number": {
                                    "asn": "{{ asn.rstrip().split(', ') }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match.as_number.as_path_list",
            "getval": re.compile(
                r"""
                \s+match\sas-number
                \sas-path-list\s(?P<as_path_list>.+)\s*
                $""", re.VERBOSE,
            ),
            "setval": "match as-number as-path-list {{ match.as_number.as_path_list|join(' ') }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "as_number": {
                                    "as_path_list": "{{ as_path_list.split() }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match.as_path",
            "getval": re.compile(
                r"""
                \s+match\sas-path\s(?P<as_path>.+)\s*
                $""", re.VERBOSE,
            ),
            "setval": "match as-path {{ match.as_path|join(' ') }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "as_path": "{{ as_path.split() }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match.community.community_list",
            "getval": re.compile(
                r"""
                \s+match\scommunity
                \s(?P<community_list>.+)
                (\s(?P<exact_match>exact-match))?
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "match community {{ match.community.community_list|join(' ') }}{{ ' exact-match' if match.community.exact_match|d(False) else '' }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "community": {
                                    "community_list": "{{ community_list.split() }}",
                                    "exact_match": "{{ not not exact_match }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match.evpn.route_types",
            "getval": re.compile(
                r"""
                \s+match\sevpn
                \sroute-type
                \s(?P<route_types>.+)\s*
                $""", re.VERBOSE,
            ),
            "setval": "match evpn route-type {{ match.evpn.route_types|join(' ') }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "evpn": {
                                    "route_types": "{{ route_types.split() }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match.extcommunity.extcommunity_list",
            "getval": re.compile(
                r"""
                \s+match\sextcommunity
                \s(?P<extcommunity_list>.+)
                \s(?P<exact_match>exact-match)?
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "match extcommunity {{ match.extcommunity.extcommunity_list|join(' ') }}"
                      "{{ ' exact-match' if match.extcommunity.exact_match|d(False) else '' }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "extcommunity": {
                                    "extcommunity_list": "{{ extcommunity_list.split() }}",
                                    "exact_match": "{{ not not exact_match }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match.interfaces",
            "getval": re.compile(
                r"""
                \s+match\sinterface
                \s(?P<interfaces>.+)
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "match interface {{ match.interfaces|join(' ') }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "interfaces": "{{ interfaces.split() }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match.ip.address.access_list",
            "getval": re.compile(
                r"""
                \s+match\sip\saddress
                \s(?P<access_list>\S+)
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "match ip address {{ match.ip.address.access_list }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "ip": {
                                    "address": {
                                        "access_list": "{{ access_list }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match.ip.address.prefix_lists",
            "getval": re.compile(
                r"""
                \s+match\sip\saddress
                \sprefix-list
                \s(?P<prefix_lists>.+)
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "match ip address prefix-list {{ match.ip.address.prefix_lists|join(' ') }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "ip": {
                                    "address": {
                                        "prefix_lists": "{{ prefix_lists.split() }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        # match ip multicast source 192.1.2.0/24 group-range 239.0.0.1 to 239.255.255.255 rp 209.165.201.0/27 rp-type Bidir
        {
            "name": "match.ip.multicast",
            "getval": re.compile(
                r"""
                \s+match\sip\smulticast
                (\ssource\s(?P<source>\S+))?
                (\sgroup\s(?P<prefix>\S+))?
                (\sgroup-range
                (\s(?P<first>\S+))?
                (\sto)?
                (\s(?P<last>\S+)))?
                (\srp\s(?P<rp>\S+))?
                (\srp-type\s(?P<rp_type>\S+))?
                \s*
                $""", re.VERBOSE,
            ),
            "setval": _tmplt_match_ip_multicast,
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "ip": {
                                    "multicast": {
                                        "group": {
                                            "prefix": "{{ prefix }}",
                                        },
                                        "group_range": {
                                            "first": "{{ first }}",
                                            "last": "{{ last }}",
                                        },
                                        "rp": {
                                            "prefix": "{{ rp }}",
                                            "rp_type": "{{ rp_type }}",
                                        },
                                        "source": "{{ source }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match.ip.next_hop.prefix_lists",
            "getval": re.compile(
                r"""
                \s+match\sip\snext-hop
                \sprefix-list\s(?P<prefix_lists>.+)
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "match ip next-hop prefix-list {{ match.ip.next_hop.prefix_lists|join(' ') }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "ip": {
                                    "next_hop": {
                                        "prefix_lists": "{{ prefix_lists.split() }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match.ip.route_source.prefix_lists",
            "getval": re.compile(
                r"""
                \s+match\sip\sroute-source
                \sprefix-list\s(?P<prefix_lists>.+)
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "match ip route-source prefix-list {{ match.ip.route_source.prefix_lists|join(' ') }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "ip": {
                                    "route_source": {
                                        "prefix_lists": "{{ prefix_lists.split() }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match.ipv6.address.access_list",
            "getval": re.compile(
                r"""
                \s+match\sipv6\saddress
                \s(?P<access_list>\S+)
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "match ipv6 address {{ match.ipv6.address.access_list }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "ipv6": {
                                    "address": {
                                        "access_list": "{{ access_list }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match.ipv6.address.prefix_lists",
            "getval": re.compile(
                r"""
                \s+match\sipv6\saddress
                \sprefix-list
                \s(?P<prefix_lists>.+)
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "match ipv6 address prefix-list {{ match.ipv6.address.prefix_lists|join(' ') }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "ipv6": {
                                    "address": {
                                        "prefix_lists": "{{ prefix_lists.split() }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match.ipv6.multicast",
            "getval": re.compile(
                r"""
                \s+match\sipv6\smulticast
                (\ssource\s(?P<source>\S+))?
                (\sgroup\s(?P<prefix>\S+))?
                (\sgroup-range
                (\s(?P<first>\S+))?
                (\sto)?
                (\s(?P<last>\S+)))?
                (\srp\s(?P<rp>\S+))?
                (\srp-type\s(?P<rp_type>\S+))?
                \s*
                $""", re.VERBOSE,
            ),
            "setval": _tmplt_match_ipv6_multicast,
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "ipv6": {
                                    "multicast": {
                                        "group": {
                                            "prefix": "{{ prefix }}",
                                        },
                                        "group_range": {
                                            "first": "{{ first }}",
                                            "last": "{{ last }}",
                                        },
                                        "rp": {
                                            "prefix": "{{ rp }}",
                                            "rp_type": "{{ rp_type }}",
                                        },
                                        "source": "{{ source }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match.ipv6.next_hop.prefix_lists",
            "getval": re.compile(
                r"""
                \s+match\sipv6\snext-hop
                \sprefix-list\s(?P<prefix_lists>.+)
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "match ipv6 next-hop prefix-list {{ match.ipv6.next_hop.prefix_lists|join(' ') }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "ipv6": {
                                    "next_hop": {
                                        "prefix_lists": "{{ prefix_lists.split() }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match.ipv6.route_source.prefix_lists",
            "getval": re.compile(
                r"""
                \s+match\sipv6\sroute-source
                \sprefix-list\s(?P<prefix_lists>.+)
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "match ipv6 route-source prefix-list {{ match.ipv6.route_source.prefix_lists|join(' ') }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "ipv6": {
                                    "route_source": {
                                        "prefix_lists": "{{ prefix_lists.split() }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match.mac_list",
            "getval": re.compile(
                r"""
                \s+match\smac-list
                \s(?P<mac_list>.+)
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "match mac-list {{ match.mac_list|join(' ') }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "mac_list": "{{ mac_list.split() }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match.metric",
            "getval": re.compile(
                r"""
                \s+match\smetric
                \s(?P<metric>.+)
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "match metric {{ match.metric|join(' ') }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "metric": "{{ metric.split() }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match.ospf_area",
            "getval": re.compile(
                r"""
                \s+match\sospf-area
                \s(?P<ospf_area>.+)
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "match ospf-area {{ match.ospf_area|join(' ') }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "ospf_area": "{{ ospf_area.split() }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match.route_types",
            "getval": re.compile(
                r"""
                \s+match\sroute-type
                \s(?P<route_types>.+)
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "match route-type {{ match.route_types|join(' ') }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "route_types": "{{ route_types.split() }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match.source_protocol",
            "getval": re.compile(
                r"""
                \s+match\ssource-protocol
                \s(?P<route_type>.+)
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "match source-protocol {{ match.source_protocol|join(' ') }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "source_protocol": "{{ source_protocol.split() }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "match.tags",
            "getval": re.compile(
                r"""
                \s+match\stag
                \s(?P<tags>.+)
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "match tag {{ match.tags|join(' ') }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "match": {
                                "tags": "{{ tags.split() }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.as_path.prepend.as_number",
            "getval": re.compile(
                r"""
                \s+set\sas-path\sprepend
                \s(?P<as_number>(?!last-as).+)
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "set as-path prepend {{ set.as_path.prepend.as_number|join(' ') }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "as_path": {
                                    "prepend": {
                                        "as_number": "{{ as_number.split() }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.as_path.prepend.last_as",
            "getval": re.compile(
                r"""
                \s+set\sas-path\sprepend
                \slast-as\s(?P<last_as>\d+)
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "set as-path prepend last-as {{ set.as_path.prepend.last_as|string }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "as_path": {
                                    "prepend": {
                                        "last_as": "{{ last_as }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.as_path.tag",
            "getval": re.compile(
                r"""
                \s+set\sas-path
                \s(?P<tag>tag)
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "set as-path tag",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "as_path": {
                                    "tag": "{{ not not tag }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.comm_list",
            "getval": re.compile(
                r"""
                \s+set\scomm-list
                \s(?P<comm_list>\S+)
                \s*delete
                \s*$""", re.VERBOSE,
            ),
            "setval": "set comm-list {{ set.comm_list }} delete",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "comm_list": "{{ comm_list }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.community",
            "getval": re.compile(
                r"""
                \s+set\scommunity
                (\s(?P<internet>internet))?
                (?P<number>(\s\d+:\d+)*)
                (\s(?P<no_export>no-export))?
                (\s(?P<no_advertise>no-advertise))?
                (\s(?P<local_as>local-AS))?
                (\s(?P<graceful_shutdown>graceful-shutdown))?
                (\s(?P<additive>additive))?\s*
                $""", re.VERBOSE,
            ),
            "setval": "set community"
                      "{{ ' internet' if set.community.internet|d(False) else '' }}"
                      "{{ ' ' + set.community.number|join(' ') if set.community.number|d(False) else '' }}"
                      "{{ ' no-export' if set.community.no_export|d(False) else '' }}"
                      "{{ ' no-advertise' if set.community.no_advertise|d(False) else '' }}"
                      "{{ ' local-AS' if set.community.local_as|d(False) else '' }}"
                      "{{ ' graceful-shutdown' if set.community.graceful_shutdown|d(False) else '' }}"
                      "{{ ' additive' if set.community.additive|d(False) else '' }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "community": {
                                    "internet": "{{ not not internet }}",
                                    "number": "{{ number.split() }}",
                                    "no_export": "{{ not not no_export }}",
                                    "no_advertise": "{{ not not no_advertise }}",
                                    "local_as": "{{ not not local_as }}",
                                    "graceful_shutdown": "{{ not not graceful_shutdown }}",
                                    "additive": "{{ not not additive }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.dampening",
            "getval": re.compile(
                r"""
                \s+set\sdampening
                \s(?P<half_life>\d+)
                \s(?P<start_reuse_route>\d+)
                \s(?P<start_suppress_route>\d+)
                \s(?P<max_suppress_time>\d+)
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "set dampening {{ set.dampening.half_life }}"
                      " {{ set.dampening.start_reuse_route }}"
                      " {{ set.dampening.start_suppress_route }}"
                      " {{ set.dampening.max_suppress_time }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "dampening": {
                                    "half_life": "{{ half_life }}",
                                    "start_reuse_route": "{{ start_reuse_route }}",
                                    "start_suppress_route": "{{ start_suppress_route }}",
                                    "max_suppress_time": "{{ max_suppress_time }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.distance",
            "getval": re.compile(
                r"""
                \s+set\sdistance
                \s(?P<igp_ebgp_routes>\d+)
                (\s(?P<internal_routes>\d+))?
                (\s(?P<local_routes>\d+))?
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "set distance {{ set.distance.igp_ebgp_routes }}"
                      "{{ ' ' + set.distance.internal_routes|string if set.distance.internal_routes|d(False) else '' }}"
                      "{{ ' ' + set.distance.local_routes|string if set.distance.internal_routes|d(False) else '' }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "distance": {
                                    "igp_ebgp_routes": "{{ igp_ebgp_routes }}",
                                    "internal_routes": "{{ internal_routes }}",
                                    "local_routes": "{{ local_routes }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.evpn.gateway_ip",
            "getval": re.compile(
                r"""
                \s+set\sevpn
                \sgateway-ip
                (\s(?P<ip>(?!use-nexthop)\S+))?
                (\s(?P<use_nexthop>use-nexthop))?
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "set evpn gateway-ip"
                      "{{ ' ' + set.evpn.gateway_ip.ip if set.evpn.gateway_ip.ip|d(False) else ''}}"
                      "{{ ' use-nexthop' if set.evpn.gateway_ip.use_nexthop|d(False) else '' }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "evpn": {
                                    "gateway_ip": {
                                        "ip": "{{ ip }}",
                                        "use_nexthop": "{{ not not use_nexthop }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.extcomm_list",
            "getval": re.compile(
                r"""
                \s+set\sextcomm-list
                \s(?P<extcomm_list>\S+)
                \s*delete
                \s*$""", re.VERBOSE,
            ),
            "setval": "set extcomm-list {{ set.extcomm_list }} delete",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "extcomm_list": "{{ extcomm_list }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.extcommunity.rt",
            "getval": re.compile(
                r"""
                \s+set\sextcommunity\srt
                (?P<extcommunity_numbers>(\s\S+:\S+)*)?
                (\s(?P<additive>additive))?
                \s*$""", re.VERBOSE,
            ),
            "setval": _tmplt_set_extcomm_rt,
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "extcommunity": {
                                    "rt": {
                                        "additive": "{{ not not additive }}",
                                        "extcommunity_numbers":
                                            "{{ extcommunity_numbers.strip().split(' ') if extcommunity_numbers|d('') else None }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.forwarding_address",
            "getval": re.compile(
                r"""
                \s+set
                \s(?P<forwarding_address>forwarding-address)
                \s*$""", re.VERBOSE,
            ),
            "setval": "set forwarding-address",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "forwarding_address": "{{ not not forwarding_address }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.null_interface",
            "getval": re.compile(
                r"""
                \s+set\sinterface
                \s(?P<interface>\S+)
                \s*$""", re.VERBOSE,
            ),
            "setval": "set interface {{ set.null_interface }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "null_interface": "{{ interface }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.ip.address.prefix_list",
            "getval": re.compile(
                r"""
                \s+set\sip\saddress
                \sprefix-list\s(?P<prefix_list>\S+)
                \s*$""", re.VERBOSE,
            ),
            "setval": "set ip address prefix-list {{ set.ip.address.prefix_list }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "ip": {
                                    "address": {
                                        "prefix_list": "{{ prefix_list }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.ip.precedence",
            "getval": re.compile(
                r"""
                \s+set\sip
                \sprecedence\s(?P<precedence>\S+)
                \s*$""", re.VERBOSE,
            ),
            "setval": "set ip precedence {{ set.ip.precedence }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "ip": {
                                    "precedence": "{{ precedence }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.ip.next_hop",
            "getval": re.compile(
                r"""
                \s+set\sip\snext-hop
                \s(?P<address>(\s?((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4})+)
                (\s+(?P<load_share>load-share))?
                (\s+(?P<force_order>force-order))?
                (\s+(?P<drop_on_fail>drop-on-fail))?
                \s*$""", re.VERBOSE,
            ),
            "setval": "set ip next-hop {{ set.ip.next_hop.address }}"
                      "{{ ' load-share' if set.ip.next_hop.load_share else '' }}"
                      "{{ ' force-order' if set.ip.next_hop.force_order else '' }}"
                      "{{ ' drop-on-fail' if set.ip.next_hop.drop_on_fail else '' }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "ip": {
                                    "next_hop": {
                                        "address": "{{ address }}",
                                        "load_share": "{{ not not load_share|d(False) }}",
                                        "force_order": "{{ not not force_order|d(False) }}",
                                        "drop_on_fail": "{{ not not drop_on_fail|d(False) }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.ip.next_hop.peer_address",
            "getval": re.compile(
                r"""
                \s+set\sip\snext-hop
                \s(?P<peer_address>peer-address)
                \s*$""", re.VERBOSE,
            ),
            "setval": "set ip next-hop peer-address",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "ip": {
                                    "next_hop": {
                                        "peer_address": "{{ not not peer_address }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.ip.next_hop.redist_unchanged",
            "getval": re.compile(
                r"""
                \s+set\sip\snext-hop
                \s(?P<redist_unchanged>redist-unchanged)
                \s*$""", re.VERBOSE,
            ),
            "setval": "set ip next-hop redist-unchanged",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "ip": {
                                    "next_hop": {
                                        "redist_unchanged": "{{ not not redist_unchanged }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.ip.next_hop.unchanged",
            "getval": re.compile(
                r"""
                \s+set\sip\snext-hop
                \s(?P<unchanged>unchanged)
                \s*$""", re.VERBOSE,
            ),
            "setval": "set ip next-hop unchanged",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "ip": {
                                    "next_hop": {
                                        "unchanged": "{{ not not unchanged }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.ip.next_hop.verify_availability",
            "getval": re.compile(
                r"""
                \s+set\sip\snext-hop\sverify-availability
                \s(?P<address>\S+)
                \strack\s(?P<track>\d)
                (\s(?P<load_share>load-share))?
                (\s(?P<force_order>force-order))?
                (\s(?P<drop_on_fail>drop-on-fail))?
                \s*$""", re.VERBOSE,
            ),
            "setval": _tmplt_set_ip_next_hop_verify_availability,
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "ip": {
                                    "next_hop": {
                                        "verify_availability": [
                                            {
                                                "address": "{{ address }}",
                                                "track": "{{ track }}",
                                                "load_share": "{{ not not load_share|d(False) }}",
                                                "force_order": "{{ not not force_order|d(False) }}",
                                                "drop_on_fail": "{{ not not drop_on_fail|d(False) }}",
                                            },
                                        ],
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.ipv6.address.prefix_list",
            "getval": re.compile(
                r"""
                \s+set\sipv6\saddress
                \sprefix-list\s(?P<prefix_list>\S+)
                \s*$""", re.VERBOSE,
            ),
            "setval": "set ipv6 address prefix-list {{ set.ipv6.address.prefix_list }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "ipv6": {
                                    "address": {
                                        "prefix_list": "{{ prefix_list }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.ipv6.precedence",
            "getval": re.compile(
                r"""
                \s+set\sipv6
                \sprecedence\s(?P<precedence>\S+)
                \s*$""", re.VERBOSE,
            ),
            "setval": "set ipv6 precedence {{ set.ipv6.precedence }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "ipv6": {
                                    "precedence": "{{ precedence }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.label_index",
            "getval": re.compile(
                r"""
                \s+set\slabel-index
                \s(?P<label_index>\d+)
                \s*$""", re.VERBOSE,
            ),
            "setval": "set label-index {{ set.label_index }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "label_index": "{{ label_index }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.level",
            "getval": re.compile(
                r"""
                \s+set\slevel
                \s(?P<level>\S+)
                \s*$""", re.VERBOSE,
            ),
            "setval": "set level {{ set.level }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "level": "{{ level }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.local_preference",
            "getval": re.compile(
                r"""
                \s+set\slocal-preference
                \s(?P<local_preference>\d+)
                \s*$""", re.VERBOSE,
            ),
            "setval": "set local-preference {{ set.local_preference }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "local_preference": "{{ local_preference }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.metric",
            "getval": re.compile(
                r"""
                \s+set\smetric
                \s(?P<bandwidth>\d+)
                (\s(?P<igrp_delay_metric>\d+))?
                (\s(?P<igrp_reliability_metric>\d+))?
                (\s(?P<igrp_effective_bandwidth_metric>\d+))?
                (\s(?P<igrp_mtu>\d+))?
                \s*$""", re.VERBOSE,
            ),
            "setval": _tmplt_set_metric,
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "metric": {
                                    "bandwidth": "{{ bandwidth }}",
                                    "igrp_delay_metric": "{{ igrp_delay_metric }}",
                                    "igrp_reliability_metric": "{{ igrp_reliability_metric }}",
                                    "igrp_effective_bandwidth_metric": "{{ igrp_effective_bandwidth_metric }}",
                                    "igrp_mtu": "{{ igrp_mtu }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.metric_type",
            "getval": re.compile(
                r"""
                \s+set\smetric-type
                \s(?P<metric_type>\S+)
                \s*$""", re.VERBOSE,
            ),
            "setval": "set metric-type {{ set.metric_type }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "metric_type": "{{ metric_type }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.nssa_only",
            "getval": re.compile(
                r"""
                \s+set
                \s(?P<nssa_only>nssa-only)
                \s*$""", re.VERBOSE,
            ),
            "setval": "set nssa-only",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "nssa_only": "{{ not not nssa_only }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.origin",
            "getval": re.compile(
                r"""
                \s+set\sorigin
                \s(?P<origin>\S+)
                \s*$""", re.VERBOSE,
            ),
            "setval": "set origin {{ set.origin }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "origin": "{{ origin }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.path_selection",
            "getval": re.compile(
                r"""
                \s+set\spath-selection
                \s(?P<path_selection>\S+)
                \sadvertise
                \s*$""", re.VERBOSE,
            ),
            "setval": "set path-selection {{ set.path_selection }} advertise",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "path_selection": "{{ path_selection }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.tag",
            "getval": re.compile(
                r"""
                \s+set\stag
                \s(?P<tag>\d+)
                \s*$""", re.VERBOSE,
            ),
            "setval": "set tag {{ set.tag }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "tag": "{{ tag }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "set.weight",
            "getval": re.compile(
                r"""
                \s+set\sweight
                \s(?P<weight>\d+)
                \s*$""", re.VERBOSE,
            ),
            "setval": "set weight {{ set.weight }}",
            "result": {
                "{{ route_map }}": {
                    "entries": {
                        "{{ sequence }}": {
                            "set": {
                                "weight": "{{ weight }}",
                            },
                        },
                    },
                },
            },
        },
    ]
    # fmt: on
