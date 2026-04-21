# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The Vrf_global parser templates file. This contains
a list of parser definitions and associated functions that
facilitates both facts gathering and native command generation for
the given network resource.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


def _tmplt_ip_route(route_item):
    command = "ip route {source} {destination}".format(**route_item)
    if route_item.get("tags"):
        tag_item = route_item.get("tags")
        command += " tag {tag_value}".format(**tag_item)
        if route_item.get("tags").get("route_pref"):
            command += " {route_pref}".format(**tag_item)
    if route_item.get("vrf"):
        command += " vrf {vrf}".format(**route_item)
    if route_item.get("track"):
        command += " track {track}".format(**route_item)
    return command


class Vrf_globalTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(Vrf_globalTemplate, self).__init__(lines=lines, tmplt=self, module=module)

    # fmt: off
    PARSERS = [
        {
            "name": "name",
            "getval": re.compile(
                r"""
                ^vrf\scontext\s(?P<name>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "vrf context {{ name }}",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                    },
                },
            },
            "shared": True,
        },
        {
            "name": "description",
            "getval": re.compile(
                r"""
                \s+description\s(?P<description>.+$)
                $""", re.VERBOSE,
            ),
            "setval": "description {{ description }}",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        'description': '{{ description }}',
                    },
                },
            },
        },
        {
            "name": "rd",
            "getval": re.compile(
                r"""
                \s+rd\s(?P<rd>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "rd {{ rd }}",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        'rd': '{{ rd }}',
                    },
                },
            },
        },
        {
            "name": "ip.auto_discard",
            "getval": re.compile(
                r"""
                \s+ip\s(?P<auto_disc>auto-discard)
                $""", re.VERBOSE,
            ),
            "setval": "ip auto-discard",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ip": {
                            "auto_discard": "{{ True if auto_disc is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "ip.domain_list",
            "getval": re.compile(
                r"""
                \s+ip\sdomain-list\s(?P<domain_list>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ip domain-list {{ domain_list }}",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ip": {
                            "domain_list": [
                                "{{ domain_list }}",
                            ],
                        },
                    },
                },
            },
        },
        {
            "name": "ip.domain_name",
            "getval": re.compile(
                r"""
                \s+ip\sdomain-name\s(?P<domain_name>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ip domain-name {{ ip.domain_name }}",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ip": {
                            "domain_name": "{{ domain_name }}",
                        },
                    },
                },
            },
        },
        {
            "name": "ip.icmp_err.source_interface",
            "getval": re.compile(
                r"""
                \s+ip\sicmp-errors
                \ssource-interface\s(?P<interface>eth|po|lo)
                (?P<interface_val>(\d+\S*))
                $""", re.VERBOSE,
            ),
            "setval": "ip icmp-errors source-interface {{ ip.icmp_err.source_interface.interface }} {{ ip.icmp_err.source_interface.interface_value }}",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ip": {
                            "icmp_err": {
                                "source_interface": {
                                    "interface": "{{ 'ethernet' if 'eth' in interface }}"
                                    "{{ 'port-channel' if 'po' in interface }}"
                                    "{{ 'loopback' if 'lo' in interface }}",
                                    "interface_value": "{{ interface_val }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ip.igmp.ssm_translate",
            "getval": re.compile(
                r"""
                \s+ip\sigmp
                \sssm-translate
                \s(?P<group_val>\S+)
                \s(?P<source_val>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ip igmp ssm-translate {{ group }} {{ source }}",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ip": {
                            "igmp": {
                                "ssm_translate": [
                                    {
                                        "group": "{{ group_val }}",
                                        "source": "{{ source_val }}",
                                    },
                                ],
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ip.mroutes",
            "getval": re.compile(
                r"""
                \s+ip\smroute
                \s(?P<group_val>\S+)
                \s(?P<source_val>\S+)
                (\s(?P<pref_val>\d+))?
                (\svrf\s(?P<vrf_val>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "ip mroute {{ group }} {{ source }}"
            "{{ ' ' + preference|string if preference is defined }}"
            "{{ ' vrf ' + vrf if vrf is defined }}",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ip": {
                            "mroutes": [
                                {
                                    "group": "{{ group_val }}",
                                    "source": "{{ source_val }}",
                                    "preference": "{{ pref_val if pref_val is defined }}",
                                    "vrf": "{{ vrf_val if vrf_val is defined }}",
                                },
                            ],
                        },
                    },
                },
            },
        },
        {
            "name": "ip.multicast.group_range_prefix_list",
            "getval": re.compile(
                r"""
                \s+ip\smulticast
                \sprefix-list\s(?P<prefix_lst>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ip multicast group-range prefix-list {{ ip.multicast.group_range_prefix_list.group_range_prefix_list }}",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ip": {
                            "multicast": {
                                "group_range_prefix_list": "{{ prefix_lst }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ip.multicast.multipath.resilient",
            "getval": re.compile(
                r"""
                \s+ip\smulticast
                \smultipath\s(?P<res>resilient)
                $""", re.VERBOSE,
            ),
            "setval": "ip multicast multipath resilient",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ip": {
                            "multicast": {
                                "multipath": {
                                    "resilient": "{{ True if res is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ip.multicast.multipath.splitting_type.none",
            "getval": re.compile(
                r"""
                \s+ip\smulticast
                \smultipath\s(?P<noneval>none)
                $""", re.VERBOSE,
            ),
            "setval": "ip multicast multipath none",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ip": {
                            "multicast": {
                                "multipath": {
                                    "splitting_type": {
                                        "none": "{{ True if noneval is defined }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ip.multicast.multipath.splitting_type.legacy",
            "getval": re.compile(
                r"""
                \s+ip\smulticast
                \smultipath\s(?P<legacy_val>legacy)
                $""", re.VERBOSE,
            ),
            "setval": "ip multicast multipath legacy",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ip": {
                            "multicast": {
                                "multipath": {
                                    "splitting_type": {
                                        "legacy": "{{ True if legacy_val is defined }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ip.multicast.multipath.splitting_type.nbm",
            "getval": re.compile(
                r"""
                \s+ip\smulticast
                \smultipath\s(?P<nbm_val>nbm)
                $""", re.VERBOSE,
            ),
            "setval": "ip multicast multipath nbm",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ip": {
                            "multicast": {
                                "multipath": {
                                    "splitting_type": {
                                        "nbm": "{{ True if nbm_val is defined }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ip.multicast.multipath.splitting_type.sg_hash",
            "getval": re.compile(
                r"""
                \s+ip\smulticast
                \smultipath\s(?P<sg_hash_val>s-g-hash)
                $""", re.VERBOSE,
            ),
            "setval": "ip multicast multipath s-g-hash",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ip": {
                            "multicast": {
                                "multipath": {
                                    "splitting_type": {
                                        "sg_hash": "{{ True if sg_hash_val is defined }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ip.multicast.multipath.splitting_type.sg_hash_next_hop",
            "getval": re.compile(
                r"""
                \s+ip\smulticast
                \smultipath
                \s(?P<sg_hash_nxt_val>s-g-hash\snext-hop-based)
                $""", re.VERBOSE,
            ),
            "setval": "ip multicast multipath s-g-hash next-hop-based",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ip": {
                            "multicast": {
                                "multipath": {
                                    "splitting_type": {
                                        "sg_hash_next_hop": "{{ True if sg_hash_nxt_val is defined }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ip.multicast.rpf",
            "getval": re.compile(
                r"""
                \s+ip\smulticast
                \srpf\sselect
                \svrf\s(?P<vrf_val>\S+)
                \sgroup-list\s(?P<group_list>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ip multicast rpf select vrf {{ vrf_name }} group-list {{ group_list_range }}",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ip": {
                            "multicast": {
                                "rpf": [
                                    {
                                        "vrf_name": "{{ vrf_val }}",
                                        "group_list_range": "{{ group_list }}",
                                    },
                                ],
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ip.name_server.use_vrf",
            "getval": re.compile(
                r"""
                \s+ip\sname-server
                \s(?P<source_addr>\S+)
                \suse-vrf\s(?P<vrf_name>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ip name-server {{ ip.name_server.use_vrf.source_address }} use-vrf {{ ip.name_server.use_vrf.vrf }}",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ip": {
                            "name_server": {
                                "use_vrf": {
                                    "source_address": "{{ source_addr }}",
                                    "vrf": "{{ vrf_name }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ip.name_server.address_list",
            "getval": re.compile(
                r"""
                \s+ip\sname-server
                \s(?P<addr_list>.+$)
                $""", re.VERBOSE,
            ),
            "setval": "ip name-server {{ ip.name_server.address_list }}",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ip": {
                            "name_server": {
                                "address_list": "{{ addr_list }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ip.route",
            "getval": re.compile(
                r"""
                \s+ip\sroute
                \s(?P<src_val>\S+)
                \s(?P<dest_val>\S+)
                $""", re.VERBOSE,
            ),
            "setval": _tmplt_ip_route,
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ip": {
                            "route": [
                                {
                                    "source": "{{ src_val }}",
                                    "destination": "{{ dest_val }}",
                                },
                            ],
                        },
                    },
                },
            },
        },
        {
            "name": "ip.route.tags",
            "getval": re.compile(
                r"""
                \s+ip\sroute
                \s(?P<src_val>\S+)
                \s(?P<dest_val>\S+)
                \stag\s(?P<tag_val>\d+)
                (\s(?P<route_pref_val>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": _tmplt_ip_route,
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ip": {
                            "route": [
                                {
                                    "source": "{{ src_val }}",
                                    "destination": "{{ dest_val }}",
                                    "tags": {
                                        "tag_value": "{{ tag_val }}",
                                        "route_pref": "{{ route_pref_val if route_pref_val is defined }}",
                                    },

                                },
                            ],
                        },
                    },
                },
            },
        },
        {
            "name": "ip.route.vrf",
            "getval": re.compile(
                r"""
                \s+ip\sroute
                \s(?P<src_val>\S+)
                \s(?P<dest_val>\S+)
                \svrf\s(?P<vrf_val>\S+)
                $""", re.VERBOSE,
            ),
            "setval": _tmplt_ip_route,
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ip": {
                            "route": [
                                {
                                    "source": "{{ src_val }}",
                                    "destination": "{{ dest_val }}",
                                    "vrf": "{{ vrf_val }}",
                                },
                            ],
                        },
                    },
                },
            },
        },
        {
            "name": "ip.route.track",
            "getval": re.compile(
                r"""
                \s+ip\sroute
                \s(?P<src_val>\S+)
                \s(?P<dest_val>\S+)
                \strack\s(?P<track_val>\S+)
                $""", re.VERBOSE,
            ),
            "setval": _tmplt_ip_route,
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ip": {
                            "route": [
                                {
                                    "source": "{{ src_val }}",
                                    "destination": "{{ dest_val }}",
                                    "track": "{{ track_val }}",
                                },
                            ],
                        },
                    },
                },
            },
        },
        {
            "name": "vni",
            "getval": re.compile(
                r"""
                \s+vni\s(?P<vni_val>\d+)
                (\s(?P<l3_val>l3))?
                $""", re.VERBOSE,
            ),
            "setval": "vni {{ vni.vni_number }}{{ ' l3' if vni.layer_3 is defined }}",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "vni": {
                            "vni_number": "{{ vni_val }}",
                            "layer_3": "{{ True if l3_val is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "multicast.service_reflect",
            "getval": re.compile(
                r"""
                \s+multicast\sservice-reflect
                \sinterface\s(?P<serv_inter>\S+)
                \smap\sinterface\s(?P<map_inter>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "multicast service-reflect interface {{ service_interface }} map interface {{ map_to }}",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "multicast": {
                            "service_reflect": [
                                {
                                    "service_interface": "{{ serv_inter }}",
                                    "map_to": "{{ map_inter }}",
                                },
                            ],
                        },
                    },
                },
            },
        },
        {
            "name": "ipv6.mld_ssm_translate",
            "getval": re.compile(
                r"""
                \s+ipv6\smld
                (\s(?P<icmp_val>icmp))?
                \sssm-translate
                \s(?P<group_val>\S+)
                \s(?P<source_val>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ipv6{{ ' icmp' if icmp is defined }} mld ssm-translate {{ group }} {{ source }}",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ipv6": {
                            "mld_ssm_translate": [
                                {
                                    "icmp": "{{ True if icmp_val is defined }}",
                                    "group": "{{ group_val }}",
                                    "source": "{{ source_val }}",
                                },
                            ],
                        },
                    },
                },
            },
        },
        {
            "name": "ipv6.multicast.group_range_prefix_list",
            "getval": re.compile(
                r"""
                \s+ipv6\smulticast
                \sgroup-range\sprefix-list
                \s(?P<prefix_lst>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ipv6 multicast group-range prefix-list {{ ipv6.multicast.group_range_prefix_list }}",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ipv6": {
                            "multicast": {
                                "group_range_prefix_list": "{{ prefix_lst }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ipv6.multicast.multipath.resilient",
            "getval": re.compile(
                r"""
                \s+ipv6\smulticast
                \smultipath\s(?P<res_val>resilient)
                $""", re.VERBOSE,
            ),
            "setval": "ipv6 multicast multipath resilient",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ipv6": {
                            "multicast": {
                                "multipath": {
                                    "resilient": "{{ True if res_val is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ipv6.multicast.multipath.splitting_type.none",
            "getval": re.compile(
                r"""
                \s+ipv6\smulticast
                \smultipath\s(?P<none_val>none)
                $""", re.VERBOSE,
            ),
            "setval": "ipv6 multicast multipath none",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ipv6": {
                            "multicast": {
                                "multipath": {
                                    "splitting_type": {
                                        "none": "{{ True if none_val is defined }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ipv6.multicast.multipath.splitting_type.sg_hash",
            "getval": re.compile(
                r"""
                \s+ipv6\smulticast
                \smultipath\s(?P<sg_hash_val>s-g-hash)
                $""", re.VERBOSE,
            ),
            "setval": "ipv6 multicast multipath s-g-hash",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ipv6": {
                            "multicast": {
                                "multipath": {
                                    "splitting_type": {
                                        "sg_hash": "{{ True if sg_hash_val is defined }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ipv6.multicast.multipath.splitting_type.sg_hash_next_hop",
            "getval": re.compile(
                r"""
                \s+ipv6\smulticast
                \smultipath\s(?P<sg_hash_next_hop_val>sg-nexthop-hash)
                $""", re.VERBOSE,
            ),
            "setval": "ipv6 multicast multipath sg-nexthop-hash",
            "result": {
                "vrfs": {
                    '{{ name }}': {
                        'name': '{{ name }}',
                        "ipv6": {
                            "multicast": {
                                "multipath": {
                                    "splitting_type": {
                                        "sg_hash_next_hop": "{{ True if sg_hash_next_hop_val is defined }}",
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
