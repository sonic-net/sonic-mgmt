# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
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


def _tmplt_confederation_peers(proc):
    cmd = "confederation peers"
    for peer in proc.get("confederation", {})["peers"]:
        cmd += " {0}".format(peer)
    return cmd


def _tmplt_path_attribute(proc):
    cmd = "path-attribute {action}".format(**proc)

    if "type" in proc:
        cmd += " {type}".format(**proc)
    elif "range" in proc:
        cmd += " range {start} {end}".format(**proc["range"])
    cmd += " in"

    return cmd


def _tmplt_bfd(proc):
    bfd = proc.get("bfd", {})
    cmd = None

    if bfd.get("set"):
        cmd = "bfd"
    if bfd.get("singlehop"):
        cmd = "bfd singlehop"
    elif bfd.get("multihop", {}).get("set"):
        cmd = "bfd multihop"

    if cmd:
        return cmd


class Bgp_globalTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(Bgp_globalTemplate, self).__init__(lines=lines, tmplt=self, module=module)

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
            "name": "vrf",
            "getval": re.compile(
                r"""
                \s+vrf
                \s(?P<vrf>\S+)$""",
                re.VERBOSE,
            ),
            "setval": "vrf {{ vrf }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "vrf": "{{ vrf }}",
                    },
                },
            },
            "shared": True,
        },
        {
            "name": "affinity_group.group_id",
            "getval": re.compile(
                r"""
                \s+affinity-group
                \sactivate\s(?P<group_id>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "affinity-group activate {{ affinity_group.group_id }}",
            "result": {
                "affinity_group": {
                    "group_id": "{{ group_id }}",
                },
            },
        },
        {
            "name": "bestpath.always_compare_med",
            "getval": re.compile(
                r"""
                \s+bestpath\s(?P<always_compare_med>always-compare-med)
                $""", re.VERBOSE,
            ),
            "setval": "bestpath always-compare-med",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bestpath": {
                            "always_compare_med": "{{ not not always_compare_med }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bestpath.as_path.ignore",
            "getval": re.compile(
                r"""
                \s+bestpath\sas-path\s(?P<ignore>ignore)
                $""", re.VERBOSE,
            ),
            "setval": "bestpath as-path ignore",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bestpath": {
                            "as_path": {
                                "ignore": "{{ not not ignore }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bestpath.as_path.multipath_relax",
            "getval": re.compile(
                r"""
                \s+bestpath\sas-path\s(?P<multipath_relax>multipath-relax)
                $""", re.VERBOSE,
            ),
            "setval": "bestpath as-path multipath-relax",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bestpath": {
                            "as_path": {
                                "multipath_relax": "{{ not not multipath_relax }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bestpath.compare_neighborid",
            "getval": re.compile(
                r"""
                \s+bestpath\s(?P<compare_neighborid>compare-neighborid)
                $""", re.VERBOSE,
            ),
            "setval": "bestpath compare-neighborid",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bestpath": {
                            "compare_neighborid": "{{ not not compare_neighborid }}",
                        },
                    },
                },

            },
        },
        {
            "name": "bestpath.compare_routerid",
            "getval": re.compile(
                r"""
                \s+bestpath\s(?P<compare_routerid>compare-routerid)
                $""", re.VERBOSE,
            ),
            "setval": "bestpath compare-routerid",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bestpath": {
                            "compare_routerid": "{{ not not compare_routerid }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bestpath.cost_community_ignore",
            "getval": re.compile(
                r"""
                \s+bestpath\scost-community\s(?P<cost_community_ignore>ignore)
                $""", re.VERBOSE,
            ),
            "setval": "bestpath cost-community ignore",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bestpath": {
                            "cost_community_ignore": "{{ not not cost_community_ignore }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bestpath.igp_metric_ignore",
            "getval": re.compile(
                r"""
                \s+bestpath\sigp-metric\s(?P<igp_metric_ignore>ignore)
                $""", re.VERBOSE,
            ),
            "setval": "bestpath igp-metric ignore",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bestpath": {
                            "igp_metric_ignore": "{{ not not igp_metric_ignore }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bestpath.med.confed",
            "getval": re.compile(
                r"""
                \s+bestpath\smed\s(?P<confed>confed)
                $""", re.VERBOSE,
            ),
            "setval": "bestpath med confed",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bestpath": {
                            "med": {
                                "confed": "{{ not not confed }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bestpath.med.missing_as_worst",
            "getval": re.compile(
                r"""
                \s+bestpath\smed\s(?P<missing_as_worst>missing-as-worst)
                $""", re.VERBOSE,
            ),
            "setval": "bestpath med missing-as-worst",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bestpath": {
                            "med": {
                                "missing_as_worst": "{{ not not missing_as_worst }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bestpath.med.non_deterministic",
            "getval": re.compile(
                r"""
                \s+bestpath\smed\s(?P<non_deterministic>non-deterministic)
                $""", re.VERBOSE,
            ),
            "setval": "bestpath med non-deterministic",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "bestpath": {
                            "med": {
                                "non_deterministic": "{{ not not non_deterministic }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "cluster_id",
            "getval": re.compile(
                r"""
                \s+cluster-id\s(?P<cluster_id>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "cluster-id {{ cluster_id }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "cluster_id": "{{ cluster_id }}",
                    },
                },
            },
        },
        {
            "name": "confederation.identifier",
            "getval": re.compile(
                r"""
                \s+confederation\sidentifier\s(?P<identifier>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "confederation identifier {{ confederation.identifier }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "confederation": {
                            "identifier": "{{ identifier }}",
                        },
                    },
                },
            },
        },
        {
            "name": "confederation.peers",
            "getval": re.compile(
                r"""
                \s+confederation\speers\s(?P<peers>.*)
                $""", re.VERBOSE,
            ),
            "setval": _tmplt_confederation_peers,
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "confederation": {
                            "peers": "{{ peers }}",
                        },
                    },
                },
            },
        },
        {
            "name": "disable_policy_batching",
            "getval": re.compile(
                r"""
                \s+(?P<disable_policy_batching>disable-policy-batching)
                $""", re.VERBOSE,
            ),
            "setval": "disable-policy-batching",
            "result": {
                "disable_policy_batching": {
                    "set": "{{ not not disable_policy_batching }}",
                },
            },
        },
        {
            "name": "disable_policy_batching.ipv4.prefix_list",
            "getval": re.compile(
                r"""
                \s+disable-policy-batching\sipv4
                \sprefix-list\s(?P<ipv4_prefix_list>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "disable-policy-batching ipv4 prefix-list {{ disable_policy_batching.ipv4.prefix_list }}",
            "result": {
                "disable_policy_batching": {
                    "ipv4": {
                        "prefix_list": "{{ ipv4_prefix_list }}",
                    },
                },
            },
        },
        {
            "name": "disable_policy_batching.ipv6.prefix_list",
            "getval": re.compile(
                r"""
                \s+disable-policy-batching\sipv6
                \sprefix-list\s(?P<ipv6_prefix_list>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "disable-policy-batching ipv6 prefix-list {{ disable_policy_batching.ipv6.prefix_list }}",
            "result": {
                "disable_policy_batching": {
                    "ipv6": {
                        "prefix_list": "{{ ipv6_prefix_list }}",
                    },
                },
            },
        },
        {
            "name": "disable_policy_batching.nexthop",
            "getval": re.compile(
                r"""
                \s+disable-policy-batching\s(?P<nexthop>nexthop)
                $""", re.VERBOSE,
            ),
            "setval": "disable-policy-batching nexthop",
            "result": {
                "disable_policy_batching": {
                    "nexthop": "{{ not not nexthop }}",
                },
            },
        },
        {
            "name": "dynamic_med_interval",
            "getval": re.compile(
                r"""
                \s+dynamic-med-interval\s(?P<dynamic_med_interval>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "dynamic-med-interval {{ dynamic_med_interval }}",
            "result": {
                "dynamic_med_interval": "{{ dynamic_med_interval }}",
            },
        },
        {
            "name": "enforce_first_as",
            "getval": re.compile(
                r"""
                \s+no\s(?P<enforce_first_as>enforce-first-as)
                $""", re.VERBOSE,
            ),
            "setval": "enforce-first-as",
            "result": {
                "enforce_first_as": "{{ not enforce_first_as }}",
            },
        },
        {
            "name": "enhanced_error",
            "getval": re.compile(
                r"""
                \s+no\s(?P<enhanced_error>enhanced-error)
                $""", re.VERBOSE,
            ),
            "setval": "enhanced-error",
            "result": {
                "enhanced_error": "{{ not enhanced_error }}",
            },
        },
        {
            "name": "fast_external_fallover",
            "getval": re.compile(
                r"""
                \s+no\s(?P<fast_external_fallover>fast-external-fallover)
                $""", re.VERBOSE,
            ),
            "setval": "fast-external-fallover",
            "result": {
                "fast_external_fallover": "{{ not fast_external_fallover }}",
            },
        },
        {
            "name": "flush_routes",
            "getval": re.compile(
                r"""
                \s+(?P<flush_routes>flush-routes)
                $""", re.VERBOSE,
            ),
            "setval": "flush-routes",
            "result": {
                "flush_routes": "{{ not not flush_routes }}",
            },
        },
        {
            "name": "graceful_restart",
            "getval": re.compile(
                r"""
                \s+no\s(?P<graceful_restart>graceful-restart)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-restart",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "graceful_restart": {
                            "set": "{{ not graceful_restart }}",
                        },
                    },
                },
            },
        },
        {
            "name": "graceful_restart.restart_time",
            "getval": re.compile(
                r"""
                \s+graceful-restart\srestart-time\s(?P<restart_time>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-restart restart-time {{ graceful_restart.restart_time }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "graceful_restart": {
                            "restart_time": "{{ restart_time }}",
                        },
                    },
                },
            },
        },
        {
            "name": "graceful_restart.stalepath_time",
            "getval": re.compile(
                r"""
                \s+graceful-restart\sstalepath-time\s(?P<stalepath_time>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-restart stalepath-time {{ graceful_restart.stalepath_time }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "graceful_restart": {
                            "stalepath_time": "{{ stalepath_time }}",
                        },
                    },
                },
            },
        },
        {
            "name": "graceful_restart.helper",
            "getval": re.compile(
                r"""
                \s+(?P<helper>graceful-restart-helper)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-restart-helper",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "graceful_restart": {
                            "helper": "{{ not not helper }}",
                        },
                    },
                },
            },
        },
        {
            "name": "graceful_shutdown.activate",
            "getval": re.compile(
                r"""
                \s+graceful-shutdown
                \s(?P<activate>activate)
                (\sroute-map
                \s(?P<route_map>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "graceful-shutdown activate{{ ' route-map ' + graceful_shutdown.activate.route_map if graceful_shutdown.activate.route_map is defined }}",
            "result": {
                "graceful_shutdown": {
                    "activate": {
                        "set": "{{ True if activate is defined and route_map is undefined else None }}",
                        "route_map": "{{ route_map }}",
                    },
                },
            },
        },
        {
            "name": "graceful_shutdown.aware",
            "getval": re.compile(
                r"""
                \s+no\sgraceful-shutdown
                \s(?P<aware>aware)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-shutdown aware",
            "result": {
                "graceful_shutdown": {
                    "aware": "{{ not aware }}",
                },
            },
        },
        {
            "name": "isolate",
            "getval": re.compile(
                r"""
                \s+(?P<isolate>isolate)
                (\s(?P<include_local>include-local))?
                $""", re.VERBOSE,
            ),
            "setval": "isolate{{ ' include-local' if isolate.include_local|d(False) is True }}",
            "result": {
                "isolate": {
                    "set": "{{ True if isolate is defined and include_local is not defined else None }}",
                    "include_local": "{{ not not include_local }}",
                },
            },
        },
        {
            "name": "log_neighbor_changes",
            "getval": re.compile(
                r"""
                \s+(?P<log_neighbor_changes>log-neighbor-changes)
                $""", re.VERBOSE,
            ),
            "setval": "log-neighbor-changes",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "log_neighbor_changes": "{{ not not log_neighbor_changes }}",
                    },
                },
            },
        },
        {
            "name": "maxas_limit",
            "getval": re.compile(
                r"""
                \s+maxas-limit\s(?P<maxas_limit>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "maxas-limit {{ maxas_limit }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "maxas_limit": "{{ maxas_limit }}",
                    },
                },
            },
        },
        # start neighbor parsers
        {
            "name": "neighbor_address",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                (\sremote-as\sroute-map\s(?P<remote_as_route_map>\S+))?
                (\sremote-as\s(?P<remote_as>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "neighbor {{ neighbor_address }}"
                      "{{ (' remote-as route-map ' + remote_as_route_map) if remote_as_route_map|d(None) else '' }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "neighbor_address": "{{ neighbor_address }}",
                                "remote_as": "{{ remote_as }}",
                                "remote_as_route_map": "{{ remote_as_route_map }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bfd",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \s(?P<bfd>bfd)
                (\s(?P<singlehop>singlehop))?
                (\s(?P<multihop>multihop))?
                $""", re.VERBOSE,
            ),
            "setval": _tmplt_bfd,
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
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
            },
        },
        {
            "name": "bfd.multihop.interval",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \sbfd\smultihop\sinterval
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
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
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
            },
        },
        {
            "name": "remote_as",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \sremote-as\s(?P<remote_as>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "remote-as {{ remote_as }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "remote_as": "{{ remote_as }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_affinity_group.group_id",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \saffinity-group\s(?P<group_id>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "affinity-group {{ neighbor_affinity_group.group_id }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "neighbor_affinity_group": {
                                    "group_id": "{{ group_id }}",
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
                \s+neighbor\s(?P<neighbor_address>\S+)
                \sbmp-activate-server\s(?P<bmp_activate_server>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "bmp-activate-server {{ bmp_activate_server }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "bmp_activate_server": "{{ bmp_activate_server }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "capability",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \scapability\ssuppress\s(?P<suppress_4_byte_as>4-byte-as)
                $""", re.VERBOSE,
            ),
            "setval": "capability suppress 4-byte-as",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "capability": {
                                    "suppress_4_byte_as": "{{ not not suppress_4_byte_as }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "description",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                (\sremote-as\sroute-map\s\S+)?
                \sdescription\s(?P<description>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "description {{ description }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "description": "{{ description }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "disable_connected_check",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \s(?P<disable_connected_check>disable-connected-check)
                $""", re.VERBOSE,
            ),
            "setval": "disable-connected-check",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "disable_connected_check": "{{ not not disable_connected_check }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "dont_capability_negotiate",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \s(?P<dont_capability_negotiate>dont-capability-negotiate)
                $""", re.VERBOSE,
            ),
            "setval": "dont-capability-negotiate",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "dont_capability_negotiate": "{{ not not dont_capability_negotiate}}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "dscp",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \sdscp\s(?P<dscp>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "dscp {{ dscp }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "dscp": "{{ dscp }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "dynamic_capability",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \s(?P<dynamic_capability>dynamic-capability)
                $""", re.VERBOSE,
            ),
            "setval": "dynamic-capability",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "dynamic_capability": "{{ not not dynamic_capability }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ebgp_multihop",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \sebgp-multihop\s(?P<ebgp_multihop>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "ebgp-multihop {{ ebgp_multihop }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "ebgp_multihop": "{{ ebgp_multihop }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "graceful_shutdown",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \sgraceful-shutdown
                \s(?P<activate>activate)
                (\sroute-map\s(?P<route_map>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "graceful-shutdown{{ (' route-map ' + graceful_shutdown.route_map) if graceful_shutdown.route_map is defined }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
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
            },
        },
        {
            "name": "inherit.peer",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \sinherit
                \speer\s(?P<peer>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "inherit peer {{ inherit.peer }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "inherit": {
                                    "peer": "{{ peer }}",
                                },
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
                \s+neighbor\s(?P<neighbor_address>\S+)
                \sinherit
                \speer-session\s(?P<peer_session>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "inherit peer-session {{ inherit.peer_session }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "inherit": {
                                    "peer_session": "{{ peer_session }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "local_as_config",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \slocal-as\s(?P<local_as>\d+)
                (\s(?P<no_prepend>no-prepend))?
                (\s(?P<replace_as>replace-as))?
                (\s(?P<dual_as>dual-as))?
                $""", re.VERBOSE,
            ),
            "setval": "local-as {{ local_as_config.as_number|string }}"
            "{{ (' no-prepend' ) if local_as_config.no_prepend|d(False) else '' }}"
            "{{ (' replace-as' ) if local_as_config.replace_as|d(False)  else '' }}"
            "{{ (' dual-as' ) if local_as_config.dual_as|d(False)  else '' }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "local_as_config": {
                                    "as_number": "{{ local_as }}",
                                    "no_prepend": "{{ not not no_prepend }}",
                                    "replace_as": "{{ not not replace_as }}",
                                    "dual_as": "{{ not not dual_as }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "log_neighbor_changes",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \s(?P<log_neighbor_changes>log-neighbor-changes)
                (\s(?P<disable>disable))?
                $""", re.VERBOSE,
            ),
            "setval": "log-neighbor-changes{{ ' disable' if log_neighbor_changes.disable is defined }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "log_neighbor_changes": {
                                    "set": "{{ True if log_neighbor_changes is defined and disable is undefined }}",
                                    "disable": "{{ not not disable }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "low_memory",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \slow-memory\s(?P<exempt>exempt)
                $""", re.VERBOSE,
            ),
            "setval": "low-memory exempt",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "low_memory": {
                                    "exempt": "{{ not not exempt }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "password",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \spassword\s(?P<encryption>\d+)
                \s(?P<key>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "password{{ (' ' + password.encryption|string) if password.encryption is defined }} {{ password.key }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "password": {
                                    "encryption": "{{ encryption }}",
                                    "key": "{{ key }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "path_attribute",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \spath-attribute\s(?P<action>\S+)\s
                (?P<type>\d+)?
                (range\s(?P<start>\d+)\s(?P<end>\d+))?
                \sin
                $""", re.VERBOSE,
            ),
            "setval": _tmplt_path_attribute,
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
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
            },
        },
        {
            "name": "peer_type",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \speer-type\s(?P<peer_type>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "peer-type {{ peer_type }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "peer_type": "{{ peer_type }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "remove_private_as",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \s(?P<remove_private_as>remove-private-as)
                (\s(?P<all>all))?
                (\s(?P<replace_as>replace-as))?
                $""", re.VERBOSE,
            ),
            "setval": "remove-private-as",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "remove_private_as": {
                                    "set": "{{ True if remove_private_as is defined and replace_as is undefined and all is undefined else None }}",
                                    "replace_as": "{{ not not replace_as }}",
                                    "all": "{{ not not all }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "shutdown",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \s(?P<shutdown>shutdown)
                $""", re.VERBOSE,
            ),
            "setval": "shutdown",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "shutdown": "{{ not not shutdown }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "timers",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \stimers\s(?P<keepalive>\d+)\s(?P<holdtime>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "timers {{ timers.keepalive }} {{ timers.holdtime }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "timers": {
                                    "keepalive": "{{ keepalive }}",
                                    "holdtime": "{{ holdtime }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "transport",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \stransport\sconnection-mode
                \s(?P<passive>passive)
                $""", re.VERBOSE,
            ),
            "setval": "transport connection-mode passive",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "transport": {
                                    "connection_mode": {
                                        "passive": "{{ not not passive }}",
                                    },
                                },
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
                \s+neighbor\s(?P<neighbor_address>\S+)
                \sttl-security\shops\s(?P<hops>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "ttl-security hops {{ ttl_security.hops }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "ttl_security": {
                                    "hops": "{{ hops }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "update_source",
            "getval": re.compile(
                r"""
                \s+neighbor\s(?P<neighbor_address>\S+)
                \supdate-source\s(?P<update_source>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "update-source {{ update_source }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbors": {
                            "{{ neighbor_address }}": {
                                "update_source": "{{ update_source }}",
                            },
                        },
                    },
                },
            },
        },
        # end neighbor parsers
        {
            "name": "neighbor_down.fib_accelerate",
            "getval": re.compile(
                r"""
                \s+neighbor-down\s(?P<fib_accelerate>fib-accelerate)
                $""", re.VERBOSE,
            ),
            "setval": "neighbor-down fib-accelerate",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "neighbor_down": {
                            "fib_accelerate": "{{ not not fib_accelerate }}",
                        },
                    },
                },
            },
        },
        {
            "name": "nexthop.suppress_default_resolution",
            "getval": re.compile(
                r"""
                \s+nexthop
                \s(?P<suppress_default_resolution>suppress-default-resolution)
                $""", re.VERBOSE,
            ),
            "setval": "nexthop suppress-default-resolution",
            "result": {
                "nexthop": {
                    "suppress_default_resolution": "{{ not not suppress_default_resolution }}",
                },
            },
        },
        {
            "name": "reconnect_interval",
            "getval": re.compile(
                r"""
                \s+reconnect-interval
                \s(?P<reconnect_interval>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "reconnect-interval {{ reconnect_interval }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "reconnect_interval": "{{ reconnect_interval }}",
                    },
                },
            },
        },
        {
            "name": "router_id",
            "getval": re.compile(
                r"""
                \s+router-id
                \s(?P<router_id>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "router-id {{ router_id }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "router_id": "{{ router_id }}",
                    },
                },
            },
        },
        {
            "name": "shutdown",
            "getval": re.compile(
                r"""
                \s+(?P<shutdown>shutdown)
                $""", re.VERBOSE,
            ),
            "setval": "shutdown",
            "result": {
                "shutdown": "{{ not not shutdown }}",
            },
        },
        {
            "name": "suppress_fib_pending",
            "getval": re.compile(
                r"""
                \s+no\s(?P<suppress_fib_pending>suppress-fib-pending)
                $""", re.VERBOSE,
            ),
            "setval": "suppress-fib-pending",
            "result": {
                "suppress_fib_pending": "{{ not suppress_fib_pending }}",
            },
        },
        {
            "name": "timers.bestpath_limit",
            "getval": re.compile(
                r"""
                \s+timers\sbestpath-limit
                \s(?P<timeout>\d+)
                (\s(?P<always>always))?
                $""", re.VERBOSE,
            ),
            "setval": "timers bestpath-limit {{ timers.bestpath_limit.timeout }}{{ ' always' if timers.bestpath_limit.timeout is defined }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "timers": {
                            "bestpath_limit": {
                                "timeout": "{{ timeout }}",
                                "always": "{{ not not always }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "timers.bgp",
            "getval": re.compile(
                r"""
                \s+timers\sbgp
                \s(?P<keepalive>\d+)
                (\s(?P<holdtime>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "timers bgp {{ timers.bgp.keepalive }} {{ timers.bgp.holdtime }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "timers": {
                            "bgp": {
                                "keepalive": "{{ keepalive }}",
                                "holdtime": "{{ holdtime }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "timers.prefix_peer_timeout",
            "getval": re.compile(
                r"""
                \s+timers
                \sprefix-peer-timeout\s(?P<prefix_peer_timeout>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "timers prefix-peer-timeout {{ timers.prefix_peer_timeout }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "timers": {
                            "prefix_peer_timeout": "{{ prefix_peer_timeout }}",
                        },
                    },
                },
            },
        },
        {
            "name": "timers.prefix_peer_wait",
            "getval": re.compile(
                r"""
                \s+timers
                \sprefix-peer-wait\s(?P<prefix_peer_wait>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "timers prefix-peer-wait {{ timers.prefix_peer_wait }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "timers": {
                            "prefix_peer_wait": "{{ prefix_peer_wait }}",
                        },
                    },
                },
            },
        },
        {
            "name": "fabric_soo",
            "getval": re.compile(
                r"""
                \s+fabric-soo
                \s(?P<fabric_soo>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "fabric-soo {{ fabric_soo }}",
            "result": {
                "fabric_soo": "{{ fabric_soo }}",
            },
        },
        {
            "name": "rd",
            "getval": re.compile(
                r"""
                \s+rd\s(?P<dual>dual)
                (\sid\s(?P<id>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "rd dual{{' id ' + rd.id if rd.id is defined }}",
            "result": {
                "rd": {
                    "dual": "{{ not not dual }}",
                    "id": "{{ id }}",
                },
            },
        },
        # VRF only
        {
            "name": "allocate_index",
            "getval": re.compile(
                r"""
                \s+allocate-index\s(?P<allocate_index>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "allocate-index {{ allocate_index }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "allocate_index": "{{ allocate_index }}",
                    },
                },
            },
        },
        # VRF only
        {
            "name": "local_as",
            "getval": re.compile(
                r"""
                \s+local-as\s(?P<local_as>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "local-as {{ local_as }}",
            "result": {
                "vrfs": {
                    '{{ "vrf_" + vrf|d() }}': {
                        "local_as": "{{ local_as }}",
                    },
                },
            },
        },
    ]
    # fmt: on
