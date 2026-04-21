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


def _tmplt_aggregate_address(aggaddr):
    cmd = "aggregate-address {prefix}"

    if aggaddr.get("advertise_map"):
        cmd += " advertise-map {advertise_map}"
    if aggaddr.get("as_set"):
        cmd += " as-set"
    if aggaddr.get("attribute_map"):
        cmd += " attribute-map {attribute_map}"
    if aggaddr.get("summary_only"):
        cmd += " summary-only"
    if aggaddr.get("suppress_map"):
        cmd += " suppress-map {suppress_map}"

    return cmd.format(**aggaddr)


def _tmplt_dampening(proc):
    damp = proc.get("dampening", {})
    cmd = "dampening"

    if damp.get("set") is False:
        return "no {0}".format(cmd)
    if damp.get("route_map"):
        cmd += " route-map {route_map}".format(**damp)
    for x in (
        "decay_half_life",
        "start_reuse_route",
        "start_suppress_route",
        "max_suppress_time",
    ):
        if x in damp:
            cmd += " {0}".format(damp[x])
    return cmd


def _tmplt_redistribute(redis):
    command = "redistribute {protocol}".format(**redis)
    if redis.get("id"):
        command += " {id}".format(**redis)
    command += " route-map {route_map}".format(**redis)
    return command


class Bgp_address_familyTemplate(NetworkTemplate):
    def __init__(self, lines=None):
        super(Bgp_address_familyTemplate, self).__init__(lines=lines, tmplt=self)

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
                (\s+vrf\s(?P<vrf>\S+))?
                (\s+neighbor\s(?P<nbr>\S+))?
                \s+address-family
                \s(?P<afi>\S+)
                (\s(?P<safi>\S+))?
                $""",
                re.VERBOSE,
            ),
            "setval": "address-family {{ afi }}{{ (' ' + safi) if safi is defined else ''}}",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "vrf": "{{ vrf }}",
                        "afi": "{{ afi }}",
                        "safi": "{{ safi }}",
                    },
                },
            },
            "shared": True,
        },
        {
            "name": "additional_paths.install_backup",
            "getval": re.compile(
                r"""
                \s+additional-paths
                \sinstall\s(?P<backup>backup)
                $""",
                re.VERBOSE,
            ),
            "setval": "additional-paths install backup",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "additional_paths": {
                            "install_backup": "{{ not not backup }}",
                        },
                    },
                },
            },
        },
        {
            "name": "additional_paths.receive",
            "getval": re.compile(
                r"""
                \s+additional-paths
                \s(?P<receive>receive)
                $""",
                re.VERBOSE,
            ),
            "setval": "additional-paths receive",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "additional_paths": {
                            "receive": "{{ not not receive }}",
                        },
                    },
                },
            },
        },
        {
            "name": "additional_paths.selection.route_map",
            "getval": re.compile(
                r"""
                \s+additional-paths
                \sselection\sroute-map
                \s(?P<route_map>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": "additional-paths selection route-map {{ additional_paths.selection.route_map }}",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "additional_paths": {
                            "selection": {
                                "route_map": "{{ route_map }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "additional_paths.send",
            "getval": re.compile(
                r"""
                \s+additional-paths
                \s(?P<send>send)
                $""",
                re.VERBOSE,
            ),
            "setval": "additional-paths send",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "additional_paths": {
                            "send": "{{ not not send }}",
                        },
                    },
                },
            },
        },
        {
            "name": "advertise_l2vpn_evpn",
            "getval": re.compile(
                r"""
                \s+(?P<advertise_l2vpn_evpn>advertise\sl2vpn\sevpn)
                $""",
                re.VERBOSE,
            ),
            "setval": "advertise l2vpn evpn",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "advertise_l2vpn_evpn": "{{ not not advertise_l2vpn_evpn }}",
                    },
                },
            },
        },
        {
            "name": "advertise_pip",
            "getval": re.compile(
                r"""
                \s+(?P<advertise_pip>advertise-pip)
                $""",
                re.VERBOSE,
            ),
            "setval": "advertise-pip",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "advertise_pip": "{{ not not advertise_pip }}",
                    },
                },
            },
        },
        {
            "name": "advertise_system_mac",
            "getval": re.compile(
                r"""
                \s+(?P<advertise_system_mac>advertise-system-mac)
                $""",
                re.VERBOSE,
            ),
            "setval": "advertise-system-mac",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "advertise_system_mac": "{{ not not advertise_system_mac }}",
                    },
                },
            },
        },
        {
            "name": "allow_vni_in_ethertag",
            "getval": re.compile(
                r"""
                \s+(?P<allow_vni_in_ethertag>allow-vni-in-ethertag)
                $""",
                re.VERBOSE,
            ),
            "setval": "allow-vni-in-ethertag",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "allow_vni_in_ethertag": "{{ not not allow_vni_in_ethertag }}",
                    },
                },
            },
        },
        {
            "name": "aggregate_address",
            "getval": re.compile(
                r"""
                \s+aggregate-address
                \s(?P<prefix>\S+)
                (\s(?P<as_set>as-set))?
                (\s(?P<summary_only>summary-only))?
                (\sadvertise-map\s(?P<advertise_map>\S+))?
                (\sattribute-map\s(?P<attribute_map>\S+))?
                (\ssuppress-map\s(?P<suppress_map>\S+))?
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_aggregate_address,
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "aggregate_address": [
                            {
                                "prefix": "{{ prefix }}",
                                "as_set": "{{ True if as_set is defined else None }}",
                                "summary_only": "{{ True if summary_only is defined else None }}",
                                "advertise_map": "{{ advertise_map }}",
                                "attribute_map": "{{ attribute_map }}",
                                "suppress_map": "{{ suppress_map }}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "client_to_client.no_reflection",
            "getval": re.compile(
                r"""
                \s+no\sclient-to-client
                \s(?P<reflection>reflection)
                $""",
                re.VERBOSE,
            ),
            "setval": "client-to-client reflection",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "client_to_client": {
                            "no_reflection": "{{ not not reflection }}",
                        },
                    },
                },
            },
        },
        {
            "name": "dampen_igp_metric",
            "getval": re.compile(
                r"""
                \s+dampen-igp-metric
                \s(?P<dampen_igp_metric>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "dampen-igp-metric {{ dampen_igp_metric }}",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "dampen_igp_metric": "{{ dampen_igp_metric }}",
                    },
                },
            },
        },
        {
            "name": "dampening",
            "getval": re.compile(
                r"""
                \s+(?P<dampening>dampening)
                (\s(?P<decay_half_life>\d+))?
                (\s(?P<start_reuse_route>\d+))?
                (\s(?P<start_suppress_route>\d+))?
                (\s(?P<max_suppress_time>\d+))?
                (\sroute-map\s(?P<route_map>\S+))?
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_dampening,
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "dampening": {
                            "set": "{{ True if dampening is defined"
                                   " and ((not decay_half_life|d(False),"
                                   " not start_reuse_route|d(False), "
                                   " not start_suppress_route|d(False), not max_suppress_time|d(False), not route_map|d(""))|all) }}",
                            "decay_half_life": "{{ decay_half_life }}",
                            "start_reuse_route": "{{ start_reuse_route }}",
                            "start_suppress_route": "{{ start_suppress_route }}",
                            "max_suppress_time": "{{ max_suppress_time }}",
                            "route_map": "{{ route_map }}",
                        },
                    },
                },
            },
        },
        {
            "name": "default_information.originate",
            "getval": re.compile(
                r"""
                \s+default-information
                \s(?P<originate>originate)
                $""",
                re.VERBOSE,
            ),
            "setval": "default-information originate",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "default_information": {
                            "originate": "{{ not not originate }}",
                        },
                    },
                },
            },
        },
        {
            "name": "default_metric",
            "getval": re.compile(
                r"""
                \s+default-metric
                \s(?P<default_metric>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "default-metric {{ default_metric }}",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "default_metric": "{{ default_metric }}",
                    },
                },
            },
        },
        {
            "name": "distance",
            "getval": re.compile(
                r"""
                \s+distance
                \s(?P<ebgp_routes>\d+)
                \s(?P<ibgp_routes>\d+)
                \s(?P<local_routes>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "distance {{ distance.ebgp_routes }} {{ distance.ibgp_routes }} {{ distance.local_routes }}",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "distance": {
                            "ebgp_routes": "{{ ebgp_routes }}",
                            "ibgp_routes": "{{ ibgp_routes }}",
                            "local_routes": "{{ local_routes }}",
                        },
                    },
                },
            },
        },
        {
            "name": "export_gateway_ip",
            "getval": re.compile(
                r"""
                \s+(?P<export_gateway_ip>export-gateway-ip)
                $""",
                re.VERBOSE,
            ),
            "setval": "export-gateway-ip",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "export_gateway_ip": "{{ not not export_gateway_ip }}",
                    },
                },
            },
        },
        {
            "name": "inject_map",
            "getval": re.compile(
                r"""
                \s+inject-map
                \s(?P<route_map>\S+)
                \sexist-map\s(?P<exist_map>\S+)
                (\s(?P<copy_attributes>copy-attributes))?
                $""",
                re.VERBOSE,
            ),
            "setval": "inject-map {{ route_map }} exist-map {{ exist_map }}{{ ' copy-attributes' if copy_attributes|d(False) else '' }}",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "inject_map": [
                            {
                                "route_map": "{{ route_map }}",
                                "exist_map": "{{ exist_map }}",
                                "copy_attributes": "{{ not not copy_attributes }}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "maximum_paths.parallel_paths",
            "getval": re.compile(
                r"""
                \s+maximum-paths
                \s(?P<parallel_paths>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "maximum-paths {{ maximum_paths.parallel_paths }}",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "maximum_paths": {
                            "parallel_paths": "{{ parallel_paths }}",
                        },
                    },
                },
            },
        },
        {
            "name": "maximum_paths.ibgp.parallel_paths",
            "getval": re.compile(
                r"""
                \s+maximum-paths
                \sibgp\s(?P<parallel_paths>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "maximum-paths ibgp {{ maximum_paths.ibgp.parallel_paths }}",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "maximum_paths": {
                            "ibgp": {
                                "parallel_paths": "{{ parallel_paths }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "maximum_paths.eibgp.parallel_paths",
            "getval": re.compile(
                r"""
                \s+maximum-paths
                \seibgp\s(?P<parallel_paths>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "maximum-paths eibgp {{ maximum_paths.eibgp.parallel_paths }}",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "maximum_paths": {
                            "eibgp": {
                                "parallel_paths": "{{ parallel_paths }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "maximum_paths.local.parallel_paths",
            "getval": re.compile(
                r"""
                \s+maximum-paths
                \slocal\s(?P<parallel_paths>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "maximum-paths local {{ maximum_paths.local.parallel_paths }}",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "maximum_paths": {
                            "local": {
                                "parallel_paths": "{{ parallel_paths }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "maximum_paths.mixed.parallel_paths",
            "getval": re.compile(
                r"""
                \s+maximum-paths
                \smixed\s(?P<parallel_paths>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "maximum-paths mixed {{ maximum_paths.mixed.parallel_paths }}",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "maximum_paths": {
                            "mixed": {
                                "parallel_paths": "{{ parallel_paths }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "networks",
            "getval": re.compile(
                r"""
                \s+network
                \s(?P<prefix>\S+)
                (\sroute-map\s(?P<route_map>\S+))?
                $""",
                re.VERBOSE,
            ),
            "setval": "network {{ prefix }}{{ (' route-map ' + route_map) if route_map is defined else '' }}",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "networks": [
                            {
                                "prefix": "{{ prefix }}",
                                "route_map": "{{ route_map }}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "nexthop.route_map",
            "getval": re.compile(
                r"""
                \s+nexthop
                \sroute-map\s(?P<route_map>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": "nexthop route-map {{ nexthop.route_map }}",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "nexthop": {
                            "route_map": "{{ route_map }}",
                        },
                    },
                },
            },
        },
        {
            "name": "nexthop.trigger_delay",
            "getval": re.compile(
                r"""
                \s+nexthop
                \strigger-delay
                \scritical\s(?P<critical_delay>\d+)
                \snon-critical\s(?P<non_critical_delay>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "nexthop trigger-delay critical {{ nexthop.trigger_delay.critical_delay }} non-critical {{ nexthop.trigger_delay.non_critical_delay }}",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "nexthop": {
                            "trigger_delay": {
                                "critical_delay": "{{ critical_delay }}",
                                "non_critical_delay": "{{ non_critical_delay }}",
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
                \s+redistribute
                \s(?P<protocol>\S+)
                (\s(?P<id>\S+))?
                \sroute-map\s(?P<rmap>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_redistribute,
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "redistribute": [
                            {
                                "protocol": "{{ protocol }}",
                                "id": "{{ id }}",
                                "route_map": "{{ rmap }}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "retain.route_target.retain_all",
            "getval": re.compile(
                r"""
                \s+retain\sroute-target
                \s(?P<retain_all>all)
                $""",
                re.VERBOSE,
            ),
            "setval": "retain route-target all",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "retain": {
                            "route_target": {
                                "retain_all": "{{ not not retain_all }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "retain.route_target.route_map",
            "getval": re.compile(
                r"""
                \s+retain\sroute-target
                \sroute-map\s(?P<route_map>\S+)
                $""",
                re.VERBOSE,
            ),
            "setval": "retain route-target route-map {{ retain.route_target.route_map }}",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "retain": {
                            "route_target": {
                                "route_map": "{{ route_map }}",
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
                \s+(?P<suppress_inactive>suppress-inactive)
                $""",
                re.VERBOSE,
            ),
            "setval": "suppress-inactive",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "suppress_inactive": "{{ not not suppress_inactive }}",
                    },
                },
            },
        },
        {
            "name": "table_map",
            "getval": re.compile(
                r"""
                \s+table-map
                \s(?P<name>\S+)
                (\s(?P<filter>filter))?
                $""",
                re.VERBOSE,
            ),
            "setval": "table-map {{ table_map.name }}{{ ' filter' if table_map.filter|d(False) }}",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "table_map": {
                            "name": "{{ name }}",
                            "filter": "{{ not not filter }}",
                        },
                    },
                },
            },
        },
        {
            "name": "timers.bestpath_defer",
            "getval": re.compile(
                r"""
                \s+timers
                \sbestpath-defer\s(?P<defer_time>\d+)
                \smaximum\s(?P<maximum_defer_time>\d+)
                $""",
                re.VERBOSE,
            ),
            "setval": "timers bestpath-defer {{ timers.bestpath_defer.defer_time }} maximum {{ timers.bestpath_defer.maximum_defer_time }}",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "timers": {
                            "bestpath_defer": {
                                "defer_time": "{{ defer_time }}",
                                "maximum_defer_time": "{{ maximum_defer_time }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "wait_igp_convergence",
            "getval": re.compile(
                r"""
                \s+(?P<wait_igp_convergence>wait-igp-convergence)
                $""",
                re.VERBOSE,
            ),
            "setval": "wait-igp-convergence",
            "result": {
                "address_family": {
                    '{{ nbr|d("nbr_") + afi + "_" + safi|d() + "_" + vrf|d() }}': {
                        "wait_igp_convergence": "{{ not not wait_igp_convergence }}",
                    },
                },
            },
        },
    ]
    # fmt: on
