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
    cmd = "aggregate-address {value}"

    if aggaddr.get("as_set"):
        cmd += " as-set"
    if aggaddr.get("as_confed_set"):
        cmd += " as-confed-set"
    if aggaddr.get("summary_only"):
        cmd += " summary-only"
    if aggaddr.get("route_policy"):
        cmd += " route-policy {route_policy}"

    return cmd.format(**aggaddr)


def _tmpl_allocate_label(config_data):
    if "allocate_label" in config_data:
        command = "allocate-label"
        if "all" in config_data["allocate_label"]:
            command += " all"

        if "route_policy" in config_data["allocate_label"]:
            command += " route-policy {route_policy}".format(**config_data["route_policy"])

        return command


def _tmpl_bgp_origin_as_validation(config_data):
    origin_as_conf = config_data.get("bgp", {}).get("origin_as", {}).get("validation")
    if origin_as_conf:
        command = []
        if "disable" in origin_as_conf:
            command.append("bgp origin-as validation disable")
        if "ibgp" in origin_as_conf.get("signal", {}):
            command.append("bgp origin-as validation signal ibgp")

        return command


def _tmpl_bgp_dampening(config_data):
    dampening_conf = config_data.get("bgp", {}).get("dampening", {})
    if dampening_conf:
        command = "bgp dampening"
        if "value" in dampening_conf:
            command += " " + str(dampening_conf["value"])
        if "route_policy" in dampening_conf:
            command += " route-policy " + dampening_conf["route_policy"]

        return command


def _tmpl_maximum_paths_ibgp(config_data):
    ibgp_conf = config_data.get("maximum_paths", {}).get("ibgp", {})
    if ibgp_conf:
        command = "maximum-paths ibgp"
        if "max_path_value" in ibgp_conf:
            command += " " + str(ibgp_conf["max_path_value"])
        if "order_igp_metric" in ibgp_conf:
            command += " order igp-metric"
        elif "selective_order_igp_metric" in ibgp_conf:
            command += " selective order igp-metric"
        elif "set" in ibgp_conf.get("unequal_cost", {}):
            command += " unequal-cost"
            if "order_igp_metric" in ibgp_conf.get("unequal_cost", {}):
                command += " order igp-metric"
            elif "selective_order_igp_metric" in ibgp_conf.get(
                "unequal_cost",
                {},
            ):
                command += " selective order igp-metric"
        return command


def _tmpl_maximum_paths_ebgp(config_data):
    ebgp_conf = config_data.get("maximum_paths", {}).get("ebgp", {})
    if ebgp_conf:
        command = "maximum-paths ebgp"
        if "max_path_value" in ebgp_conf:
            command += " " + str(ebgp_conf["max_path_value"])
        if "order_igp_metric" in ebgp_conf:
            command += " order igp-metric"
        elif "selective_order_igp_metric" in ebgp_conf:
            command += " selective order igp-metric"
        return command


def _tmpl_maximum_paths_eibgp(config_data):
    eibgp_conf = config_data.get("maximum_paths", {}).get("eibgp", {})
    if eibgp_conf:
        command = "maximum-paths ebgp"
        if "max_path_value" in eibgp_conf:
            command += " " + str(eibgp_conf["max_path_value"])
        if "order_igp_metric" in eibgp_conf:
            command += " order igp-metric"
        elif "selective_order_igp_metric" in eibgp_conf:
            command += " selective order igp-metric"
        return command


def _tmpl_network(config_data):
    cmd = "network {network}"
    if config_data.get("backdoor_route_policy"):
        cmd += " backdoor-route-policy {backdoor-route-policy}"
    if config_data.get("route_policy"):
        cmd += " route-policy {route_policy}"
    return cmd.format(**config_data)


def _tmpl_nexthop(config_data):
    nexthop_conf = config_data.get("nexthop", {})
    commands = []
    if nexthop_conf:
        if "resolution_prefix_length_minimum" in nexthop_conf:
            command = "nexthop resolution prefix-length minimum " + str(
                nexthop_conf["resolution_prefix_length_minimum"],
            )
            commands.append(command)
        if "trigger_delay_critical" in nexthop_conf:
            command = "nexthop trigger-delay critical " + str(
                nexthop_conf["trigger_delay_non_critical"],
            )
            commands.append(command)
        if "trigger_delay_non_critical" in nexthop_conf:
            command = "nexthop trigger-delay non-critical " + str(
                nexthop_conf["trigger_delay_non_critical"],
            )
            commands.append(command)
        if "route_policy" in nexthop_conf:
            command += " route-policy " + nexthop_conf["route_policy"]

    return commands


def _tmpl_optimal_route(config_data):
    orr_conf = config_data.get("optimal_route_reflection", {})
    if orr_conf:
        command = "optimal-route-reflection"
        if "group_name" in orr_conf:
            command += " " + str(orr_conf["value"])
        if "primary_address" in orr_conf:
            command += " " + orr_conf["primary_address"]
        if "secondary_address" in orr_conf:
            command += " " + orr_conf["secondary_address"]
        return command


def _tmpl_update(config_data):
    update_conf = config_data.get("update", {})
    update_wait = config_data.get("update", {}).get("wait_install")
    update_limit = config_data.get("update", {}).get("limit", {})
    commands = []
    if update_conf:
        if update_wait:
            command = "update wait-install"
            commands.append(command)
        if "address_family" in update_limit:
            command = "update limit address-family " + str(
                update_limit["address_family"],
            )
            commands.append(command)
        if "sub_group" in update_limit:
            if "ibgp" in update_limit["sub_group"]:
                command = "update limit sub-group ibgp " + str(
                    update_limit["sub_group"]["ibgp"],
                )
                commands.append(command)
            if "ebgp" in update_limit["sub_group"]:
                command = "update limit sub-group ebgp " + str(
                    update_limit["sub_group"]["ebgp"],
                )
                commands.append(command)
    return commands


def _tmplt_redistribute(redis):
    command = "redistribute {protocol}".format(**redis)
    if redis.get("id"):
        command += " {id}".format(**redis)
    if redis.get("metric"):
        command += " metric {metric}".format(**redis)
    if redis.get("level"):
        command += " level {level}".format(**redis)
    if redis.get("internal"):
        command += " internal"
    if redis.get("external"):
        command += " external"
    if redis.get("nssa_external"):
        command += " nssa-external"
    if redis.get("external_ospf"):
        command += " external {external_ospf}".format(**redis)
    if redis.get("route_policy"):
        command += " route-policy {route_policy}".format(**redis)
    return command


def _tmpl_vrf_all(config_data):
    conf = config_data.get("vrf_all", {})
    commands = []
    if conf:
        if "source_rt_import_policy" in conf:
            commands.append("vrf all source rt import-policy")
        if "label_mode" in conf:
            command = "vrf all label mode"
            if "per_ce" in conf.get("label_mode"):
                command += " per-ce"
            elif "per_vrf" in conf.get("label_mode"):
                command += " per-vrf"
            elif "route_policy" in conf.get("label_mode"):
                command += " route-policy " + conf["route_policy"]
        if "table_policy" in conf:
            command = "vrf all table-policy " + conf["table_policy"]
            commands.append(command)
        return command


def _tmpl_wt(config_data):
    conf = config_data.get("weight", "")
    if conf:
        command = "weight"
        if "reset_on_import" in conf:
            command += " reset-on-import"
        elif "reset_on_import_disable" in conf:
            command += " reset-on-import disable"
        return command


def _tmpl_label_mode(conf):
    if "label_mode" in conf:
        command = "vrf all label mode"
        if "per_ce" in conf.get("label_mode"):
            command += " per-ce"
        elif "per_vrf" in conf.get("label_mode"):
            command += " per-vrf"
        elif "per_prefix" in conf.get("label_mode"):
            command += " per-prefix"
        elif "route_policy" in conf.get("label_mode"):
            command += " route-policy " + conf["route_policy"]
    return command


class Bgp_address_familyTemplate(NetworkTemplate):
    def __init__(self, lines=None):
        super(Bgp_address_familyTemplate, self).__init__(
            lines=lines,
            tmplt=self,
        )

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
            "setval": "router bgp {{ as_number }}",
            "result": {"as_number": "{{ as_num }}"},
            "shared": True,
        },
        {
            "name": "vrf",
            "getval": re.compile(
                r"""
                \s+vrf
                \s(?P<vrf>\b(?!all\b)\S+)$""",
                re.VERBOSE,
            ),
            "setval": "vrf {{ vrf }}",
            "result": {
            },
            "shared": True,
        },
        {
            "name": "address_family",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\b(?!all\b)\S+))?
                (?P<address_family>\s+address-family\s(?P<afi>\S+)\s(?P<safi>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "address-family {{ afi}} {{safi}}",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "afi": "{{ afi}}",
                        "safi": "{{safi}}",
                        "vrf": "{{ vrf }}",
                    },
                },
            },
            "shared": True,
        },
        {
            "name": "advertise_best_external",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+advertise\s(?P<abe>best-external)
                $""", re.VERBOSE,
            ),
            "setval": "advertise best-external",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "advertise_best_external": "{{True if abe is defined}}",
                    },
                },
            },
        },
        {
            "name": "allocate_label",
            "getval": re.compile(
                r"""
                \s+allocate-label\s(?P<all>all)
                 (\sroute-policy\s(?P<route_policy>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_allocate_label,
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "allocate_label": {
                            "all": "{{True if all is defined}}",
                            "route_policy": "{{route_policy}}",
                        },
                    },
                },
            },
        },

        {
            "name": "aggregate_address",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+aggregate-address\s(?P<value>\S+)
                (\sas-set(?P<as_set>))?
                (\sas-confed-set(?P<as_confed_set>))?
                (\ssummary-only(?P<summery_only>))?
                (\sroute-policy\s(?P<route_policy>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": _tmplt_aggregate_address,
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "aggregate_address": [
                            {
                                "as_set": "{{True if as_set is defined}}",
                                "as_confed_set": "{{True if as_confed_set is defined}}",
                                "summary_only": "{{True if summery_only is defined}}",
                                "value": "{{value}}",
                                "route_policy": "{{route_policy}}",
                            },
                        ],
                    },
                },
            },

        },
        {
            "name": "additional_paths",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+additional-paths\s(?P<value>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "additional-paths {{additional_paths}}",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "additional_paths": "{{value}}",
                    },
                },
            },
        },
        {
            "name": "as_path_loopcheck_out_disable",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+as-path-loopcheck\sout(?P<value>\sdisable)
                $""", re.VERBOSE,
            ),
            "setval": "as-path-loopcheck out disable",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "as_path_loopcheck_out_disable": "{{True if value is defined }}",
                    },
                },
            },
        },
        {
            "name": "bgp_attribute_download",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+bgp\s(?P<value>attribute-download)
                $""", re.VERBOSE,
            ),
            "setval": "bgp attribute-download",
            "compval": "bgp.attribute_download",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d()}}': {
                        "bgp": {
                            "attribute_download": "{{True if value is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_bestpath_origin_as_use",
            "getval": re.compile(
                r"""
                \s+bgp\sbestpath\s(?P<origin_as>origin-as\suse\svalidity)
                $""", re.VERBOSE,
            ),
            "setval": "bgp bestpath origin-as use validity",
            "compval": "bgp.bestpath.origin_as.use",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "bgp": {
                            "bestpath": {"origin_as": {"use": {"validity": "{{True if origin_as is defined }}"}}},
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_bestpath_origin_as_allow",
            "getval": re.compile(
                r"""
                \s+bgp\sbestpath\s(?P<origin_as>origin-as\sallow\sinvalid)
                $""", re.VERBOSE,
            ),
            "setval": "bgp bestpath origin-as allow invalid",
            "compval": "bgp.bestpath.origin_as.allow",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "bgp": {
                            "bestpath": {
                                "origin_as": {"allow": {"invalid": "{{True if origin_as is defined }}"}},
                            },
                        },
                    },
                },
            },

        },
        {
            "name": "bgp_reflection_disable",
            "getval": re.compile(
                r"""
                \s+bgp\sclient-to-client
                \sreflection
                \sdisable(?P<disable>)
                $""", re.VERBOSE,
            ),
            "setval": "bgp client-to-client reflection disable",
            "compval": "bgp.client_to_client.reflection.disable",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "bgp": {
                            "client_to_client": {
                                "reflection": {
                                    "disable": "{{True if disable is defined}}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_client_to_client_reflection_cluster_id",
            "getval": re.compile(
                r"""
                \s+bgp\sclient-to-client
                (\sreflection\scluster-id(?P<cs_id>\s\d+))?
                (\sdisable(?P<disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "bgp client-to-clinet reflection cluster-id "
                      "{{ bgp.client_to_client.reflection.cluster_id }} disable",
            "compval": "bgp.client_to_client.reflection.cluster_id",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "bgp": {
                            "client_to_client": {
                                "reflection": {
                                    "cluster_id_disable": {
                                        "cluster_id": "{{cs_id}}",
                                        "disable": "{{True if disable is defined}}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_dampening",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+bgp\sdampening(?P<set>)
                (\s(?P<value>\d+))?
                (\sroute-policy\s(?P<route_policy>)\S+)?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_bgp_dampening,
            "compval": "bgp.dampening",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "bgp": {
                            "dampening": {
                                "set": "{{True if set is defined}}",
                                "value": "{{value}}",
                                "route_policy": "{{route_policy}}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_label_delay",
            "getval": re.compile(
                r"""
                \s+bgp\slabel-delay(?P<set>)
                (\s(?P<first>\S+))
                (\s(?P<second>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "bgp label-delay {{ bgp.label_delay.delay_second_parts}} {{ bgp.label_delay.delay_ms_parts}}",
            "compval": "bgp.label_delay",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "bgp": {
                            "label_delay": {
                                "delay_second_parts": "{{first}}",
                                "delay_ms_parts": "{{second}}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_import_delay",
            "getval": re.compile(
                r"""
                \s+bgp\simport-delay(?P<set>)
                (\s(?P<first>\S+))
                (\s(?P<second>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "bgp import-delay {{ bgp.import_delay.delay_second_parts}} {{ bgp.import_delay.delay_ms_parts}}",
            "compval": "bgp.import_delay",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "bgp": {
                            "import_delay": {
                                "delay_second_parts": "{{first}}",
                                "delay_ms_parts": "{{second}}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_origin_as_validation",
            "getval": re.compile(
                r"""
                \s+bgp\sorigin-as\svalidation
                (\s(?P<disable>disable))?
                (\ssignal\s(?P<signal>ibgp))?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_bgp_origin_as_validation,
            "compval": "bgp.origin_as.validation",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "bgp": {
                            "origin_as": {
                                "validation": {
                                    "disable": "{{True if disable is defined}}",
                                    "signal": {
                                        "ibgp": "{{True if signal is defined}}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bgp_scan_time",
            "getval": re.compile(
                r"""
                \s+bgp\sscan-time\s(?P<scan_time>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "bgp scan-time {{bgp.scan_time}}",
            "compval": "bgp.scan_time",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "bgp": {
                            "scan_time": "{{scan_time}}",
                        },
                    },
                },
            },
        },
        {
            "name": "default_martian_check_disable",
            "getval": re.compile(
                r"""
                \s+default-martian-check(?P<disable>\sdisable)
                $""", re.VERBOSE,
            ),
            "setval": "default-martian-check disable",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "default_martian_check_disable": "{{ True if disable is defined}}",
                    },
                },
            },
        },
        {
            "name": "distance",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+distance\sbgp
                (\s(?P<external>\d+))?
                (\s(?P<internal>\d+))?
                (\s(?P<local>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "distnace bgp {{distnace.bgp.routes_external_to_as}} "
                      "{{distnace.bgp.routes_internal_to_as}} {{distnace.bgp.local_routes}}",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "distance": {
                            "routes_external_to_as": "{{external}}",
                            "routes_internal_to_as": "{{internal}}",
                            "local_routes": "{{local}}",
                        },
                    },
                },
            },
        },
        {
            "name": "dynamic_med",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+dynamic-med\sinterval\s(?P<dynamic_med>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "dynamic-med interval {{dynamic_med}}",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "dynamic_med": "{{ dynamic_med}}",
                    },
                },
            },
        },
        {
            "name": "maximum_paths_ibgp",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+maximum-paths\sibgp\s((?P<max_path_value>\S+))?
                (\sorder\sigp-metric(?P<order_igp_metric>))?
                (\sselective\sorder\sigp-metric(?P<selective_order_igp_metric>))?
                (\sunequal-cost(?P<unequal_cost>))?
                (\sorder\sigp-metric(?P<order_igp_metric1>))?
                (\sselective\sorder\sigp-metric(?P<selective_order_igp_metric1>))?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_maximum_paths_ibgp,
            "compval": "maximum_paths.ibgp",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "maximum_paths": {
                            "ibgp": {
                                "max_path_value": "{{ max_path_value }}",
                                "order_igp_metric": "{{ True if order_igp_metric is defined}}",
                                "selective_order_igp_metric":
                                "{{ True if selective_order_igp_metric is defined}}",
                                "unequal_cost": {
                                    "set": "{{ True if unequal_cost is defined}}",
                                    "order_igp_metric": "{{ True if order_igp_metric1 is defined}}",
                                    "selective_order_igp_metric": "{{ True if selective_order_igp_metric1 is defined}}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "maximum_paths_ebgp",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+maximum-paths\sebgp\s((?P<max_path_value>\S+))?
                (\sorder\sigp-metric(?P<order_igp_metric>))?
                (\sselective\sorder\sigp-metric(?P<selective_order_igp_metric>))?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_maximum_paths_ebgp,
            "compval": "maximum_paths.ebgp",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "maximum_paths": {
                            "ebgp": {
                                "max_path_value": "{{ max_path_value }}",
                                "order_igp_metric": "{{ True if order_igp_metric is defined}}",
                                "selective_order_igp_metric":
                                "{{ True if selective_order_igp_metric is defined}}",

                            },
                        },
                    },
                },
            },
        },
        {
            "name": "maximum_paths_eibgp",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+maximum-paths\seibgp\s((?P<max_path_value>\S+))?
                (\sorder\sigp-metric(?P<order_igp_metric>))?
                (\sselective\sorder\sigp-metric(?P<selective_order_igp_metric>))?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_maximum_paths_eibgp,
            "compval": "maximum_paths.eibgp",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "maximum_paths": {
                            "eibgp": {
                                "max_path_value": "{{ max_path_value }}",
                                "order_igp_metric": "{{ True if order_igp_metric is defined}}",
                                "selective_order_igp_metric":
                                "{{ True if selective_order_igp_metric is defined}}",

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
                \s+network\s(?P<value>\S+)
                (\sbackdoor-route-policy\s(?P<backdoor_route_policy>)\S+)?
                (\sroute-policy\s(?P<route_policy>)\S+)?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_network,
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "networks": [
                            {
                                "backdoor_route_policy": "{{backdoor_route_policy}}",
                                "network": "{{value}}",
                                "route_policy": "{{route_policy}}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "nexthop",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+nexthop
                (\sresolution\sprefix-length\sminimum\s(?P<value>\d+))?
                (\strigger-delay\scritical\s(?P<trigger_delay_critical>\d+))?
                 (\strigger-delay\snon-critical\s(?P<trigger_delay_non_critical>\d+))?
                (\sroute-policy\s(?P<route_policy>)\S+)?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_nexthop,
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "nexthop": {
                            "trigger_delay_critical": "{{trigger_delay_critical}}",
                            "trigger_delay_non_critical": "{{trigger_delay_non_critical}}",
                            "resolution_prefix_length_minimum": "{{value}}",
                            "route_policy": "{{route_policy}}",
                        },
                    },
                },
            },
        },
        {
            "name": "optimal_route_reflection",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+optimal-route-reflection
                (\s(?P<value>\S+))?
                (\s(?P<primary>\S+))?
                (\s(?P<secondary>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_optimal_route,
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "optimal_route_reflection": {
                            "group_name": "{{value}}",
                            "primary_address": "{{primary}}",
                            "secondary_address": "{{secondary}}",
                        },
                    },
                },
            },
        },
        {
            "name": "permanent_network_route_policy",
            "getval": re.compile(
                r"""
                \s+permanent-network\s(?P<value>route_policy\S+)?
                $""", re.VERBOSE,
            ),
            "setval": "permanent-network route-policy {{permanent_network_route_policy}}",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "permanent_network_route_policy": "{{route_policy}}",
                    },
                },
            },
        },
        {
            "name": "retain_local_label",
            "getval": re.compile(
                r"""
                \s+retain\slocal-label\s(?P<value>\d+)?
                $""", re.VERBOSE,
            ),
            "setval": "retain local-label {{retain_local_label}}",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "retain_local_label": "{{value}}",
                    },
                },
            },
        },
        {
            "name": "update",
            "getval": re.compile(
                r"""
                \s+update
                (\slimit)?
                (\ssub-group)?
                (\sibgp\s(?P<ibgp>\d+))?
                 (\sebgp\s(?P<ebgp>\d+))?
                (\saddress-family\s(?P<af>\d+))?
                (\swait-install(?P<wait>))?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_update,
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "update": {
                            "wait_install": "{{True if wait is defined}}",
                            "limit": {
                                "sub_group": {
                                    "ibgp": "{{ibgp}}",
                                    "ebgp": "{{ebgp}}",
                                },
                                "address_family": "{{af}}",
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
                (\s+vrf\s(?P<vrf>\S+))?
                \s+redistribute
                \s(?P<protocol>\S+)
                (\s(?P<id>\S+))?
                (\smetric\s(?P<metric>\d+))?
                (\slevel\s(?P<level>\S+))?
                (\sinternal(?P<internal>))?
                (\sexternal(?P<external>)(\s(?P<ospf_external>\S+))?)?
                (\snssa-external(?P<nssa_external>))?
                (\sroute-policy\s(?P<route_policy>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": _tmplt_redistribute,
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "redistribute": [
                            {
                                "protocol": "{{protocol}}",
                                "id": "{{id}}",
                                "route_policy": "{{route_policy}}",
                                "metric": "{{metric}}",
                                "internal": "{{True if internal is defined}}",
                                "external": "{{True if external is defined}}",
                                "level": "{{level}}",
                                "ospf_external": "{{ospf_external}}",
                                "nssa_external": "{{True if nssa_external is defined}}",
                            },
                        ],
                    },
                },
            },
        },
        {
            "name": "inter_as_install",
            "getval": re.compile(
                r"""
                \s+inter-as\s(?P<inter_as>install)
                $""", re.VERBOSE,
            ),
            "setval": "inter-as install",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "inter_as_install": "{{True if inter_as is defined}}",
                    },
                },
            },

        },
        {
            "name": "segmented_multicast",
            "getval": re.compile(
                r"""
                \s+(?P<segmented_multicast>segmented-multicast)
                $""", re.VERBOSE,
            ),
            "setval": "segmented-multicast",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "segmented_multicast": "{{True if segmented_multicast is defined}}",
                    },
                },
            },

        },
        {
            "name": "global_table_multicast",
            "getval": re.compile(
                r"""
                \s+(?P<global_table_multicast>global-table-multicast)
                $""", re.VERBOSE,
            ),
            "setval": "global-table-multicast",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "global_table_multicast": "{{True if global_table_multicast is defined}}",
                    },
                },
            },

        },
        {
            "name": "table_policy",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                (\s+table-policy\s(?P<table_policy>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "table-policy {{table_policy}}",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "table_policy": "{{table_policy}}",
                    },
                },
            },
        },
        {
            "name": "vrf_all_conf",
            "getval": re.compile(
                r"""
                \s+vrf\sall
                (\s+source\srt(?P<source_rt_import_policy>\simport-policy))?
                (\s+table-policy\s(?P<table_policy>\S+))?
                (\s+label\smode)?
                (\s+(?P<per_ce>per-ce))?
                (\s+(?P<per_vrf>per-vrf))?
                (\s+route_policy\s(?P<route_policy>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_vrf_all,
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "vrf_all_conf": {
                            "source_rt_import_policy": "{{ True if source_rt_import_policy is defined}}",
                            "table_policy": "{{table_policy}}",
                            "label_mode": {
                                "per_ce": "{{ True if per_ce is defined}}",
                                "per_vrf": "{{True if per_vrf is defined}}",
                                "route_policy": "{{route_policy}}",
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
                \s+weight
                (\sreset-on-import\sdisable(?P<reset_on_import_disable>))?
                (\sreset-on-import(?P<reset_on_import>))?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_wt,
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "weight": {
                            "reset_on_import_disable": "{{ True if reset_on_import_disable is defined}}",
                            "reset_on_import": "{{ True if reset_on_import is defined}}",
                        },
                    },
                },
            },
        },
        {
            "name": "route_target_download",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+route-target\s(?P<value>download)
                $""", re.VERBOSE,
            ),
            "setval": "route-target download",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "route_target_download": "{{True if value is defined }}",

                    },
                },
            },
        },
        {
            "name": "mvpn_single_forwarder_selection_all",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+mvpn\ssingle-forwarder-selection\s(?P<value>all)
                $""", re.VERBOSE,
            ),
            "setval": "mvpn single-forwarder-selection all",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "mvpn_single_forwarder_selection_all": "{{True if value is defined }}",
                    },
                },
            },
        },
        {
            "name": "mvpn_single_forwarder_selection_highest_ip_address",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+mvpn\ssingle-forwarder-selection\s(?P<value>highest-ip-address)
                $""", re.VERBOSE,
            ),
            "setval": "mvpn single-forwarder-selection highest-ip-address",
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "mvpn_single_forwarder_selection_highest_ip_address": "{{True if value is defined }}",
                    },
                },
            },
        },
        {
            "name": "label_mode",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+label\smode\s(?P<per_ce>per-ce)?(?P<per_prefix>per-prefix)?
                (?P<per_vrf>per-vrf)?
                (?P<rr>route-policy\s\S+)?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_label_mode,
            "result": {
                "address_family": {
                    '{{"address_family_" + afi + "_" + safi + "_vrf_" + vrf|d() }}': {
                        "label_mode": {
                            "per_ce": "{{ True if per_ce is defined}}",
                            "per_prefix": "{{ True if per_prefix is defined}}",
                            "per_vrf": "{{ True if per_vrf is defined}}",
                            "route_policy": "{{ route_policy}}",
                        },
                    },
                },
            },
        },
    ]
    # fmt: on
