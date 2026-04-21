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


def _tmpl_aigp(config_data):
    conf = config_data.get("aigp", {})
    commands = []
    if conf:
        if "set" in conf:
            commands.append("aigp")
        if "disable" in conf:
            commands.append("aigp disable")
        if "send_cost_community_disable" in conf:
            commands.append("aigp send cost-community disable")
        if "send_med" in conf and "set" in conf.get("send_med", {}):
            commands.append("aigp send med")
        if "send_med" in conf and "disable" in conf.get("send_med", {}):
            commands.append("aigp send med disable")
    return commands


def _tmpl_validation(config_data):
    conf = config_data.get("validation", {})
    command = ""
    if conf:
        if "set" in conf:
            command = "validation"
        if "disable" in conf:
            command = "validation disbale"
        if "redirect" in conf:
            command = "validation redirect"
    return command


def _tmpl_next_hop_unchanged(config_data):
    conf = config_data.get("next_hop_unchanged", {})
    command = ""
    if conf:
        if "set" in conf:
            command = "next-hop-unchanged"
        if "inheritance_disable" in conf:
            command += "next-hop-unchanged inheritance-disable"
        if "multipath" in conf:
            command = "next-hop-unchanged multipath"
    return command


def _tmpl_maximum_prefix(config_data):
    conf = config_data.get("maximum_prefix", {})
    if conf:
        command = "maximum-prefix"
        if "max_limit" in conf:
            command += " " + str(conf["max_limit"])
        if "threshold_value" in conf:
            command += " " + str(conf["threshold_value"])
        if "restart" in conf:
            command += " restart " + str(conf["restart"])
        elif "warning_only" in conf:
            command += " warning-only"
        elif "discard_extra_paths" in conf:
            command += " discard-extra-paths"

    return command


def _tmpl_soft_reconfiguration(config_data):
    conf = config_data.get("soft_reconfiguration", {})
    if conf:
        command = "soft-reconfiguration "
        if "inbound" in conf:
            command += "inbound"
            if "set" in conf["inbound"]:
                pass
            elif "always" in conf["inbound"]:
                command += " always"
            if "inheritance_disable" in conf["inbound"]:
                command += " inheritance-disable"

    return command


def _tmpl_remove_private_AS(config_data):
    conf = config_data.get("remove_private_AS", {})
    if conf:
        command = " "
        if "set" in conf:
            command = "remove-private-AS"
        if "inbound" in conf:
            command += " inbound"
        if "entire_aspath" in conf:
            command += " entire-aspath"
        elif "inheritance_disable" in conf:
            command = "remove-private-AS inheritance-disable"
    return command


def _tmpl_default_originate(config_data):
    conf = config_data.get("default_originate", {})
    command = ""
    if conf:
        if "set" in conf:
            command = "default-originate"
        if "inheritance_disable" in conf:
            command = "default-originate inheritance-disable"
        if "route_policy" in conf:
            command = "default-originate route_policy " + conf["route_policy"]
    return command


class Bgp_neighbor_address_familyTemplate(NetworkTemplate):
    def __init__(self, lines=None):
        super(Bgp_neighbor_address_familyTemplate, self).__init__(
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
            "compval": "as_number",
            "result": {"as_number": "{{ as_num }}"},
            "shared": True,
        },
        {
            "name": "address_family",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                (\s+(?P<nbr_address>neighbor\s\S+))
                (?P<address_family>\s+address-family\s(?P<afi>\S+)\s(?P<safi>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "address-family {{ afi}} {{safi}}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "neighbor_address": "{{nbr_address.split(" ")[1]}}",
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "afi": "{{ afi}}",
                                        "safi": "{{safi}}",
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
            "name": "aigp",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \saigp(?P<aigp>)
                (\sdisable(?P<disable>))?
                (\ssend\smed(?P<send_med>))?
                (\ssend\smed\sdisable(?P<send_disable>))?
                (\ssend\scost-community\sdisable(?P<cc_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_aigp,
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "aigp": {
                                            "set": "{{ True if aigp is defined }}",
                                            "disable": "{{ True if disable is defined}}",
                                            "send_med": {
                                                "set": "{{ True if send_med is defined }}",
                                                "disable": "{{ True if send_disable is defined}}",
                                            },
                                            "send_cost_community_disable": "{{True if cc_disable is defined}}",
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
            "name": "allowas_in",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \sallowas-in(?P<allowas_in>)(\s(?P<value>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "allowas-in {{allowas_in.value if allowas_in.value is defined }}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "allowas_in": {
                                            "set": "{{True if allowas_in is defined and value is not defined}}",
                                            "value": "{{value }}",
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
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \sas-override(?P<as_override>)
                (\sinheritance-disable(?P<inheritance_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "as-override{{' inheritance-disable' if as_override.inheritance_disable is defined else ''}}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "as_override": {
                                            "set": "{{True if as_override is defined "
                                                   "and inheritance_disable is not defined}}",
                                            "inheritance_disable": "{{True if inheritance_disable is defined}}",
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
            "name": "bestpath_origin_as_allow_invalid",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \sbestpath\sorigin-as\sallow\sinvalid(?P<invalid>)
                $""", re.VERBOSE,
            ),
            "setval": "bestpath origin-as allow invalid",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "bestpath_origin_as_allow_invalid": "{{ True if invalid is defined}}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "capability_orf_prefix",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \scapability\sorf\sprefix\s(?P<capability_orf_prefix>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "capability orf prefix {{capability_orf_prefix }}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "capability_orf_prefix": "{{capability_orf_prefix}}",
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
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \sdefault-originate(?P<default_originate>)
                (\sroute-policy\s(?P<route_policy>\S+))?
                (\sinheritance-disable(?P<inheritance_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_default_originate,
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi}}': {
                                        "default_originate": {
                                            "set": "{{True if default_originate is defined}}",
                                            "route_policy": "{{route_policy}}",
                                            "inheritance_disable": "{{True if inheritance_disable is defined}}",
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
            "name": "long_lived_graceful_restart_capable",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \s+long-lived-graceful-restart
                \s(?P<capable>capable)
                $""", re.VERBOSE,
            ),
            "setval": "long-lived-graceful-restart capable",
            "compval": "long_lived_graceful_restart.capable",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "long_lived_graceful_restart": {
                                            "capable": "{{True if capable is defined}}",
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
            "name": "long_lived_graceful_restart_stale_time",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \s+long-lived-graceful-restart
                \s+stale-time\ssend\s(?P<stale_time_send>\d+)\saccept\s(?P<accept>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "long-lived-graceful-restart stale-time send "
                      "{{stale_time.send}} accept {{stale_time.accept}}",
            "compval": "long_lived_graceful_restart.stale_time",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "long_lived_graceful_restart": {
                                            "stale_time": {
                                                "send": "{{stale_time_send}}",
                                                "accept": "{{accept}}",
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
            "name": "maximum_prefix",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \s+maximum-prefix
                (\s(?P<maximum_prefix>\d+))?
                (\s(?P<threshold_value>\d+))?
                (\srestart\s(?P<restart>\d+))?
                (\swarning-only\s(?P<warning_only>))?
                (\sdiscard-extra-paths\s(?P<discard_extra_paths>))?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_maximum_prefix,
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "maximum_prefix": {
                                            "max_limit": "{{maximum_prefix}}",
                                            "threshold_value": "{{threshold_value}}",
                                            "restart": "{{restart}}",
                                            "warning_only": "{{ True if warning_only is defined}}",
                                            "discard_extra_paths": "{{ True if discard_extra_paths is defined}}",
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
            "name": "multipath",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \smultipath(?P<multipath>)
                $""", re.VERBOSE,
            ),
            "setval": "multipath",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "multipath": "{{True if multipath is defined}}",
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
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \snext-hop-self(?P<next_hop_self>)
                (\sinheritance-disable(?P<inheritance_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "next-hop-self{{' inheritance-disable' if next_hop_self.inheritance_disable is defined else ''}}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "next_hop_self": {
                                            "set": "{{True if next_hop_self is defined and"
                                                   " inheritance_disable is not defined}}",
                                            "inheritance_disable": "{{True if inheritance_disable is defined}}",
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
            "name": "next_hop_unchanged",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \snext-hop-unchanged(?P<next_hop_unchanged>)
                (\sinheritance-disable(?P<inheritance_disable>))?
                (\smultipath(?P<multipath>))?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_next_hop_unchanged,
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi}}': {
                                        "next_hop_unchanged": {
                                            "set": "{{True if next_hop_self is defined }}",
                                            "inheritance_disable": "{{True if inheritance_disable is defined}}",
                                            "multipath": "{{True if multipath is defined}}",
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
            "name": "optimal_route_reflection_group_name",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \soptimal-route-reflection\s(?P<group_name>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "optimal-route-reflection {{optimal_route_reflection_group_name}}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "optimal_route_reflection_group_name": "{{ group_name}}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "orf_route_policy",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \sorf\sroute-policy\s(?P<orf_rr>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "orf route-policy {{orf_route_policy}}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "orf_route_policy": "{{orf_rr}}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "origin_as",
            "getval": re.compile(
                r"""
                \s+(?P<nbr_address>neighbor\s\S+)
                \sorigin-as\svalidation\sdisable(?P<origin_as>)
                $""", re.VERBOSE,
            ),
            "setval": "origin-as validation disable",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "origin_as": {
                                            "validation": {
                                                "disable": "{{True if origin_as is defined }}",
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
            "name": "route_policy.inbound",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \sroute-policy\s(?P<route_policy>\S+)
                \sin
                $""", re.VERBOSE,
            ),
            "setval": "route-policy {{route_policy.inbound}} in",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "route_policy": {
                                            "inbound": "{{route_policy}}",
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
            "name": "route_policy.outbound",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \sroute-policy\s(?P<route_policy>\S+)
                \sout
                $""", re.VERBOSE,
            ),
            "setval": "route-policy {{route_policy.outbound}} out",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "route_policy": {
                                            "outbound": "{{route_policy}}",
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
            "name": "remove_private_AS",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \sremove-private-AS(?P<remove_private_AS>)
                (\sinbound(?P<inbound>))?
                (\sentire-aspath(?P<entire_aspath>))?
                (\sinheritance-disable(?P<inheritance_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_remove_private_AS,
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "remove_private_AS": {
                                            "set": "{{True if remove_private_AS is defined}}",
                                            "inbound": "{{True if inbound is defined}}",
                                            "entire_aspath": "{{True if entire_aspath is defined}}",
                                            "inheritance_disable": "{{True if inheritance_disable is defined}}",
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
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \sroute-reflector-client(?P<route_reflector_client>)
                (\sinheritance-disable(?P<inheritance_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "route-reflector-client{{' inheritance-disable' "
                      "if route_reflector_client.inheritance_disable is defined }}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "route_reflector_client": {
                                            "set": "{{True if route_reflector_client is defined and "
                                                   "inheritance_disable is not defined }}",
                                            "inheritance_disable": "{{True if inheritance_disable is defined}}",
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
            "name": "send_community_ebgp",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \ssend-community-ebgp(?P<send_community_ebgp>)
                (\sinheritance-disable(?P<inheritance_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "send-community-ebgp{{' inheritance-disable' "
                      "if send_community_ebgp.inheritance_disable is defined else ''}}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "send_community_ebgp": {
                                            "set": "{{True if send_community_ebgp is defined and "
                                                   "inheritance_disable is not defined}}",
                                            "inheritance_disable": "{{True if inheritance_disable is defined}}",
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
            "name": "send_community_gshut_ebgp",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \ssend-community-gshut-ebgp(?P<send_community_gshut_ebg>)
                (\sinheritance-disable(?P<inheritance_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "send-community-gshut-ebgp{{' inheritance-disable' "
                      "if send_community_gshut_ebgp.inheritance_disable is defined else ''}}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "send_community_gshut_ebgp": {
                                            "set": "{{True if send_community_gshut_ebg is defined and "
                                                   "inheritance_disable is not defined}}",
                                            "inheritance_disable": "{{True if inheritance_disable is defined}}",
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
            "name": "send_extended_community_ebgp",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \ssend-extended-community-ebgp(?P<send_extended_community_ebgp>)
                (\sinheritance-disable(?P<inheritance_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "send-extended-community-ebgp{{' inheritance-disable' "
                      "if send_extended_community_ebgp.inheritance_disable is defined else ''}}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "send_extended_community_ebgp": {
                                            "set": "{{True if send_extended_community_ebgp is defined and "
                                            "inheritance_disable is not defined}}",
                                            "inheritance_disable": "{{True if inheritance_disable is defined}}",
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
            "name": "send_multicast_attributes",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \s+(?P<send_multicast_attributes>send-multicast-attributes)
                (\sdisable(?P<disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "send-multicast-attributes{{' disable' "
                      "if send_multicast_attributes.disable is defined else ''}}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "send_multicast_attributes": {
                                            "set": "{{True if send_multicast_attributes is "
                                                   "defined and disable is not defined}}",
                                            "disable": "{{True if disable is defined}}",
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
            "name": "soft_reconfiguration",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \ssoft-reconfiguration
                \sinbound(?P<inbound>)
                (\salways(?P<always>))?
                (\sinheritance-disable(?P<inheritance_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_soft_reconfiguration,
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "soft_reconfiguration": {
                                            "inbound": {
                                                "set": "{{True if inbound is defined and "
                                                       "inheritance_disable is not defined and "
                                                       "always is not defined}}",
                                                "always": "{{True if always is defined }}",
                                                "inheritance_disable": "{{True if inheritance_disable is defined}}",
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
            "name": "weight",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \sweight\s(?P<weight>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "weight {{weight}}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "weight": "{{weight}}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "validation",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \svalidation(?P<validation>)
                (\sredirect(?P<redirect>))?
                 (\sdisable(?P<disable>))?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_validation,
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "validation": {
                                            "set": "{{True if validation is defined}}",
                                            "redirect": "{{True if redirect is defined }}",
                                            "disable": "{{ True if disable is defined}}",
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
            "name": "site_of_origin",
            "getval": re.compile(
                r"""
                (\s+vrf\s(?P<vrf>\S+))?
                \s+(?P<nbr_address>neighbor\s\S+)
                \ssite-of-origin\s(?P<site_of_origin>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "site-of-origin {{site_of_origin}}",
            "result": {
                "vrfs": {
                    "{{ 'vrf_' + vrf|d() }}": {
                        "vrf": "{{ vrf }}",
                        "neighbors": {
                            "{{nbr_address.split(" ")[1]}}": {
                                "address_family": {
                                    '{{"address_family_" + afi + "_" + safi }}': {
                                        "site_of_origin": "{{site_of_origin}}",
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
