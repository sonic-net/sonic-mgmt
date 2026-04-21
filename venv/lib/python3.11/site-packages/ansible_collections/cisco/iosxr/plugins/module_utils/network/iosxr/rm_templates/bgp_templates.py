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


UNIQUE_NEIB_ADD = "{{ nbr_address }}"


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
        command = "remove-private-AS"
        if "inbound" in conf:
            command += " inbound"
        if "entire_aspath" in conf:
            command += " entire-aspath"
        if "inheritance_disable" in conf:
            command += " inheritance-disable"
    return command


def _templ_local_as(config_data):
    conf = config_data.get("local_as", {})
    if conf.get("value"):
        command = "local-as " + str(conf.get("value", {}))
    if "no_prepend" in conf:
        command = "local-as"
        if "replace_as" in conf.get("no_prepend", {}):
            if "dual_as" in conf.get("no_prepend", {}).get("replace_as", {}):
                command += " no-prepend replace-as dual-as"
            elif "set" in conf.get("no_prepend", {}).get("replace_as", {}):
                command += " no-prepend replace-as"
        elif "set" in conf.get("no_prepend", {}):
            command += " no-prepend"
    return command


class Bgp_templatesTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(Bgp_templatesTemplate, self).__init__(
            lines=lines,
            tmplt=self,
            module=module,
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
                \s+neighbor-group\s(?P<nbr_address>\S+)
                (?P<address_family>\s+address-family\s(?P<afi>\S+)\s(?P<safi>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "address-family {{ afi}} {{safi}}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi }}': {
                                "afi": "{{ afi}}",
                                "safi": "{{safi}}",
                            },
                        },
                    },
                },
            },
            "shared": True,
        },
        {
            "name": "neighbor_group",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "neighbor-group {{ name}}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "name": UNIQUE_NEIB_ADD,
                    },
                },
            },
            "shared": True,
        },
        {
            "name": "signalling",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \sSignalling(?P<signalling>)
                (\sbgp\sdisable(?P<b_disable>))?
                (\sldp\sdisable(?P<l_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "{{ 'signalling bgp disable' if signalling.bgp_disable else 'signalling ldp disable' }} ",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi }}': {
                                "signalling": {
                                    "bgp_disable": "{{ True if b_disable is defined }}",
                                    "ldp_disable": "{{ True if l_disable is defined}}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "advertise.local_labeled_route.set",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                (?P<a_Set>\sadvertise\slocal-labeled-route(?P<a_set>))
                $""", re.VERBOSE,
            ),
            "setval": "advertise local-labeled-route",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi }}': {
                                "advertise": {
                                    "local_labeled_route": {
                                        "set": "{{ True if a_set is defined}}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "advertise.local_labeled_route.disable",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \sadvertise
                (\slocal-labeled-route\sdisable(?P<l_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "advertise local-labeled-route disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi }}': {
                                "advertise": {
                                    "local_labeled_route": {
                                        "disable": "{{ True if l_disable is defined}}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "advertise.permanent_network",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \sadvertise
                (\spermanent-network(?P<set>))?
                $""", re.VERBOSE,
            ),
            "setval": "advertise permanent-network",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi }}': {
                                "advertise": {
                                    "permanent_network": "{{ True if set is defined}}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "aigp.set",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                (?P<aigp>\saigp)
                $""", re.VERBOSE,
            ),
            "setval": "aigp",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi }}': {
                                "aigp": {
                                    "set": "{{ True if aigp is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "aigp.disable",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \saigp(?P<aigp>)
                (\sdisable(?P<disable>))
                $""", re.VERBOSE,
            ),
            "setval": "aigp disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi }}': {
                                "aigp": {
                                    "disable": "{{ True if disable is defined}}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "aigp.send_med",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \saigp(?P<aigp>)
                (\ssend\smed(?P<send_med>))?
                (\ssend\smed\sdisable(?P<send_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "'aigp send med disable' if {{aigp.send_med.disable}} is defined else 'aigp send med'",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi }}': {
                                "aigp": {
                                    "send_med": {
                                        "set": "{{ True if send_med is defined }}",
                                        "disable": "{{ True if send_disable is defined}}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "aigp.send_cost_community_disable",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \saigp(?P<aigp>)
                (\ssend\scost-community\sdisable(?P<cc_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "aigp send cost-community disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi }}': {
                                "aigp": {
                                    "send_cost_community_disable": "{{True if cc_disable is defined}}",
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
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \sallowas-in(?P<allowas_in>)(\s(?P<value>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "allowas-in {{allowas_in.value if allowas_in.value is defined }}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
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
        {
            "name": "as_override",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \sas-override(?P<as_override>)
                (\sinheritance-disable(?P<inheritance_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "as-override{{' inheritance-disable' if as_override.inheritance_disable is defined else ''}}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
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
        {
            "name": "bestpath_origin_as_allow_invalid",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \sbestpath\sorigin-as\sallow\sinvalid(?P<invalid>)
                $""", re.VERBOSE,
            ),
            "setval": "bestpath origin-as allow invalid",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi }}': {
                                "bestpath_origin_as_allow_invalid": "{{ True if invalid is defined}}",
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
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \scapability\sorf\sprefix\s(?P<capability_orf_prefix>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "capability orf prefix {{capability_orf_prefix }}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi }}': {
                                "capability_orf_prefix": "{{capability_orf_prefix}}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "default_originate.set",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s+default-originate(?P<default_originate>)
                $""", re.VERBOSE,
            ),
            "setval": "default-originate",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi}}': {
                                "default_originate": {
                                    "set": "{{True if default_originate is defined}}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "default_originate.route_policy",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s+default-originate(?P<default_originate>)
                (\sroute-policy\s(?P<route_policy>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "default-originate route-policy {{default_originate.route_policy}}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi}}': {
                                "default_originate": {
                                    "route_policy": "{{route_policy}}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "default_originate.inheritance_disable",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s+default-originate\s(?P<disable>inheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "default-originate inheritance-disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi}}': {
                                "default_originate": {
                                    "inheritance_disable": "{{true if disable is defined}}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "encapsulation_type_srv6",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \sencapsulation-type\ssrv6(?P<encapsulation_type_srv6>)
                $""", re.VERBOSE,
            ),
            "setval": "encapsulation-type srv6",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi }}': {
                                "encapsulation_type_srv6": "{{true if encapsulation_type_srv6 is defined}}",
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
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s+long-lived-graceful-restart
                \s(?P<capable>capable)
                $""", re.VERBOSE,
            ),
            "setval": "long-lived-graceful-restart capable",
            "compval": "long_lived_graceful_restart.capable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
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
        {
            "name": "long_lived_graceful_restart_stale_time",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s+long-lived-graceful-restart
                \s+stale-time\ssend\s(?P<stale_time_send>\d+)\saccept\s(?P<accept>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "long-lived-graceful-restart stale-time send "
                      "{{stale_time.send}} accept {{stale_time.accept}}",
            "compval": "long_lived_graceful_restart.stale_time",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
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
        {
            "name": "maximum_prefix",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
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
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
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

        {
            "name": "multipath",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \smultipath(?P<multipath>)
                $""", re.VERBOSE,
            ),
            "setval": "multipath",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi }}': {
                                "multipath": "{{True if multipath is defined}}",
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
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \snext-hop-self(?P<next_hop_self>)
                (\sinheritance-disable(?P<inheritance_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "next-hop-self{{' inheritance-disable' if next_hop_self.inheritance_disable is defined else ''}}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
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
        {
            "name": "next_hop_unchanged.set",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \snext-hop-unchanged(?P<next_hop_unchanged>)
                $""", re.VERBOSE,
            ),
            "setval": "next-hop-unchanged",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi}}': {
                                "next_hop_unchanged": {
                                    "set": "{{True if next_hop_self is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "next_hop_unchanged.inheritance_disable",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \snext-hop-unchanged(?P<next_hop_unchanged>)
                ((?P<inheritance_disable>)\sinheritance-disable)?
                $""", re.VERBOSE,
            ),
            "setval": "next-hop-unchanged inheritance-disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi}}': {
                                "next_hop_unchanged": {
                                    "inheritance_disable": "{{True if inheritance_disable is defined}}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "next_hop_unchanged.multipath",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \snext-hop-unchanged(?P<next_hop_unchanged>)
                (?P<multipath>\smultipath)?
                $""", re.VERBOSE,
            ),
            "setval": "next-hop-unchanged multipath",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi}}': {
                                "next_hop_unchanged": {
                                    "multipath": "{{True if multipath is defined}}",
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
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \soptimal-route-reflection\s(?P<group_name>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "optimal-route-reflection {{optimal_route_reflection_group_name}}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi }}': {
                                "optimal_route_reflection_group_name": "{{ group_name}}",
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
                \s+(?P<nbr_address>neighbor\s\S+)
                \sorf\sroute-policy\s(?P<orf_rr>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "orf route-policy {{orf_route_policy}}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi }}': {
                                "orf_route_policy": "{{orf_rr}}",
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
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \sorigin-as\svalidation\sdisable(?P<origin_as>)
                $""", re.VERBOSE,
            ),
            "setval": "origin-as validation disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
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
        {
            "name": "remove_private_AS.set",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \sremove-private-AS(?P<remove_private_AS>)
                $""", re.VERBOSE,
            ),
            "setval": "remove-private-AS",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi }}': {
                                "remove_private_AS": {
                                    "set": "{{True if remove_private_AS is defined}}",
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
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \sremove-private-AS(?P<remove_private_AS>)
                (\sinbound(?P<inbound>))?
                (\sentire-aspath(?P<entire_aspath>))?
                (\sinheritance-disable(?P<inheritance_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_remove_private_AS,
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi }}': {
                                "remove_private_AS": {
                                    "inheritance_disable": "{{True if inheritance_disable is defined}}",
                                    "inbound": "{{True if inbound is defined}}",
                                    "entire_aspath": "{{True if entire_aspath is defined}}",
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
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \sroute-policy\s(?P<route_policy>\S+)
                \sin
                $""", re.VERBOSE,
            ),
            "setval": "route-policy {{route_policy.inbound}} in",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
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
        {
            "name": "route_policy.outbound",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \sroute-policy\s(?P<route_policy>\S+)
                \sout
                $""", re.VERBOSE,
            ),
            "setval": "route-policy {{route_policy.outbound}} out",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
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
        {
            "name": "route_reflector_client",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \sroute-reflector-client(?P<route_reflector_client>)
                (\sinheritance-disable(?P<inheritance_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "route-reflector-client{{' inheritance-disable' "
                      "if route_reflector_client.inheritance_disable is defined }}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
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
        {
            "name": "send_community_ebgp",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \ssend-community-ebgp(?P<send_community_ebgp>)
                (\sinheritance-disable(?P<inheritance_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "send-community-ebgp{{' inheritance-disable' "
                      "if send_community_ebgp.inheritance_disable is defined else ''}}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
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
        {
            "name": "send_community_gshut_ebgp",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \ssend-community-gshut-ebgp(?P<send_community_gshut_ebg>)
                (\sinheritance-disable(?P<inheritance_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "send-community-gshut-ebgp{{' inheritance-disable' "
                      "if send_community_gshut_ebgp.inheritance_disable is defined else ''}}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
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
        {
            "name": "send_extended_community_ebgp",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \ssend-extended-community-ebgp(?P<send_extended_community_ebgp>)
                (\sinheritance-disable(?P<inheritance_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "send-extended-community-ebgp{{' inheritance-disable' "
                      "if send_extended_community_ebgp.inheritance_disable is defined else ''}}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
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
        {
            "name": "send_multicast_attributes",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s+(?P<send_multicast_attributes>send-multicast-attributes)
                (\sdisable(?P<disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "send-multicast-attributes{{' disable' "
                      "if send_multicast_attributes.disable is defined else ''}}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
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
        {
            "name": "soft_reconfiguration",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \ssoft-reconfiguration
                \sinbound(?P<inbound>)
                (\salways(?P<always>))?
                (\sinheritance-disable(?P<inheritance_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": _tmpl_soft_reconfiguration,
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
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
        {
            "name": "weight",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \sweight\s(?P<weight>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "weight {{weight}}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi }}': {
                                "weight": "{{weight}}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "use",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \suse\s(?P<af_use>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "weight {{weight}}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi }}': {
                                "use": "{{af_use}}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "update.out_originator_loopcheck_set",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \supdate\sout\soriginator-loopcheck(?P<set>)
                $""", re.VERBOSE,
            ),
            "setval": "update out originator-loopcheck",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi }}': {
                                "update": {
                                    "out_originator_loopcheck_set": "{{True if set is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "update.out_originator_loopcheck_disable",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \supdate\sout\soriginator-loopcheck(?P<set>)
                (\sdisable(?P<disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "update out originator-loopcheck disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "address_family": {
                            '{{"address_family_" + afi + "_" + safi }}': {
                                "update": {
                                    "out_originator_loopcheck_disable": "{{True if disable is defined}}",
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
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<advertise_in>advertisement-interval\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "advertisement-interval {{ advertisement_interval }}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "advertisement_interval": "{{ advertise_in.split(" ")[1] }}",
                    },
                },
            },
        },
        {
            "name": "bfd_fast_detect_disable",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \sbfd
                \sfast-detect
                \s(?P<disable>disable)
                $""", re.VERBOSE,
            ),
            "setval": "bfd fast-detect disable",
            "compval": "bfd.fast_detect.disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "bfd": {
                            "fast_detect": {"disable": "{{ True if disable is defined }}"},
                        },
                    },
                },
            },
        },
        {
            "name": "bfd_fast_detect_set",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \sbfd
                \s(?P<fast_detect>fast-detect)
                $""", re.VERBOSE,
            ),
            "setval": "bfd fast-detect",
            "compval": "bfd.fast_detect.set",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "bfd": {
                            "fast_detect": {"set": "{{ True if fast_detect is defined }}"},
                        },
                    },
                },
            },
        },
        {
            "name": "bfd_fast_detect_strict_mode",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \sbfd
                \sfast-detect
                \s(?P<strict_mode>strict-mode)
                $""", re.VERBOSE,
            ),
            "setval": "bfd fast-detect strict-mode",
            "compval": "bfd.fast_detect.strict_mode",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "bfd": {
                            "fast_detect": {"strict_mode": "{{ True if strict_mode is defined }}"},
                        },
                    },
                },
            },
        },
        {
            "name": "bfd_nbr_multiplier",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \sbfd
                \s(?P<multiplier>multiplier\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "bfd multiplier {{ bfd.multiplier}}",
            "compval": "bfd.multiplier",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD:
                    {
                        "bfd": {
                            "multiplier": "{{multiplier.split(" ")[1]}}",
                        },
                    },
                },
            },
        },
        {
            "name": "bfd_nbr_minimum_interval",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \sbfd
                \s(?P<min_interval>minimum-interval\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "bfd minimum-interval {{ bfd.minimum_interval}}",
            "compval": "bfd.minimum_interval",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "bfd": {
                            "minimum_interval": "{{min_interval.split(" ")[1]}}",
                        },
                    },
                },
            },
        },
        {
            "name": "bmp_activate",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \sbmp-activate
                \s(?P<bmp_activate>server\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "bmp-activate server {{bmp_activate.server}}",
            "compval": "bmp_activate.serevr",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "bmp_activate": {"server": "{{ bmp_activate.split(" ")[1] }}"},
                    },
                },
            },
        },
        {
            "name": "neighbor_cluster_id",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<cluster_id>cluster-id\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "cluster-id {{ cluster_id }}",
            "compval": "cluster_id",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {"cluster_id": "{{ cluster_id.split(" ")[1] }}"},
                },
            },
        },
        {
            "name": "neighbor_description",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \sdescription\s(?P<description>.+)
                $""", re.VERBOSE,
            ),
            "setval": "description {{ description }}",
            "compval": "description",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {"description": "{{ description }}"},
                },
            },
        },
        {
            "name": "dmz_link_bandwidth",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<dmz_link_bandwidth>dmz-link-bandwidth)
                $""", re.VERBOSE,
            ),
            "setval": "dmz-link-bandwidth",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "dmz_link_bandwidth": {
                            "set": "{{ True if dmz_link_bandwidth is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "dmz_link_bandwidth_inheritance_disable",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \sdmz-link-bandwidth
                \s(?P<dmz_link_bandwidth>inheritance_disable)
                $""", re.VERBOSE,
            ),
            "setval": "dmz-link-bandwidth inheritance-disable",
            "compval": "dmz_link_bandwidth.inheritance_disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "dmz_link_bandwidth": {
                            "inheritance_disable": "{{ True if dmz_link_bandwidth is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "dscp",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<dscp>dscp\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "dscp {{ dscp }}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "dscp": "{{ dscp.split(" ")[1] }}",
                    },
                },
            },
        },
        {
            "name": "ebgp_multihop_value",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<ebgp_multihop>ebgp-multihop\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "ebgp-multihop {{ ebgp_multihop.value}}",
            "compval": "ebgp_multihop.value",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "ebgp_multihop": {
                            "value": "{{ ebgp_multihop.split(" ")[1] }}",
                        },
                    },
                },
            },
        },
        {
            "name": "ebgp_multihop_mpls",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<ebgp_multihop>ebgp-multihop\s\S*\smpls)
                $""", re.VERBOSE,
            ),
            "setval": "ebgp-multihop mpls",
            "compval": "ebgp_multihop.mpls",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "ebgp_multihop": {"mpls": "{{ True if ebgp_multihop is defined }}"},
                    },
                },
            },
        },
        {
            "name": "ebgp_recv_extcommunity_dmz_set",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<ebgp_recv_extcommunity_dmz>ebgp-recv-extcommunity-dmz)
                $""", re.VERBOSE,
            ),
            "setval": "ebgp-recv-extcommunity-dmz inheritance-disable",
            "compval": "ebgp_recv_extcommunity_dm.set",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "ebgp_recv_extcommunity_dmz": {
                            "set": "{{ True if ebgp_recv_extcommunity_dmz is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "ebgp_recv_extcommunity_dmz",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<ebgp_recv_extcommunity_dmz>ebgp-recv-extcommunity-dmz\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "ebgp-recv-extcommunity-dmz inheritance-disable ",
            "compval": "ebgp_recv_extcommunity_dmz.inheritance_disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "ebgp_recv_extcommunity_dmz": {
                            "inheritance_disable": "{{ True if ebgp_recv_extcommunity_dmz is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "ebgp_send_extcommunity_dmz",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<ebgp_send_extcommunity_dmz>ebgp-send-extcommunity-dmz\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "ebgp-send-extcommunity-dmz inheritance-disable ",
            "compval": "ebgp_send_extcommunity_dmz.inheritance_disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "ebgp_send_extcommunity_dmz": {
                            "inheritance_disable": "{{ True if ebgp_send_extcommunity_dmz is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "ebgp_send_extcommunity_dmz_set",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<ebgp_send_extcommunity_dmz>ebgp-send-extcommunity-dmz)
                $""", re.VERBOSE,
            ),
            "setval": "ebgp-send-extcommunity-dmz",
            "compval": "ebgp_send_extcommunity_dmz.set",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "ebgp_send_extcommunity_dmz": {
                            "set": "{{ True if ebgp_send_extcommunity_dmz is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "ebgp_send_extcommunity_dmz_cumulatie",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<ebgp_send_extcommunity_dmz>ebgp-send-extcommunity-dmz\scumulatie)
                $""", re.VERBOSE,
            ),
            "setval": "ebgp-send-extcommunity-dmz cumulatie ",
            "compval": "ebgp_send_extcommunity_dmz.cumulatie",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "ebgp_send_extcommunity_dmz": {
                            "cumulatie": "{{ True if ebgp_send_extcommunity_dmz is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "egress_engineering",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<egress_engineering>egress-engineering\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "egress-engineering inheritance-disable ",
            "compval": "egress_engineering.inheritance_disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "egress_engineering": {
                            "inheritance_disable": "{{ True if egress_engineering is defined }}",
                        },
                    },
                },
            },

        },
        {
            "name": "egress_engineering_set",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<egress_engineering>egress-engineering)
                $""", re.VERBOSE,
            ),
            "setval": "egress-engineering",
            "compval": "egress_engineering.set",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "egress_engineering": {
                            "set": "{{ True if egress_engineering is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_enforce_first_as_disable",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<enforce_first_as_disable>enforce-first-as\sdisable)
                $""", re.VERBOSE,
            ),
            "setval": "enforce-first-as disable",
            "compval": "enforce_first_as.disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "enforce_first_as": {
                            "disable": "{{ True if enforce_first_as_disable is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_graceful_restart_restart_time",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<graceful_restart_restart_time>graceful-restart\srestart-time\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-restart restart-time {{ graceful_restart.restart_time}}",
            "compval": "graceful_restart.restart_time",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "graceful_restart": {
                            "restart_time": "{{ graceful_restart_restart_time.split(" ")[2] }}",
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_graceful_restart_stalepath_time",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<graceful_restart_stalepath_time>graceful-restart\sstalepath-time\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-restart stalepath-time {{ graceful_restart.stalepath_time}}",
            "compval": "graceful_restart.stalepath_time",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "graceful_restart": {
                            "stalepath_time": "{{ graceful_restart_stalepath_time.split(" ")[2] }}",
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_graceful_maintenance_set",
            "getval": re.compile(
                r"""
               \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<graceful_maintenance>graceful-maintenance)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-maintenance",
            "compval": "graceful_maintenance.set",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "graceful_maintenance": {
                            "set": "{{ True if graceful_maintenance is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_graceful_maintenance_activate",
            "getval": re.compile(
                r"""
               \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<graceful_maintenance>graceful-maintenance\sactivate)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-maintenance activate",
            "compval": "graceful_maintenance.activate.set",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "graceful_maintenance": {
                            "activate": {"set": "{{ True if graceful_maintenance is defined }}"},
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_graceful_maintenance_activate_inheritance_disable",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<graceful_maintenance>activate\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-maintenance activate inheritance-disable",
            "compval": "graceful_maintenance.activate.inheritance_disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "graceful_maintenance": {
                            "activate": {
                                "inheritance_disable": "{{ True if graceful_maintenance is defined }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_graceful_maintenance_as_prepends",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<as_prepends>as-prepends\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-maintenance as-prepends inheritance-disable",
            "compval": "graceful_maintenance.as_prepends.inheritance_disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "graceful_maintenance": {
                            "as_prepends": {
                                "inheritance_disable": "{{ True if as_prepends is defined }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_graceful_maintenance_local_preference_disable",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<local_preference>local-preference\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-maintenance local-preference inheritance-disable",
            "compval": "graceful_maintenance.local_preference.inheritance_disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "graceful_maintenance": {
                            "local_preference": {
                                "inheritance_disable": "{{ True if local_preference is defined }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_graceful_maintenance_local_preference",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<local_preference>local-preference\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-maintenance local-preference {{ graceful_maintenance.local_preference.value}}",
            "compval": "graceful_maintenance.local_preference.value",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "graceful_maintenance": {
                            "local_preference": {
                                "value": "{{ local_preference.split(" ")[1]}}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_graceful_maintenance_as_prepends_value",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<as_prepends>as-prepends\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "graceful-maintenance as-prepends {{ graceful_maintenance.as_prepends.value }}",
            "compval": "graceful_maintenance.as_prepends.value",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "graceful_maintenance": {
                            "as_prepends": {
                                "value": "{{ as_prepends.split(" ")[1]}}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "ignore_connected_check_set",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<ignore_connected_check>ignore-connected-check)
                $""", re.VERBOSE,
            ),
            "setval": "ignore-connected-check",
            "compval": "ignore_connected_check.set",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "ignore_connected_check": {
                            "set": "{{ True if ignore_connected_check is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "ignore_connected_check",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<ignore_connected_check>ignore-connected-check\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "ignore-connected-check inheritance-disable ",
            "compval": "ignore_connected_check.inheritance_disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "ignore_connected_check": {
                            "inheritance_disable": "{{ True if ignore_connected_check is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "idle_watch_time",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \sidle-watch-time(?P<idle_watch_time>\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "idle-watch-time {{idle_watch_time}} ",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "idle_watch_time": "{{idle_watch_time}}",
                    },
                },
            },
        },
        {
            "name": "internal_vpn_client",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                (?P<internal_vpn_client>\sinternal-vpn-client)
                $""", re.VERBOSE,
            ),
            "setval": "internal-vpn-client",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "internal_vpn_client": "{{true if internal_vpn_client is defined}}",
                    },
                },
            },
        },
        {
            "name": "keychain",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<keychain>keychain\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "keychain inheritance-disable ",
            "compval": "keychain.inheritance_disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "keychain": {
                            "inheritance_disable": "{{ True if keychain is defined }}",
                        },
                    },
                },
            },

        },
        {
            "name": "keychain_name",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<keychain>keychain\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "keychain {{ keychain.name }}",
            "compval": "keychain.name",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "keychain": {
                            "name": "{{ keychain.split(" ")[1] }}",
                        },
                    },
                },
            },
        },
        {
            "name": "local_address",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \slocal
                \s(?P<local>address\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "local address inheritance-disable",
            "compval": "local.address.inheritance_disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "local": {
                            "address": {
                                "inheritance_disable": "{{ True if local is defined }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "local",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \slocal
                \s(?P<local>address\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "local address {{ local.address.ipv4_address }}",
            "compval": "local.address.ipv4_address",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "local": {
                            "address": {
                                "ipv4_address": "{{ local.split(" ")[1] }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "local_as_inheritance_disable",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<local_as>local-as\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "local-as inheritance-disable",
            "compval": "local_as.inheritance_disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "local_as": {
                            "inheritance_disable": "{{ True if local_as is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "local_as",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<local_as>local-as\s\S+)
                (\s(?P<no_prepend>no-prepend))?
                (\s(?P<replace_as>replace-as))?
                (\s(?P<dual_as>dual-as))?
                $""", re.VERBOSE,
            ),
            "setval": _templ_local_as,
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "local_as": {
                            "value": "{{ local_as.split(" ")[1] }}",
                            "no_prepend": {
                                "set": "{{ True if no_prepend is defined and replace_as is undefined and dual_as is undefined else None}}",
                                "replace_as": {
                                    "set": "{{ True if replace_as is defined and dual_as is undefined}}",
                                    "dual_as": "{{ not not dual_as}}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "local_address_subnet",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \slocal-address-subnet(?P<local>\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "local-address-subnet {{local_address_subnet}}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "local_address_subnet": "{{local.split(" ")[1]}}",
                    },
                },
            },
        },
        {
            "name": "neighbor_log_message_in_value",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \slog
                \smessage
                \s(?P<value>in\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "log message in {{ log.message.in.value}}",
            "compval": "log.log_message.in.value",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "log": {
                            "log_message": {
                                "in": {
                                    "value": "{{ value.split(" ")[1] }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_log_message_in_disable",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \slog
                \smessage
                \s(?P<disable>in\sdisable)
                $""", re.VERBOSE,
            ),
            "setval": "log message in disable",
            "compval": "log.log_message.in.disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "log": {
                            "log_message": {
                                "in": {
                                    "disable": "{{ True if disable is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_log_message_in_inheritance_disable",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \slog
                \smessage
                \s(?P<disable>in\sinheritance-diable)
                $""", re.VERBOSE,
            ),
            "setval": "log message in inheritance-diable",
            "compval": "log.log_message.in.inheritance_disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "log": {
                            "log_message": {
                                "in": {
                                    "inheritance_disable": "{{ True if disable is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_log_message_out_value",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \slog
                \smessage
                \s(?P<value>out\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "log message out {{ log.message.out.value}}",
            "compval": "log.log_message.out.value",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "log": {
                            "log_message": {
                                "out": {
                                    "value": "{{ value.split(" ")[1] }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_log_message_out_disable",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \slog
                \smessage
                \s(?P<disable>out\sdisable)
                $""", re.VERBOSE,
            ),
            "setval": "log message out disable",
            "compval": "log.log_message.out.disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "log": {
                            "log_message": {
                                "out": {
                                    "disable": "{{ True if disable is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_log_message_out_inheritance_disable",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \slog
                \smessage
                \s(?P<disable>out\sinheritance-diable)
                $""", re.VERBOSE,
            ),
            "setval": "log message out inheritance-diable",
            "compval": "log.log_message.out.inheritance_disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "log": {
                            "log_message": {
                                "out": {
                                    "inheritance_disable": "{{ True if disable is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "maximum_peers",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \smaximum-peers(?P<local>\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "maximum-peers {maximum_peers}}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "maximum_peers": "{{local}}",
                    },
                },
            },

        },
        {
            "name": "password_inheritance_disable",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<password>password\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "password inheritance-disable",
            "compval": "password.inheritance_disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "password": {
                            "inheritance_disable": "{{ True if password is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "password_encrypted",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \spassword\sencrypted
                \s(?P<password>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "password encrypted {{password.encrypted}}",
            "compval": "password.encrypted",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "password": {
                            "encrypted": "{{ password }}",
                        },
                    },
                },
            },
        },
        {
            "name": "peer_set",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \speer-set(?P<local>\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "peer-set {peer_set}}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "peer_set": "{{local}}",
                    },
                },
            },
        },
        {
            "name": "receive_buffer_size",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<receive_buffer_size>receive-buffer-size\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "receive-buffer-size {{ receive_buffer_size }}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "receive_buffer_size": "{{ receive_buffer_size.split(" ")[1] }}",
                    },
                },
            },
        },
        {
            "name": "send_buffer_size",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<send_buffer_size>send-buffer-size\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "send-buffer-size {{ send_buffer_size }}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "send_buffer_size": "{{ send_buffer_size.split(" ")[1] }}",
                    },
                },
            },
        },
        {
            "name": "precedence",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \sprecedence\s(?P<local>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "precedence {{precedence}}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "precedence": "{{local}}",
                    },
                },
            },
        },
        {
            "name": "remote_as",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<remote_as>remote-as\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "remote-as {{ remote_as }}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "remote_as": "{{ remote_as.split(" ")[1] }}",
                    },
                },
            },
        },
        {
            "name": "remote_as_list",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<remote_as>remote-as-list\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "remote-as-list {{ remote_as_list }}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "remote_as_list": "{{ remote_as.split(" ")[1] }}",
                    },
                },
            },
        },
        {
            "name": "session_open_mode",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<session_open_mode>session-open-mode\s(active-only|both|passive-only))
                $""", re.VERBOSE,
            ),
            "setval": "session-open-mode {{ session_open_mode }}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "session_open_mode": "{{ session_open_mode.split(" ")[1] }}",
                    },
                },
            },
        },
        {
            "name": "neighbor_shutdown",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<shutdown>shutdown)
                $""", re.VERBOSE,
            ),
            "setval": "shutdown",
            "compval": "shutdown",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "shutdown": {
                            "set": "{{ True if shutdown is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_shutdown_inheritance_disable",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<shutdown>shutdown\sinheritance_disable)
                $""", re.VERBOSE,
            ),
            "setval": "shutdown inheritance-disable",
            "compval": "shutdown.inheritance_disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "shutdown": {"inheritance_disable": "{{ True if shutdown is defined }}"},
                    },
                },
            },
        },
        {
            "name": "neighbor_tcp_mss_inheritance_disable",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<tcp_mss_disable>tcp\smss\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "tcp mss inheritance-disable",
            "compval": "tcp.mss.inheritance_disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "tcp": {
                            "mss": {
                                "inheritance_disable": "{{ True if tcp_mss_disable is defined }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_tcp_mss",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<tcp_mss>tcp\smss\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "tcp mss {{ tcp.mss.value }}",
            "compval": "tcp.mss.value",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "tcp": {
                            "mss": {
                                "value": "{{ tcp_mss.split(" ")[2] }}",
                            },
                        },
                    },
                },
            },

        },
        {
            "name": "neighbor_timers_keepalive",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<timers_keepalive_time>timers\s\d+)
                \s(?P<timers_holdtime>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "timers {{ timers.keepalive_time}} {{ timers.holdtime }}",
            "compval": "timers",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "timers": {
                            "keepalive_time": "{{ timers_keepalive_time.split(" ")[1] }}",
                            "holdtime": "{{ timers_holdtime.split(" ")[0] }}",
                        },
                    },
                },
            },
        },
        {
            "name": "use.neighbor_group",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \suse\sneighbor-group\s(?P<neighbor_group>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "use neighbor-group {{ use.neighbor_group }}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "use": {
                            "neighbor_group": "{{ neighbor_group }}",
                        },
                    },
                },
            },

        },
        {
            "name": "use.session_group",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \suse\ssession-group\s(?P<session_group>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "use session-group {{ use.session_group }}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "use": {
                            "session_group": "{{ session_group }}",
                        },
                    },
                },
            },
        },
        {
            "name": "update_source",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \supdate-source
                \s(?P<update_source>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "update-source {{ update_source}}",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "update_source": "{{ update_source}}",
                    },
                },
            },
        },
        {
            "name": "neighbor_ttl_security_inheritance_disable",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<ttl_security>ttl-security\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "ttl-security inheritance-disable",
            "compval": "ttl_security.inheritance_disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "ttl_security": {
                            "inheritance_disable": "{{ True if ttl_security is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_ttl_security",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<ttl_security>ttl-security)
                $""", re.VERBOSE,
            ),
            "setval": "ttl-security",
            "compval": "ttl_security.set",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "ttl_security": {
                            "set": "{{ True if ttl_security is defined }}",
                        },
                    },
                },
            },

        },
        {
            "name": "neighbor_update_in_filtering_attribute_filter_group",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<attribute_filter_group>attribute-filter\sgroup\s\S+)
                $""", re.VERBOSE,
            ),
            "setval": "update in filtering attribute-filter group {{ update.in.filtering.attribute_filter.group }}",
            "compval": "update.in.filtering.attribute_filter.group",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "update": {
                            "in": {
                                "filtering": {
                                    "attribute_filter": {
                                        "group": "{{ attribute_filter_group.split(" ")[2] }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_update_in_filtering_logging_disable",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<logging_disable>logging\sdisable)
                $""", re.VERBOSE,
            ),
            "setval": "update in filtering logging disable",
            "compval": "update.in.filtering.logging.disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "update": {
                            "in": {
                                "filtering": {
                                    "logging": {
                                        "disable": "{{True if logging_disable is defined }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },

        },
        {
            "name": "neighbor_update_in_filtering_message_buffers",
            "getval": re.compile(
                r"""
                 \s+neighbor-group\s(?P<nbr_address>\S+)
                \s(?P<message_buffers>message\sbuffers\s\d+)
                $""", re.VERBOSE,
            ),
            "setval": "update in filtering message buffers {{ update.in.filtering.message.buffers}}",
            "compval": "update.in.filtering.update_message.buffers",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "update": {
                            "in": {
                                "filtering": {
                                    "update_message": {
                                        "buffers": "{{ message_buffers.split(" ")[2] }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_capability_additional_paths_send",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \scapability
                \sadditional-paths
                \s(?P<additional_paths_send>send)
                $""", re.VERBOSE,
            ),
            "setval": "capability additional-paths send",
            "compval": "capability.additional_paths.send.set",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "capability": {
                            "additional_paths": {
                                "send": {
                                    "set": "{{ True if additional_paths_send is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_capability_additional_paths_send_disable",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \scapability
                \sadditional-paths
                \s(?P<additional_paths_send>send\sdisable)
                $""", re.VERBOSE,
            ),
            "setval": "capability additional-paths send disable",
            "compval": "capability.additional_paths.send.disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "capability": {
                            "additional_paths": {
                                "send": {
                                    "disable": "{{ True if additional_paths_send is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_capability_additional_paths_rcv",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \scapability
                \sadditional-paths
                \s(?P<additional_paths_receive>receive)
                $""", re.VERBOSE,
            ),
            "setval": "capability additional-paths receive",
            "compval": "capability.additional_paths.receive.set",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "capability": {
                            "additional_paths": {
                                "receive": {
                                    "set": "{{ True if additional_paths_receive is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_capability_additional_paths_rcv_disable",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \scapability
                \sadditional-paths
                \s(?P<additional_paths_receive_disable>receive\sdisable)
                $""", re.VERBOSE,
            ),
            "setval": "capability additional-paths receive disable",
            "compval": "capability.additional_paths.receive.disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "capability": {
                            "additional_paths": {
                                "receive": {
                                    "disable": "{{ True if additional_paths_receive_disable is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_capability_suppress_four_byte_AS",
            "getval": re.compile(
                r"""
               \s+neighbor-group\s(?P<nbr_address>\S+)
                \scapability
                \ssuppress
                \s(?P<suppress_4_byte_as>4-byte-as)
                $""", re.VERBOSE,
            ),
            "setval": "capability suppress 4-byte-as",
            "compval": "capability.suppress.four_byte_AS.set",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "capability": {
                            "suppress": {
                                "four_byte_AS": {
                                    "set": "{{ True if suppress_4_byte_as is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_capability_suppress_all",
            "getval": re.compile(
                r"""
                \s+neighbor-group\s(?P<nbr_address>\S+)
                \scapability
                \ssuppress
                \s(?P<all>all)
                $""", re.VERBOSE,
            ),
            "setval": "capability suppress all",
            "compval": "capability.suppress.all.set",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "capability": {
                            "suppress": {
                                "all": {
                                    "set": "{{ True if all is defined }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "neighbor_capability_suppress_all_inheritance_disable",
            "getval": re.compile(
                r"""
               \s+neighbor-group\s(?P<nbr_address>\S+)
                \scapability
                \ssuppress
                \s(?P<all>all\sinheritance-disable)
                $""", re.VERBOSE,
            ),
            "setval": "capability suppress all inheritance-disable",
            "compval": "capability.suppress.all.inheritance_disable",
            "result": {
                "neighbor": {
                    UNIQUE_NEIB_ADD: {
                        "capability": {
                            "suppress": {
                                "all": {
                                    "inheritance_disable": "{{ True if all is defined }}",
                                },
                            },
                        },
                    },
                },
            },

        },

    ]
    # fmt: on
