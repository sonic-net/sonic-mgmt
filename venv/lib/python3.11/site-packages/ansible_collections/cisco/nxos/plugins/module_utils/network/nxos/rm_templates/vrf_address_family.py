# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The Vrf_address_family parser templates file. This contains
a list of parser definitions and associated functions that
facilitates both facts gathering and native command generation for
the given network resource.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


def _tmplt_maximum(maximum):
    cmd = "maximum routes"
    maxData = maximum.get("maximum")
    if maxData.get("max_routes"):
        cmd += f" {maxData['max_routes']}"
    if maxData.get("max_route_options", {}).get("threshold", {}).get("threshold_value"):
        threshold = maxData["max_route_options"]["threshold"]
        cmd += f" {threshold['threshold_value']}"
        if threshold.get("reinstall_threshold"):
            cmd += f" reinstall {threshold['reinstall_threshold']}"
    if maxData.get("max_route_options", {}).get("warning_only"):
        cmd += " warning-only"
    return cmd


def _tmplt_export_vrf(vrf):
    cmd = "export vrf"
    vrfData = vrf.get("vrf")
    if vrfData.get("max_prefix") or vrfData.get("map_import"):
        cmd += " default"
        if vrfData.get("max_prefix"):
            cmd += f" {vrfData['max_prefix']}"
        if vrfData.get("map_import"):
            cmd += f" map {vrfData['map_import']}"
    if vrfData.get("allow_vpn"):
        cmd += " allow-vpn"
    return cmd


def _tmplt_import_vrf(vrf):
    cmd = "import vrf"
    vrfData = vrf.get("vrf")
    if vrfData.get("max_prefix") or vrfData.get("map_import"):
        cmd += " default"
        if vrfData.get("max_prefix"):
            cmd += f" {vrfData['max_prefix']}"
        if vrfData.get("map_import"):
            cmd += f" map {vrfData['map_import']}"
    if vrfData.get("advertise_vpn"):
        cmd += " advertise-vpn"
    return cmd


class Vrf_address_familyTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(Vrf_address_familyTemplate, self).__init__(lines=lines, tmplt=self, module=module)

    # fmt: off
    PARSERS = [
        {
            "name": "address_family",
            "getval": re.compile(
                r"""
                ^vrf\scontext\s(?P<name>\S+)\s+
                (?P<address_families>\s+address-family
                \s(?P<afi>\S+)\s(?P<safi>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "address-family {{ afi }} {{ safi }}",
            "result": {
                '{{ name }}': {
                    "name": "{{ name }}",
                    "address_families": {
                        "{{ 'address_families_'+afi+'_'+safi }}": {
                            "afi": "{{ afi }}",
                            "safi": "{{ safi }}",
                        },
                    },
                },
            },
            "shared": True,
        },
        {
            "name": "maximum",
            "getval": re.compile(
                r"""
                \s+maximum\sroutes\s(?P<max_routes>\d+)
                (\s(?P<threshold_value>\d+))?
                (\sreinstall\s(?P<reinstall>\d+))?
                (\s((?P<warning_only>warning-only)))?
                $""", re.VERBOSE,
            ),
            "setval": _tmplt_maximum,
            "result": {
                '{{ name }}': {
                    "address_families": {
                        "{{ 'address_families_'+afi+'_'+safi }}": {
                            "afi": "{{ afi }}",
                            "safi": "{{ safi }}",
                            "maximum": {
                                "max_routes": "{{ max_routes }}",
                                "max_route_options": {
                                    "warning_only": "{{ True if warning_only }}",
                                    "threshold": {
                                        "threshold_value": "{{ threshold_value }}",
                                        "reinstall_threshold": "{{ reinstall }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "route_target.import",
            "getval": re.compile(
                r"""
                \s+route-target\simport\s(?P<import>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "route-target import {{ import }}",
            "result": {
                '{{ name }}': {
                    "address_families": {
                        "{{ 'address_families_'+afi+'_'+safi }}": {
                            "afi": "{{ afi }}",
                            "safi": "{{ safi }}",
                            "route_target": [{
                                "import": "{{ import }}",
                            }],
                        },
                    },
                },
            },
        },
        {
            "name": "route_target.export",
            "getval": re.compile(
                r"""
                \s+route-target\sexport\s(?P<export>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "route-target export {{ export }}",
            "result": {
                '{{ name }}': {
                    "address_families": {
                        "{{ 'address_families_'+afi+'_'+safi }}": {
                            "afi": "{{ afi }}",
                            "safi": "{{ safi }}",
                            "route_target": [{
                                "export": "{{ export }}",
                            }],
                        },
                    },
                },
            },
        },
        {
            "name": "export.map",
            "getval": re.compile(
                r"""
                \s+export\smap\s(?P<export_map>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "export map {{ map }}",
            "result": {
                '{{ name }}': {
                    "address_families": {
                        "{{ 'address_families_'+afi+'_'+safi }}": {
                            "afi": "{{ afi }}",
                            "safi": "{{ safi }}",
                            "export": [{
                                "map": "{{ export_map }}",
                            }],
                        },
                    },
                },
            },
        },
        {
            "name": "export.vrf",
            "getval": re.compile(
                r"""
                \s+export\svrf
                ((\sdefault)
                (\s(?P<max_prefix>\d+))?
                (\smap\s(?P<map_import>\S+))?)?
                (\s(?P<allow_vpn>allow-vpn))?
                $""", re.VERBOSE,
            ),
            "setval": _tmplt_export_vrf,
            "result": {
                '{{ name }}': {
                    "address_families": {
                        "{{ 'address_families_'+afi+'_'+safi }}": {
                            "afi": "{{ afi }}",
                            "safi": "{{ safi }}",
                            "export": [{
                                "vrf": {
                                    "allow_vpn": "{{ True if allow_vpn }}",
                                    "max_prefix": "{{ max_prefix if max_prefix }}",
                                    "map_import": "{{ map_import if map_import }}",
                                },
                            }],
                        },
                    },
                },
            },
        },
        {
            "name": "import.map",
            "getval": re.compile(
                r"""
                \s+import\smap\s(?P<import_map>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "import map {{ map }}",
            "result": {
                '{{ name }}': {
                    "address_families": {
                        "{{ 'address_families_'+afi+'_'+safi }}": {
                            "afi": "{{ afi }}",
                            "safi": "{{ safi }}",
                            "import": [{
                                "map": "{{ import_map }}",
                            }],
                        },
                    },
                },
            },
        },
        {
            "name": "import.vrf",
            "getval": re.compile(
                r"""
                \s+import\svrf
                ((\sdefault)
                (\s(?P<max_prefix>\d+))?
                (\smap\s(?P<map_import>\S+))?)?
                (\s(?P<advertise_vpn>advertise-vpn))?
                $""", re.VERBOSE,
            ),
            "setval": _tmplt_import_vrf,
            "result": {
                '{{ name }}': {
                    "address_families": {
                        "{{ 'address_families_'+afi+'_'+safi }}": {
                            "afi": "{{ afi }}",
                            "safi": "{{ safi }}",
                            "import": [{
                                "vrf": {
                                    "advertise_vpn": "{{ True if advertise_vpn }}",
                                    "max_prefix": "{{ max_prefix if max_prefix }}",
                                    "map_import": "{{ map_import if map_import }}",
                                },
                            }],
                        },
                    },
                },
            },
        },
    ]
    # fmt: on
