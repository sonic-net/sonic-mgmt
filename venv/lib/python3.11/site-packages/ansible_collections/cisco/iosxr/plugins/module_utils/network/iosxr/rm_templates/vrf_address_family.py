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


class Vrf_address_familyTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(Vrf_address_familyTemplate, self).__init__(
            lines=lines,
            tmplt=self,
            module=module,
        )

    # fmt: off
    PARSERS = [
        {
            "name": "name",
            "getval": re.compile(
                r"""
                ^vrf\s(?P<name>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "vrf {{ name }}",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                },
            },
            "shared": True,
        },
        {
            "name": "address_family",
            "getval": re.compile(
                r"""
                ^vrf\s(?P<name>\S+)
                (?P<address_families>\s+address-family\s(?P<afi>\S+)\s(?P<safi>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "address-family {{ afi }} {{ safi }}",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                    "address_families": {
                        '{{"address_families_" + afi + "_" + safi }}': {
                            "afi": "{{ afi}}",
                            "safi": "{{safi}}",
                        },
                    },
                },
            },
        },
        {
            "name": "export.route_policy",
            "getval": re.compile(
                r"""
                ^vrf\s(?P<name>\S+)
                (?P<address_families>\s+address-family\s(?P<afi>\S+)\s(?P<safi>\S+))
                \s+export\sroute-policy\s(?P<export_route_policy>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "export route-policy {{ export.route_policy }}",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                    "address_families": {
                        '{{"address_families_" + afi + "_" + safi }}': {
                            "afi": "{{ afi}}",
                            "safi": "{{safi}}",
                            "export": {
                                "route_policy": "{{ export_route_policy }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "export.route_target",
            "getval": re.compile(
                r"""
                ^vrf\s(?P<name>\S+)
                (?P<address_families>\s+address-family\s(?P<afi>\S+)\s(?P<safi>\S+))
                \s+export\sroute-target\s(?P<export_route_target>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "export route-target {{ export.route_target }}",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                    "address_families": {
                        '{{"address_families_" + afi + "_" + safi }}': {
                            "afi": "{{ afi}}",
                            "safi": "{{safi}}",
                            "export": {
                                "route_target": "{{ export_route_target }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "export.to.default_vrf.route_policy",
            "getval": re.compile(
                r"""
                ^vrf\s(?P<name>\S+)
                (?P<address_families>\s+address-family\s(?P<afi>\S+)\s(?P<safi>\S+))
                \s+export\sto\sdefault-vrf\sroute-policy\s(?P<export_to_default_vrf_route_policy>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "export to default-vrf route-policy {{ export.to.default_vrf.route_policy }}",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                    "address_families": {
                        '{{"address_families_" + afi + "_" + safi }}': {
                            "afi": "{{ afi}}",
                            "safi": "{{safi}}",
                            "export": {
                                "to": {
                                    "default_vrf": {
                                        "route_policy": "{{ export_to_default_vrf_route_policy }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "export.to.vrf.allow_imported_vpn",
            "getval": re.compile(
                r"""
                ^vrf\s(?P<name>\S+)
                (?P<address_families>\s+address-family\s(?P<afi>\S+)\s(?P<safi>\S+))
                \s+export\sto\svrf\s(?P<allow_imported_vpn>allow-imported-vpn)
                $""", re.VERBOSE,
            ),
            "setval": "export to vrf allow-imported-vpn",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                    "address_families": {
                        '{{"address_families_" + afi + "_" + safi }}': {
                            "afi": "{{ afi}}",
                            "safi": "{{safi}}",
                            "export": {
                                "to": {
                                    "vrf": {
                                        "allow_imported_vpn": "{{ true if allow_imported_vpn is defined }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "import_config.route_target",
            "getval": re.compile(
                r"""
                ^vrf\s(?P<name>\S+)
                (?P<address_families>\s+address-family\s(?P<afi>\S+)\s(?P<safi>\S+))
                \s+import\sroute-target\s(?P<import_config_route_target>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "import route-target {{ import_config.route_target }}",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                    "address_families": {
                        '{{"address_families_" + afi + "_" + safi }}': {
                            "afi": "{{ afi}}",
                            "safi": "{{safi}}",
                            "import_config": {
                                "route_target": "{{import_config_route_target}}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "import_config.route_policy",
            "getval": re.compile(
                r"""
                ^vrf\s(?P<name>\S+)
                (?P<address_families>\s+address-family\s(?P<afi>\S+)\s(?P<safi>\S+))
                \s+import\sroute-policy\s(?P<import_config_route_policy>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "import route-policy {{ import_config.route_policy }}",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                    "address_families": {
                        '{{"address_families_" + afi + "_" + safi }}': {
                            "afi": "{{ afi}}",
                            "safi": "{{safi}}",
                            "import_config": {
                                "route_policy": "{{import_config_route_policy}}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "import_config.from_config.bridge_domain.advertise_as_vpn",
            "getval": re.compile(
                r"""
                ^vrf\s(?P<name>\S+)
                (?P<address_families>\s+address-family\s(?P<afi>\S+)\s(?P<safi>\S+))
                \s+import\sfrom\sbridge-domain\s(?P<advertise_as_vpn>advertise-as-vpn)
                $""", re.VERBOSE,
            ),
            "setval": "import from bridge-domain advertise-as-vpn",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                    "address_families": {
                        '{{"address_families_" + afi + "_" + safi }}': {
                            "afi": "{{ afi}}",
                            "safi": "{{safi}}",
                            "import_config": {
                                "from_config": {
                                    "bridge_domain": {
                                        "advertise_as_vpn": "{{ true if advertise_as_vpn is defined }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "import_config.from_config.default_vrf.route_policy",
            "getval": re.compile(
                r"""
                ^vrf\s(?P<name>\S+)
                (?P<address_families>\s+address-family\s(?P<afi>\S+)\s(?P<safi>\S+))
                \s+import\sfrom\sdefault-vrf\sroute-policy\s(?P<import_config_from_config_default_vrf_route_policy>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "import from default-vrf route-policy {{ import_config.from_config.default_vrf.route_policy }}",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                    "address_families": {
                        '{{"address_families_" + afi + "_" + safi }}': {
                            "afi": "{{ afi}}",
                            "safi": "{{safi}}",
                            "import_config": {
                                "from_config": {
                                    "default_vrf": {
                                        "route_policy": "{{ import_config_from_config_default_vrf_route_policy }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "import_config.from_config.vrf.advertise_as_vpn",
            "getval": re.compile(
                r"""
                ^vrf\s(?P<name>\S+)
                (?P<address_families>\s+address-family\s(?P<afi>\S+)\s(?P<safi>\S+))
                \s+import\sfrom\svrf\s(?P<advertise_as_vpn>advertise-as-vpn)
                $""", re.VERBOSE,
            ),
            "setval": "import from vrf advertise-as-vpn",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                    "address_families": {
                        '{{"address_families_" + afi + "_" + safi }}': {
                            "afi": "{{ afi}}",
                            "safi": "{{safi}}",
                            "import_config": {
                                "from_config": {
                                    "vrf": {
                                        "advertise_as_vpn": "{{ true if advertise_as_vpn is defined }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "maximum.prefix",
            "getval": re.compile(
                r"""
                ^vrf\s(?P<name>\S+)
                (?P<address_families>\s+address-family\s(?P<afi>\S+)\s(?P<safi>\S+))
                \s+maximum\sprefix\s(?P<maximum_prefix>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "maximum prefix {{ maximum.prefix }}",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                    "address_families": {
                        '{{"address_families_" + afi + "_" + safi }}': {
                            "afi": "{{ afi}}",
                            "safi": "{{safi}}",
                            "maximum": {
                                "prefix": "{{ maximum_prefix }}",
                            },
                        },
                    },
                },
            },
        },
    ]
    # fmt: on
