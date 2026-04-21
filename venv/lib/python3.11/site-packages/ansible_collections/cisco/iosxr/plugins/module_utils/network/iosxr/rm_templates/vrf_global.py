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


class Vrf_globalTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(Vrf_globalTemplate, self).__init__(
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
            "name": "description",
            "getval": re.compile(
                r"""
                ^vrf\s(?P<name>\S+)
                \s+description\s(?P<description>.+$)
                $""", re.VERBOSE,
            ),
            "setval": "description {{ description }}",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                    'description': '{{ description }}',
                },
            },
        },
        {
            "name": "evpn_route_sync",
            "getval": re.compile(
                r"""
                ^vrf\s(?P<name>\S+)
                \s+evpn-route-sync\s(?P<evpn_route_sync>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "evpn-route-sync {{ evpn_route_sync }}",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                    "evpn_route_sync": "{{ evpn_route_sync }}",
                },
            },
        },
        {
            "name": "fallback_vrf",
            "getval": re.compile(
                r"""
                ^vrf\s(?P<name>\S+)
                \s+fallback-vrf\s(?P<fallback_vrf>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "fallback-vrf {{ fallback_vrf }}",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                    "fallback_vrf": "{{ fallback_vrf }}",
                },
            },
        },
        {
            "name": "mhost.default_interface",
            "getval": re.compile(
                r"""
                ^vrf\s(?P<name>\S+)
                (?P<mhost>\s+mhost\s(?P<afi>\S+))
                \s+default-interface\s(?P<default_interface>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "mhost {{ mhost.afi }} default-interface {{ mhost.default_interface }}",
            "compval": "mhost.default_interface",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                    "mhost": {
                        "afi": "{{ afi }}",
                        "default_interface": "{{ default_interface }}",
                    },
                },
            },
        },
        {
            "name": "rd",
            "getval": re.compile(
                r"""
                ^vrf\s(?P<name>\S+)
                \s+rd\s(?P<rd>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "rd {{ rd }}",
            "compval": "rd",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                    "rd": "{{ rd }}",
                },
            },
        },
        {
            "name": "remote_route_filtering.disable",
            "getval": re.compile(
                r"""
                ^vrf\s(?P<name>\S+)
                \s+remote-route-filtering\s(?P<disable>disable)
                $""", re.VERBOSE,
            ),
            "setval": "remote-route-filtering disable",
            "compval": "remote_route_filtering.disable",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                    "remote_route_filtering": {
                        "disable": "{{ true if disable is defined }}",
                    },
                },
            },
        },
        {
            "name": "vpn.id",
            "getval": re.compile(
                r"""
                ^vrf\s(?P<name>\S+)
                \s+vpn\sid\s(?P<vpn_id>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "vpn id {{ vpn.id }}",
            "compval": "vpn.id",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                    "vpn": {
                        "id": "{{ vpn_id }}",
                    },
                },
            },
        },
    ]
    # fmt: on
