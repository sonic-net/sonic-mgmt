# -*- coding: utf-8 -*-
# Copyright 2025 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The L2_interfaces parser templates file. This contains
a list of parser definitions and associated functions that
facilitates both facts gathering and native command generation for
the given network resource.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


class L2_interfacesTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(L2_interfacesTemplate, self).__init__(lines=lines, tmplt=self, module=module)

    # fmt: off
    PARSERS = [
        {
            "name": "name",
            "getval": re.compile(
                r"""
                ^interface\s(?P<name>\S+)
                $""", re.VERBOSE,
            ),
            "setval": 'interface {{ name }}',
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                },
            },
            "shared": True,
        },
        {
            "name": "mode",
            "getval": re.compile(
                r"""
                \s+switchport\smode
                \s+(?P<mode>access|trunk|dot1q-tunnel|fex-fabric|fabricpath)
                $""", re.VERBOSE,
            ),
            "setval": "switchport mode {{ mode }}",
            "result": {
                '{{ name }}': {
                    'mode': "{{ mode }}",
                },
            },
        },
        {
            "name": "access.vlan",
            "getval": re.compile(
                r"""
                \s+switchport\saccess\svlan
                \s+(?P<vlan>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "switchport access vlan {{ access.vlan }}",
            "result": {
                '{{ name }}': {
                    'access': {
                        'vlan': "{{ vlan }}",
                    },
                },
            },
        },
        {
            "name": "trunk.native_vlan",
            "getval": re.compile(
                r"""
                \s+switchport\strunk\snative\svlan
                \s+(?P<vlan>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "switchport trunk native vlan {{ trunk.native_vlan }}",
            "result": {
                '{{ name }}': {
                    'trunk': {
                        'native_vlan': "{{ vlan }}",
                    },
                },
            },
        },
        {
            "name": "trunk.allowed_vlans",
            "getval": re.compile(
                r"""
                \s+switchport\strunk\sallowed\svlan
                \s+(?P<allowed_vlans>.+)
                $""", re.VERBOSE,
            ),
            "setval": "",
            "result": {
                '{{ name }}': {
                    'trunk': {
                        'allowed_vlans': "{{ allowed_vlans }}",
                    },
                },
            },
        },
        {
            "name": "beacon",
            "getval": re.compile(
                r"""
                \s+(?P<beacon>beacon)
                $""", re.VERBOSE,
            ),
            "setval": "beacon",
            "result": {
                '{{ name }}': {
                    'beacon': "{{ True if beacon }}",
                },
            },
        },
        {
            "name": "link_flap.error_disable",
            "getval": re.compile(
                r"""
                \s+link-flap\serror-disable
                (\s+count\s(?P<count>\d+))?
                (\s+interval\s(?P<interval>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "link-flap error-disable"
            "{{ ' count ' + count|string if count is defined else '' }}"
            "{{ ' interval ' + interval|string if interval is defined else '' }}",
            "result": {
                '{{ name }}': {
                    'link_flap': {
                        'error_disable': {
                            'count': "{{ count }}",
                            'interval': "{{ interval }}",
                        },
                    },
                },
            },
        },
        {
            "name": "cdp_enable",
            "getval": re.compile(
                r"""
                \s+cdp\senable
                $""", re.VERBOSE,
            ),
            "setval": "cdp enable",
            "result": {
                '{{ name }}': {
                    'cdp_enable': True,
                },
            },
        },
        {
            "name": "no_cdp_enable",
            "getval": re.compile(
                r"""
                \s+no\scdp\senable
                $""", re.VERBOSE,
            ),
            "setval": "no cdp enable",
            "result": {
                '{{ name }}': {
                    'cdp_enable': False,
                },
            },
        },
    ]
    # fmt: on
