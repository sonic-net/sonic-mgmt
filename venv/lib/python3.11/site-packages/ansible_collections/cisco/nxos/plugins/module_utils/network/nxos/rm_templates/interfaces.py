# -*- coding: utf-8 -*-
# Copyright 2025 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The Interfaces parser templates file. This contains
a list of parser definitions and associated functions that
facilitates both facts gathering and native command generation for
the given network resource.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


class InterfacesTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(InterfacesTemplate, self).__init__(lines=lines, tmplt=self, module=module)

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
            "name": "description",
            "getval": re.compile(
                r"""
                \s+description\s(?P<description>.+$)
                $""", re.VERBOSE,
            ),
            "setval": "description {{ description }}",
            "result": {
                '{{ name }}': {
                    'description': "'{{ description }}'",
                },
            },
        },
        {
            "name": "enabled",
            "getval": re.compile(
                r"""
                (?P<negate>\s+no)?
                (?P<shutdown>\s+shutdown)
                $""", re.VERBOSE,
            ),
            "setval": "shutdown",
            "result": {
                '{{ name }}': {
                    'enabled': "{{ False if shutdown is defined and negate is not defined else True }}",
                },
            },
        },
        {
            "name": "speed",
            "getval": re.compile(
                r"""
                \s+speed\s(?P<speed>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "speed {{ speed|string }}",
            "result": {
                '{{ name }}': {
                    'speed': "{{ speed }}",
                },
            },
        },
        {
            "name": "mtu",
            "getval": re.compile(
                r"""
                \s+mtu\s(?P<mtu>\d+)
                $""", re.VERBOSE,
            ),
            "setval": "mtu {{ mtu|string }}",
            "result": {
                '{{ name }}': {
                    'mtu': "{{ mtu }}",
                },
            },
        },
        {
            "name": "duplex",
            "getval": re.compile(
                r"""
                \s+duplex\s(?P<duplex>full|half|auto)
                $""", re.VERBOSE,
            ),
            "setval": "duplex {{ duplex }}",
            "result": {
                '{{ name }}': {
                    'duplex': "{{ duplex }}",
                },
            },
        },
        {
            "name": "ip_forward",
            "getval": re.compile(
                r"""
                \s+ip\s(?P<ip_forward>forward)
                $""", re.VERBOSE,
            ),
            "setval": "ip forward",
            "result": {
                '{{ name }}': {
                    'ip_forward': "{{ True if ip_forward is defined }}",
                },
            },
        },
        {
            "name": "fabric_forwarding_anycast_gateway",
            "getval": re.compile(
                r"""
                \s+fabric\sforwarding
                \smode\sanycast-gateway
                $""", re.VERBOSE,
            ),
            "setval": "fabric forwarding mode anycast-gateway",
            "result": {
                '{{ name }}': {
                    'fabric_forwarding_anycast_gateway': "{{ True }}",
                },
            },
        },
        {  # only applicable for switches
            "name": "mode",
            "getval": re.compile(
                r"""
                (?P<negate>\s+no)?
                (?P<switchport>\s+switchport)
                $""", re.VERBOSE,
            ),
            "setval": "switchport",
            "result": {
                '{{ name }}': {
                    'mode': "{{ 'layer2' if switchport is defined and negate is not defined else 'layer3' }}",
                },
            },
        },
        {
            "name": "mac_address",
            "getval": re.compile(
                r"""
                \s+mac-address
                (\s(?P<mac_address>.+))
                $""", re.VERBOSE,
            ),
            "setval": "mac-address {{ mac_address }}",
            "result": {
                '{{ name }}': {
                    'mac_address': "{{ mac_address }}",
                },
            },
        },
        {
            "name": "logging.link_status",
            "getval": re.compile(
                r"""
                \s+logging\sevent
                \sport(\s(?P<link_status>link-status))
                $""", re.VERBOSE,
            ),
            "setval": "logging event port link-status",
            "result": {
                '{{ name }}': {
                    "logging": {
                        "link_status": "{{ True if link_status is defined }}",
                    },
                },
            },
        },
        {
            "name": "logging.trunk_status",
            "getval": re.compile(
                r"""
                \s+logging\sevent
                \sport(\s(?P<trunk_status>trunk-status))
                $""", re.VERBOSE,
            ),
            "setval": "logging event port trunk-status",
            "result": {
                '{{ name }}': {
                    "logging": {
                        "trunk_status": "{{ True if trunk_status is defined }}",
                    },
                },
            },
        },
        {
            "name": "snmp.trap.link_status",
            "getval": re.compile(
                r"""
                \s+snmp\strap(\s(?P<link_status>link-status))
                $""", re.VERBOSE,
            ),
            "setval": "snmp trap link-status",
            "result": {
                '{{ name }}': {
                    "snmp": {
                        "trap": {
                            "link_status": "{{ True if link_status is defined }}",
                        },
                    },
                },
            },
        },
        {
            "name": "service_policy.input",
            "getval": re.compile(
                r"""
                \s+service-policy\sinput
                (\s(?P<service_policy_input>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "service-policy input {{ service_policy.input }}",
            "result": {
                '{{ name }}': {
                    "service_policy": {
                        "input": "{{ service_policy_input }}",
                    },
                },
            },
        },
        {
            "name": "service_policy.output",
            "getval": re.compile(
                r"""
                \s+service-policy\soutput
                (\s(?P<service_policy_output>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "service-policy output {{ service_policy.output }}",
            "result": {
                '{{ name }}': {
                    "service_policy": {
                        "output": "{{ service_policy_output }}",
                    },
                },
            },
        },
        {
            "name": "service_policy.type_options.qos.input",
            "getval": re.compile(
                r"""
                \s+service-policy\stype\sqos
                (\sinput\s(?P<service_policy_input>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "service-policy type qos input {{ service_policy.type_options.qos.input }}",
            "result": {
                '{{ name }}': {
                    "service_policy": {
                        "type_options": {
                            "qos": {
                                "input": "{{ service_policy_input }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "service_policy.type_options.qos.output",
            "getval": re.compile(
                r"""
                \s+service-policy\stype\sqos
                (\soutput\s(?P<service_policy_output>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "service-policy type qos output {{ service_policy.type_options.qos.output }}",
            "result": {
                '{{ name }}': {
                    "service_policy": {
                        "type_options": {
                            "qos": {
                                "output": "{{ service_policy_output }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "service_policy.type_options.queuing.input",
            "getval": re.compile(
                r"""
                \s+service-policy\stype\squeuing
                (\sinput\s(?P<service_policy_input>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "service-policy type queuing input {{ service_policy.type_options.queuing.input }}",
            "result": {
                '{{ name }}': {
                    "service_policy": {
                        "type_options": {
                            "queuing": {
                                "input": "{{ service_policy_input }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "service_policy.type_options.queuing.output",
            "getval": re.compile(
                r"""
                \s+service-policy\stype\squeuing
                (\soutput\s(?P<service_policy_output>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "service-policy type queuing output {{ service_policy.type_options.queuing.output }}",
            "result": {
                '{{ name }}': {
                    "service_policy": {
                        "type_options": {
                            "queuing": {
                                "output": "{{ service_policy_output }}",
                            },
                        },
                    },
                },
            },
        },
    ]
    # fmt: on
