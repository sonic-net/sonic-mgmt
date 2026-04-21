#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The arg spec for the sonic_ipv6_router_advertisement module
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class Ipv6_router_advertisementArgs(object):  # pylint: disable=R0903
    """The arg spec for the sonic_ipv6_router_advertisement module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        'config': {
            'elements': 'dict',
            'options': {
                'adv_interval_option': {'type': 'bool'},
                'dnssl': {
                    'elements': 'dict',
                    'options': {
                        'dnssl_name': {'required': True, 'type': 'str'},
                        'valid_lifetime': {'type': 'int'}
                    },
                    'type': 'list'
                },
                'home_agent_config': {'type': 'bool'},
                'home_agent_lifetime': {'type': 'int'},
                'home_agent_preference': {'type': 'int'},
                'managed_config': {'type': 'bool'},
                'min_ra_interval': {'type': 'int'},
                'min_ra_interval_msec': {'type': 'int'},
                'mtu': {'type': 'int'},
                'name': {'required': True, 'type': 'str'},
                'other_config': {'type': 'bool'},
                'ra_fast_retrans': {'type': 'bool'},
                'ra_hop_limit': {'type': 'int'},
                'ra_interval': {'type': 'int'},
                'ra_interval_msec': {'type': 'int'},
                'ra_lifetime': {'type': 'int'},
                'ra_prefixes': {
                    'elements': 'dict',
                    'options': {
                        'no_autoconfig': {'type': 'bool'},
                        'off_link': {'type': 'bool'},
                        'preferred_lifetime': {'type': 'int'},
                        'prefix': {'required': True, 'type': 'str'},
                        'router_address': {'type': 'bool'},
                        'valid_lifetime': {'type': 'int'}
                    },
                    'type': 'list'
                },
                'ra_retrans_interval': {'type': 'int'},
                'rdnss': {
                    'elements': 'dict',
                    'options': {
                        'address': {'required': True, 'type': 'str'},
                        'valid_lifetime': {'type': 'int'}
                    },
                    'type': 'list'
                },
                'reachable_time': {'type': 'int'},
                'router_preference': {
                    'choices': ['low', 'medium', 'high'],
                    'type': 'str'
                },
                'suppress': {'type': 'bool'}
            },
            'type': 'list'
        },
        'state': {
            'choices': ['merged', 'deleted', 'replaced', 'overridden'],
            'default': 'merged',
            'type': 'str'
        }
    }  # pylint: disable=C0301
