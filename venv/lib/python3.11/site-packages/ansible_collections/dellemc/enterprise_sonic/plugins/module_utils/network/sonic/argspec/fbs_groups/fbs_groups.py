#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The arg spec for the sonic_fbs_groups module
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type


class Fbs_groupsArgs(object):  # pylint: disable=R0903
    """The arg spec for the sonic_fbs_groups module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        'config': {
            'options': {
                'next_hop_groups': {
                    'elements': 'dict',
                    'options': {
                        'group_description': {'type': 'str'},
                        'group_name': {'required': True, 'type': 'str'},
                        'group_type': {'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                        'next_hops': {
                            'elements': 'dict',
                            'options': {
                                'entry_id': {'required': True, 'type': 'int'},
                                'ip_address': {'type': 'str'},
                                'vrf': {'type': 'str'},
                                'next_hop_type': {
                                    'choices': ['non_recursive', 'overlay', 'recursive'],
                                    'type': 'str'
                                }
                            },
                            'type': 'list'
                        },
                        'threshold_down': {'type': 'int'},
                        'threshold_type': {'choices': ['count', 'percentage'], 'type': 'str'},
                        'threshold_up': {'type': 'int'}
                    },
                    'type': 'list'
                },
                'replication_groups': {
                    'elements': 'dict',
                    'options': {
                        'group_description': {'type': 'str'},
                        'group_name': {'required': True, 'type': 'str'},
                        'group_type': {'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                        'next_hops': {
                            'elements': 'dict',
                            'options': {
                                'entry_id': {'required': True, 'type': 'int'},
                                'ip_address': {'type': 'str'},
                                'vrf': {'type': 'str'},
                                'next_hop_type': {
                                    'choices': ['non_recursive', 'overlay', 'recursive'],
                                    'type': 'str'
                                },
                                'single_copy': {'type': 'bool'}
                            },
                            'type': 'list'
                        }
                    },
                    'type': 'list'
                }
            },
            'type': 'dict'
        },
        'state': {
            'choices': ['merged', 'deleted', 'replaced', 'overridden'],
            'default': 'merged',
            'type': 'str'
        }
    }  # pylint: disable=C0301
