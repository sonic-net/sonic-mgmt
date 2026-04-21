#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The arg spec for the sonic_ospfv3 module
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type


class Ospfv3Args(object):  # pylint: disable=R0903
    """The arg spec for the sonic_ospfv3 module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        'config': {
            'elements': 'dict',
            'options': {
                'auto_cost_reference_bandwidth': {'type': 'int'},
                'distance': {
                    'options': {
                        'all': {'type': 'int'},
                        'external': {'type': 'int'},
                        'inter_area': {'type': 'int'},
                        'intra_area': {'type': 'int'}
                    },
                    'type': 'dict'
                },
                'graceful_restart': {
                    'options': {
                        'grace_period': {'type': 'int'},
                        'enable': {'type': 'bool'},
                        'helper': {
                            'options': {
                                'enable': {'type': 'bool'},
                                'advertise_router_id': {'elements': 'str', 'type': 'list'},
                                'planned_only': {'type': 'bool'},
                                'strict_lsa_checking': {'type': 'bool'},
                                'supported_grace_time': {'type': 'int'}
                            },
                            'type': 'dict'
                        },
                    },
                    'type': 'dict'
                },
                'log_adjacency_changes': {'choices': ['brief', 'detail'], 'type': 'str'},
                'maximum_paths': {'type': 'int'},
                'redistribute': {
                    'elements': 'dict',
                    'options': {
                        'always': {'type': 'bool'},
                        'metric': {'type': 'int'},
                        'metric_type': {'choices': [1, 2], 'type': 'int'},
                        'protocol': {
                            'choices': ['bgp', 'kernel', 'connected', 'static', 'default_route'],
                            'required': True,
                            'type': 'str'
                        },
                        'route_map': {'type': 'str'}
                    },
                    'type': 'list'
                },
                'router_id': {'type': 'str'},
                'timers': {
                    'options': {
                        'lsa_min_arrival': {'type': 'int'},
                        'throttle_spf': {
                            'options': {
                                'delay_time': {'type': 'int'},
                                'initial_hold_time': {'type': 'int'},
                                'maximum_hold_time': {'type': 'int'}
                            },
                            'required_together': [['delay_time', 'initial_hold_time', 'maximum_hold_time']],
                            'type': 'dict'
                        }
                    },
                    'type': 'dict'
                },
                'vrf_name': {'default': 'default', 'type': 'str'},
                'write_multiplier': {'type': 'int'}
            },
            'type': 'list'
        },
        'state': {
            'choices': ['merged', 'deleted', 'replaced', 'overridden'],
            'default': 'merged',
            'type': 'str'
        }
    }  # pylint: disable=C0301
