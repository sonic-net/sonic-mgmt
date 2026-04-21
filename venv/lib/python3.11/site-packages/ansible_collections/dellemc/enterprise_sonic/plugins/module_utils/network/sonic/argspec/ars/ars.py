#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The arg spec for the sonic_ars module
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type


class ArsArgs(object):  # pylint: disable=R0903
    """The arg spec for the sonic_ars module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        'config': {
            'options': {
                'ars_objects': {
                    'elements': 'dict',
                    'options': {
                        'idle_time': {'type': 'int'},
                        'max_flows': {'choices': [256, 512, 1024, 2048, 4096, 8192, 16384, 32768], 'type': 'int'},
                        'mode': {
                            'choices': ['fixed', 'flowlet-quality', 'flowlet-random', 'packet-quality', 'packet-random'],
                            'type': 'str'
                        },
                        'name': {'required': True, 'type': 'str'}
                    },
                    'type': 'list'
                },
                'port_bindings': {
                    'elements': 'dict',
                    'options': {
                        'name': {'required': True, 'type': 'str'},
                        'profile': {'type': 'str'}
                    },
                    'type': 'list'
                },
                'port_profiles': {
                    'elements': 'dict',
                    'options': {
                        'enable': {'type': 'bool'},
                        'load_future_weight': {'type': 'int'},
                        'load_past_weight': {'type': 'int'},
                        'load_scaling_factor': {'choices': [0, 1, 2.5, 4, 5, 10, 20, 40, 80], 'type': 'float'},
                        'name': {'required': True, 'type': 'str'}},
                    'type': 'list'
                },
                'profiles': {
                    'elements': 'dict',
                    'options': {
                        'algorithm': {'choices': ['EWMA'], 'type': 'str'},
                        'load_current_max_val': {'type': 'int'},
                        'load_current_min_val': {'type': 'int'},
                        'load_future_max_val': {'type': 'int'},
                        'load_future_min_val': {'type': 'int'},
                        'load_past_max_val': {'type': 'int'},
                        'load_past_min_val': {'type': 'int'},
                        'name': {'required': True, 'type': 'str'},
                        'port_load_current': {'type': 'bool'},
                        'port_load_exponent': {'type': 'int'},
                        'port_load_future': {'type': 'bool'},
                        'port_load_future_weight': {'type': 'int'},
                        'port_load_past': {'type': 'bool'},
                        'port_load_past_weight': {'type': 'int'},
                        'random_seed': {'type': 'int'},
                        'sampling_interval': {'type': 'int'}
                    },
                    'type': 'list'
                },
                'switch_binding': {
                    'options': {
                        'profile': {'type': 'str'}
                    },
                    'type': 'dict'
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
