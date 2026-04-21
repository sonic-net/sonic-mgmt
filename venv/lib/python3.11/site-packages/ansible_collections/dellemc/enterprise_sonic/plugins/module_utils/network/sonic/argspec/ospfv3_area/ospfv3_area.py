#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


"""
The arg spec for the sonic_ospfv3_area module
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type


class Ospfv3_areaArgs(object):  # pylint: disable=R0903
    """The arg spec for the sonic_ospfv3_area module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        'config': {
            'elements': 'dict',
            'mutually_exclusive': [['stub', 'nssa']],
            'options': {
                'area_id': {'required': True, 'type': 'str'},
                'filter_list_in': {'type': 'str'},
                'filter_list_out': {'type': 'str'},
                'nssa': {
                    'mutually_exclusive': [['no_summary', 'default_originate']],
                    'options': {
                        'enabled': {'required': True, 'type': 'bool'},
                        'default_originate': {
                            'type': 'dict',
                            'options': {
                                'enabled': {'required': True, 'type': 'bool'},
                                'metric': {'type': 'int'},
                                'metric_type': {'type': 'int', 'choices': [1, 2]}
                            }
                        },
                        'no_summary': {'type': 'bool'},
                        'ranges': {
                            'elements': 'dict',
                            'options': {
                                'advertise': {'type': 'bool'},
                                'cost': {'type': 'int'},
                                'prefix': {'required': True, 'type': 'str'}
                            },
                            'type': 'list'
                        }
                    },
                    'type': 'dict'
                },
                'ranges': {
                    'elements': 'dict',
                    'options': {
                        'advertise': {'type': 'bool'},
                        'cost': {'type': 'int'},
                        'prefix': {'required': True, 'type': 'str'}
                    },
                    'type': 'list'
                },
                'stub': {
                    'options': {
                        'enabled': {'required': True, 'type': 'bool'},
                        'no_summary': {'type': 'bool'}
                    },
                    'type': 'dict'
                },
                'vrf_name': {'required': True, 'type': 'str'},
            },
            'type': 'list'
        },
        'state': {
            'choices': ['merged', 'replaced', 'overridden', 'deleted'],
            'default': 'merged',
            'type': 'str'
        }
    }  # pylint: disable=C0301
