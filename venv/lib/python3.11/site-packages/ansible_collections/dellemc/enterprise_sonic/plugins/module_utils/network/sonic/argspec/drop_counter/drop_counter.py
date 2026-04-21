#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The arg spec for the sonic_drop_counter module
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type


class Drop_counterArgs(object):  # pylint: disable=R0903
    """The arg spec for the sonic_drop_counter module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        'config': {
            'elements': 'dict',
            'options': {
                'alias': {'type': 'str'},
                'counter_description': {'type': 'str'},
                'counter_type': {
                    'choices': ['PORT_INGRESS_DROPS'],
                    'type': 'str'
                },
                'enable': {'type': 'bool'},
                'group': {'type': 'str'},
                'mirror': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'reasons': {
                    'choices': [
                        'ACL_ANY',
                        'ANY',
                        'DIP_LINK_LOCAL',
                        'EXCEEDS_L3_MTU',
                        'FDB_AND_BLACKHOLE_DISCARDS',
                        'IP_HEADER_ERROR',
                        'L3_EGRESS_LINK_DOWN',
                        'MPLS_MISS',
                        'SIP_LINK_LOCAL',
                        'SMAC_EQUALS_DMAC'
                    ],
                    'elements': 'str',
                    'type': 'list'
                }
            },
            'type': 'list'
        },
        'state': {
            'choices': ['merged', 'deleted', 'replaced', 'overridden'],
            'default': 'merged',
            'type': 'str'
        }
    }  # pylint: disable=C0301
