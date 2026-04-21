#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The arg spec for the sonic_network_policy module
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type


class Network_policyArgs(object):  # pylint: disable=R0903
    """The arg spec for the sonic_network_policy module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        'config': {
            'elements': 'dict',
            'options': {
                'applications': {
                    'elements': 'dict',
                    'mutually_exclusive': [['dot1p', 'vlan_id']],
                    'options': {
                        'app_type': {
                            'choices': ['voice', 'voice-signaling'],
                            'required': True,
                            'type': 'str'
                        },
                        'dscp': {'type': 'int'},
                        'dot1p': {'choices': ['enabled'], 'type': 'str'},
                        'priority': {'type': 'int'},
                        'untagged': {'type': 'bool'},
                        'vlan_id': {'type': 'int'}
                    },
                    'type': 'list'
                },
                'number': {'required': True, 'type': 'int'}
            },
            'type': 'list'
        },
        'state': {
            'choices': ['merged', 'deleted', 'replaced', 'overridden'],
            'default': 'merged',
            'type': 'str'
        }
    }  # pylint: disable=C0301
