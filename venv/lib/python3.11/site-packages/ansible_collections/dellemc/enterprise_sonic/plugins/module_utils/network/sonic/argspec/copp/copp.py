#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The arg spec for the sonic_copp module
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class CoppArgs(object):  # pylint: disable=R0903
    """The arg spec for the sonic_copp module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        'config': {
            'options': {
                'copp_groups': {
                    'elements': 'dict',
                    'options': {
                        'cbs': {'type': 'str'},
                        'cir': {'type': 'str'},
                        'copp_name': {'required': True, 'type': 'str'},
                        'queue': {'type': 'int'},
                        'trap_action': {
                            'choices': ['copy', 'copy_cancel', 'deny', 'drop', 'forward', 'log', 'transit', 'trap'],
                            'type': 'str'
                        },
                        'trap_priority': {'type': 'int'}
                    },
                    'type': 'list'
                },
                'copp_traps': {
                    'elements': 'dict',
                    'options': {
                        'name': {'required': True, 'type': 'str'},
                        'trap_protocol_ids': {'type': 'str'},
                        'trap_group': {'type': 'str'}
                    },
                    'type': 'list'
                }
            },
            'type': 'dict'
        },
        'state': {'choices': ['merged', 'deleted', 'replaced', 'overridden'], 'default': 'merged', 'type': 'str'}
    }  # pylint: disable=C0301
