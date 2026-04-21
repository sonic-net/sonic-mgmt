#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The arg spec for the sonic_pms module
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type


class PmsArgs(object):  # pylint: disable=R0903
    """The arg spec for the sonic_pms module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        'config': {
            'elements': 'dict',
            'options': {
                'port_security_enable': {'required': True, 'type': 'bool'},
                'max_allowed_macs': {'type': 'int'},
                'name': {'required': True, 'type': 'str'},
                'sticky_mac': {'type': 'bool'},
                'violation': {'choices': ['PROTECT', 'SHUTDOWN'], 'type': 'str'}
            },
            'type': 'list'
        },
        'state': {
            'choices': ['merged', 'deleted', 'replaced', 'overridden'],
            'default': 'merged',
            'type': 'str'
        }
    }  # pylint: disable=C0301
