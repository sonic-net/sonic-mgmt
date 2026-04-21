#
# -*- coding: utf-8 -*-
# © Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The arg spec for the sonic_port_breakout module
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class Port_breakoutArgs(object):  # pylint: disable=R0903
    """The arg spec for the sonic_port_breakout module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        'config': {
            'elements': 'dict',
            'options': {
                'mode': {
                    'choices': ['1x10G', '1x25G', '1x40G', '1x50G', '1x100G',
                                '1x200G', '1x400G', '1x800G', '2x10G', '2x25G',
                                '2x40G', '2x50G', '2x100G', '2x200G', '2x400G',
                                '4x10G', '4x25G', '4x50G', '4x100G', '4x200G',
                                '8x10G', '8x25G', '8x50G', '8x100G'],
                    'type': 'str'
                },
                'name': {'required': True, 'type': 'str'}
            },
            'type': 'list'
        },
        'state': {
            'choices': ['merged', 'deleted', 'replaced', 'overridden'],
            'default': 'merged'
        }
    }  # pylint: disable=C0301
