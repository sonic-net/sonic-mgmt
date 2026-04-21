from __future__ import absolute_import, division, print_function
__metaclass__ = type
#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The arg spec for the sonic_br_l2pt module
"""


class Br_l2ptArgs(object):  # pylint: disable=R0903
    """The arg spec for the sonic_br_l2pt module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        'config': {
            'elements': 'dict',
            'options': {
                'bridge_l2pt_params': {
                    'elements': 'dict',
                    'options': {
                        'protocol': {
                            'choices': ['LLDP', 'LACP', 'STP', 'CDP'],
                            'required': True,
                            'type': 'str'
                        },
                        'vlan_ids': {
                            'elements': 'str',
                            'type': 'list'
                        }
                    },
                    'type': 'list'
                },
                'name': {
                    'required': True,
                    'type': 'str'
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
