#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#############################################

"""
The arg spec for the sonic_ptp_port_ds module
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class Ptp_port_dsArgs(object):  # pylint: disable=R0903
    """The arg spec for the sonic_ptp_port_ds module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        'config': {
            'elements': 'dict',
            'options': {
                'interface': {
                    'required': True,
                    'type': 'str'
                },
                'local_priority': {
                    'type': 'int'
                },
                'role': {
                    'choices': ['dynamic', 'master', 'slave'],
                    'type': 'str'
                },
                'unicast_table': {
                    'type': 'list',
                    'elements': 'str'
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
