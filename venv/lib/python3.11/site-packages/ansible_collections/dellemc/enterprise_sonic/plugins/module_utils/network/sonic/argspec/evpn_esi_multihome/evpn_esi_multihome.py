#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The arg spec for the sonic_evpn_esi_multihome module
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type


class Evpn_esi_multihomeArgs(object):  # pylint: disable=R0903
    """The arg spec for the sonic_evpn_esi_multihome module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        'config': {
            'options': {
                'df_election_time': {
                    'type': 'int'
                },
                'es_activation_delay': {
                    'type': 'int'
                },
                'mac_holdtime': {
                    'type': 'int'
                },
                'neigh_holdtime': {
                    'type': 'int'
                },
                'startup_delay': {
                    'type': 'int'
                }
            },
            'type': 'dict'
        },
        'state': {
            'choices': ['merged', 'replaced', 'overridden', 'deleted'],
            'default': 'merged',
            'type': 'str'
        }
    }  # pylint: disable=C0301
