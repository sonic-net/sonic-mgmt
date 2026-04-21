#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The arg spec for the sonic_ptp_default_ds module
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class Ptp_default_dsArgs(object):  # pylint: disable=R0903
    """The arg spec for the sonic_ptp_default_ds module
    """
    def __init__(self, **kwargs):
        pass
    argument_spec = {
        'config': {
            'options': {
                'announce_receipt_timeout': {'type': 'int'},
                'clock_type': {
                    'choices': ['BC', 'E2E_TC', 'P2P_TC', 'disable'],
                    'type': 'str'
                },
                'domain_number': {'type': 'int'},
                'domain_profile': {
                    'choices': ['ieee1588', 'G.8275.1', 'G.8275.2'],
                    'type': 'str'
                },
                'log_announce_interval': {'type': 'int'},
                'log_min_delay_req_interval': {'type': 'int'},
                'log_sync_interval': {'type': 'int'},
                'network_transport': {
                    'choices': ['L2', 'UDPv4', 'UDPv6'],
                    'type': 'str'
                },
                'priority1': {'type': 'int'},
                'priority2': {'type': 'int'},
                'source_interface': {'type': 'str'},
                'two_step_flag': {'type': 'int'},
                'unicast_multicast': {
                    'choices': ['unicast', 'multicast'],
                    'type': 'str'
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
