#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The arg spec for the sonic_lldp_interfaces module
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type


class Lldp_interfacesArgs(object):  # pylint: disable=R0903
    """The arg spec for the sonic_lldp_interfaces module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        'config': {
            'elements': 'dict',
            'options': {
                'name': {
                    'required': True,
                    'type': 'str'
                },
                'enable': {
                    'type': 'bool'
                },
                'med_tlv_select': {
                    'options': {
                        'network_policy': {
                            'type': 'bool'
                        },
                        'power_management': {
                            'type': 'bool'
                        }
                    },
                    'type': 'dict'
                },
                'mode': {
                    'choices': ['receive', 'transmit'],
                    'type': 'str'
                },
                'network_policy': {
                    'type': 'int'
                },
                'tlv_select': {
                    'options': {
                        'power_management': {
                            'type': 'bool'
                        },
                        'port_vlan_id': {
                            'type': 'bool'
                        },
                        'vlan_name': {
                            'type': 'bool'
                        },
                        'link_aggregation': {
                            'type': 'bool'
                        },
                        'max_frame_size': {
                            'type': 'bool'
                        }
                    },
                    'type': 'dict'
                },
                'vlan_name_tlv': {
                    'options': {
                        'max_tlv_count': {
                            'type': 'int'
                        },
                        'allowed_vlans': {
                            'elements': 'dict',
                            'options': {
                                'vlan': {'type': 'str'}
                            },
                            'type': 'list'
                        }
                    },
                    'type': 'dict'
                },
                'tlv_set': {
                    'options': {
                        'ipv4_management_address': {
                            'type': 'str'
                        },
                        'ipv6_management_address': {
                            'type': 'str'
                        }
                    },
                    'type': 'dict'
                }
            },
            'type': 'list'
        },
        'state': {
            'choices': ['merged', 'deleted', 'overridden', 'replaced'],
            'default': 'merged',
            'type': 'str'
        }
    }  # pylint: disable=C0301
