#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The arg spec for the sonic_route_maps module
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class Route_mapsArgs(object):  # pylint: disable=R0903
    """The arg spec for the sonic_route_maps module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        'config': {
            'elements': 'dict',
            'options': {
                'map_name': {'required': True, 'type': 'str'},
                'action': {
                    'choices': ['permit', 'deny'],
                    'type': 'str'
                },
                'sequence_num': {
                    'type': 'int'
                },
                'match': {
                    'options': {
                        'as_path': {'type': 'str'},
                        'community': {'type': 'str'},
                        'evpn': {
                            'options': {
                                'default_route': {'type': 'bool'},
                                'route_type': {
                                    'choices': ['macip', 'multicast', 'prefix'],
                                    'type': 'str'
                                },
                                'vni': {'type': 'int'}
                            },
                            'required_one_of': [['default_route', 'route_type', 'vni']],
                            'type': 'dict'
                        },
                        'ext_comm': {'type': 'str'},
                        'interface': {'type': 'str'},
                        'ip': {
                            'options': {
                                'address': {'type': 'str'},
                                'next_hop': {'type': 'str'}
                            },
                            'required_one_of': [['address', 'next_hop']],
                            'type': 'dict'
                        },
                        'ipv6': {
                            'options': {
                                'address': {
                                    'required': True,
                                    'type': 'str'
                                }
                            },
                            'type': 'dict'
                        },
                        'local_preference': {'type': 'int'},
                        'metric': {'type': 'int'},
                        'origin': {
                            'choices': ['egp', 'igp', 'incomplete'],
                            'type': 'str'
                        },
                        'peer': {
                            'mutually_exclusive': [['ip', 'ipv6', 'interface']],
                            'options': {
                                'interface': {'type': 'str'},
                                'ip': {'type': 'str'},
                                'ipv6': {'type': 'str'}
                            },
                            'required_one_of': [['ip', 'ipv6', 'interface']],
                            'type': 'dict'
                        },
                        'source_protocol': {
                            'choices': ['bgp', 'connected', 'ospf', 'static'],
                            'type': 'str'
                        },
                        'source_vrf': {'type': 'str'},
                        'tag': {'type': 'int'}
                    },
                    'type': 'dict'
                },
                'set': {
                    'options': {
                        'ars_object': {'type': 'str'},
                        'as_path_prepend': {'type': 'str'},
                        'comm_list_delete': {'type': 'str'},
                        'community': {
                            'options': {
                                'community_number': {
                                    'elements': 'str',
                                    'type': 'list'
                                },
                                'community_attributes': {
                                    'elements': 'str',
                                    'type': 'list',
                                    'mutually_exclusive': [
                                        ['none', 'local_as'],
                                        ['none', 'no_advertise'],
                                        ['none', 'no_export'],
                                        ['none', 'no_peer'],
                                        ['none', 'additive']
                                    ],
                                    'choices': [
                                        'local_as',
                                        'no_advertise',
                                        'no_export',
                                        'no_peer',
                                        'additive',
                                        'none'
                                    ]
                                },
                            },
                            'type': 'dict'
                        },
                        'extcommunity': {
                            'options': {
                                'rt': {
                                    'elements': 'str',
                                    'type': 'list'
                                },
                                'soo': {
                                    'elements': 'str',
                                    'type': 'list'
                                },
                                'bandwidth': {
                                    "options": {
                                        "bandwidth_value": {"type": "str", "required": True},
                                        "transitive_value": {"type": "bool"},
                                    },
                                    'type': 'dict'
                                },
                            },
                            'required_one_of': [['rt', 'soo', 'bandwidth']],
                            'type': 'dict'
                        },
                        'ip_next_hop': {
                            'options': {
                                'address': {'type': 'str'},
                                'native': {'type': 'bool'}
                            },
                            'required_one_of': [['address', 'native']],
                            'type': 'dict'
                        },
                        'ipv6_next_hop': {
                            'options': {
                                'global_addr': {'type': 'str'},
                                'native': {'type': 'bool'},
                                'prefer_global': {'type': 'bool'}
                            },
                            'required_one_of': [['global_addr', 'prefer_global', 'native']],
                            'type': 'dict'
                        },
                        'local_preference': {'type': 'int'},
                        'metric': {
                            'mutually_exclusive': [['value', 'rtt_action']],
                            'required_one_of': [['value', 'rtt_action']],
                            'options': {
                                'rtt_action': {
                                    'choices': ['set', 'add', 'subtract'],
                                    'type': 'str'
                                },
                                'value': {'type': 'int'}
                            },
                            'type': 'dict'
                        },
                        'origin': {
                            'choices': ['egp', 'igp', 'incomplete'],
                            'type': 'str'
                        },
                        'weight': {'type': 'int'},
                        'tag': {'type': 'int'}
                    },
                    'type': 'dict'
                },
                'call': {'type': 'str'},
            },
            'type': 'list'
        },
        'state': {
            'choices': ['merged', 'deleted', 'replaced', 'overridden'],
            'default': 'merged',
            'type': 'str'
        }
    }  # pylint: disable=C0301
