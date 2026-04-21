#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The arg spec for the sonic_fbs_policies module
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type


class Fbs_policiesArgs(object):  # pylint: disable=R0903
    """The arg spec for the sonic_fbs_policies module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        'config': {
            'elements': 'dict',
            'options': {
                'policy_description': {'type': 'str'},
                'policy_name': {'required': True, 'type': 'str'},
                'policy_type': {
                    'choices': ['acl-copp', 'copp', 'forwarding', 'monitoring', 'qos'],
                    'type': 'str'
                },
                'sections': {
                    'elements': 'dict',
                    'options': {
                        'class': {'required': True, 'type': 'str'},
                        'acl_copp': {
                            'options': {
                                'cpu_queue_index': {'type': 'int'},
                                'policer': {
                                    'options': {
                                        'cbs': {'type': 'int'},
                                        'cir': {'type': 'int'},
                                        'pbs': {'type': 'int'},
                                        'pir': {'type': 'int'}
                                    },
                                    'type': 'dict'
                                }
                            },
                            'type': 'dict'
                        },
                        'forwarding': {
                            'options': {
                                'ars_disable': {'type': 'bool'},
                                'egress_interfaces': {
                                    'elements': 'dict',
                                    'options': {
                                        'intf_name': {'required': True, 'type': 'str'},
                                        'priority': {'type': 'int'}
                                    },
                                    'type': 'list'
                                },
                                'next_hops': {
                                    'elements': 'dict',
                                    'options': {
                                        'address': {'required': True, 'type': 'str'},
                                        'vrf': {'type': 'str'},
                                        'priority': {'type': 'int'}
                                    },
                                    'type': 'list'
                                },
                                'next_hop_groups': {
                                    'elements': 'dict',
                                    'options': {
                                        'group_name': {'required': True, 'type': 'str'},
                                        'group_type': {'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                                        'priority': {'type': 'int'}
                                    },
                                    'type': 'list'
                                },
                                'replication_groups': {
                                    'elements': 'dict',
                                    'options': {
                                        'group_name': {'required': True, 'type': 'str'},
                                        'group_type': {'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                                        'priority': {'type': 'int'}
                                    },
                                    'type': 'list'
                                }
                            },
                            'type': 'dict'
                        },
                        'mirror_sessions': {
                            'elements': 'dict',
                            'options': {
                                'session_name': {'required': True, 'type': 'str'}
                            },
                            'type': 'list'
                        },
                        'priority': {'type': 'int'},
                        'qos': {
                            'options': {
                                'output_queue_index': {'type': 'int'},
                                'policer': {
                                    'options': {
                                        'cbs': {'type': 'int'},
                                        'cir': {'type': 'int'},
                                        'pbs': {'type': 'int'},
                                        'pir': {'type': 'int'}
                                    },
                                    'type': 'dict'
                                },
                                'remark': {
                                    'options': {
                                        'set_dot1p': {'type': 'int'},
                                        'set_dscp': {'type': 'int'}
                                    },
                                    'type': 'dict'
                                }
                            },
                            'type': 'dict'
                        },
                        'section_description': {'type': 'str'}
                    },
                    'type': 'list'
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
