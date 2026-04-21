#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The arg spec for the sonic_ssh_server module
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class Ssh_serverArgs(object):  # pylint: disable=R0903
    """The arg spec for the sonic_ssh_server module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        'config': {
            'options': {
                'server_globals': {
                    'options': {
                        'password_authentication': {
                            'type': 'bool'
                        },
                        'publickey_authentication': {
                            'type': 'bool'
                        },
                        'max_auth_retries': {
                            'type': 'int'
                        },
                        'disable_forwarding': {
                            'type': 'bool'
                        },
                        'permit_root_login': {
                            'type': 'bool'
                        },
                        'permit_user_rc': {
                            'type': 'bool'
                        },
                        'x11_forwarding': {
                            'type': 'bool'
                        },
                        'permit_user_environment': {
                            'type': 'bool'
                        },
                        'ciphers': {
                            'type': 'str'
                        },
                        'macs': {
                            'type': 'str'
                        },
                        'kexalgorithms': {
                            'type': 'str'
                        },
                        'hostkeyalgorithms': {
                            'type': 'str', 'no_log': False,
                        }
                    },
                    'type': 'dict'
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
