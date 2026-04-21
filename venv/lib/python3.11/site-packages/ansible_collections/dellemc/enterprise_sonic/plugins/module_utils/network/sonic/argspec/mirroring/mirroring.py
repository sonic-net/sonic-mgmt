#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The arg spec for the sonic_mirroring module
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class MirroringArgs(object):  # pylint: disable=R0903

    """The arg spec for the sonic_mirroring module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        "config": {
            "options": {
                "span": {
                    "elements": "dict",
                    "options": {
                        "name": {"required": True, "type": "str"},
                        "dst_port": {"type": "str"},
                        "source": {"type": "str"},
                        "direction": {"choices": ["rx", "tx", "both"],
                                      "type": "str"}
                    },
                    "type": "list"
                },
                "erspan": {
                    "elements": "dict",
                    "options": {
                        "name": {"required": True, "type": "str"},
                        "dst_ip": {"type": "str"},
                        "src_ip": {"type": "str"},
                        "source": {"type": "str"},
                        "direction": {"choices": ["rx", "tx", "both"],
                                      "type": "str"},
                        "dscp": {"type": "int"},
                        "gre": {"type": "str"},
                        "ttl": {"type": "int"},
                        "queue": {"type": "int"}
                    },
                    "type": "list"
                }
            },
            "type": "dict"
        },
        "state": {
            "choices": ["merged", "replaced", "overridden", "deleted"],
            "default": "merged",
            "type": "str"
        }
    }  # pylint: disable=C0301
