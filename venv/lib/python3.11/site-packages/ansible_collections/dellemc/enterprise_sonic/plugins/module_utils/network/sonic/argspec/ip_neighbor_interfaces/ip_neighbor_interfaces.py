#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The arg spec for the sonic_ip_neighbor_interfaces module
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class Ip_neighbor_interfacesArgs(object):  # pylint: disable=R0903
    """The arg spec for the sonic_ip_neighbor_interfaces module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        "config": {
            "elements": "dict",
            "options": {
                "ipv4_neighbors": {
                    "elements": "dict",
                    "options": {
                        "ip": {"required": True, "type": "str"},
                        "mac": {"type": "str"}
                    },
                    "type": "list"
                },
                "ipv6_neighbors": {
                    "elements": "dict",
                    "options": {
                        "ip": {"required": True, "type": "str"},
                        "mac": {"type": "str"}
                    },
                    "type": "list"
                },
                "name": {"required": True, "type": "str"}
            },
            "type": "list"
        },
        "state": {
            "choices": ["merged", "deleted", "replaced", "overridden"],
            "default": "merged",
            "type": "str"
        }
    }  # pylint: disable=C0301
