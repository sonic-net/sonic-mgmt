#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The arg spec for the sonic_ecmp_load_share module
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class Ecmp_load_shareArgs(object):  # pylint: disable=R0903

    """The arg spec for the sonic_ecmp_load_share module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        "config": {
            "options": {
                "hash_algorithm": {
                    "type": "str",
                    "choices": ["CRC",
                                "XOR",
                                "CRC_32LO",
                                "CRC_32HI",
                                "CRC_CCITT",
                                "CRC_XOR",
                                "JENKINS_HASH_LO",
                                "JENKINS_HASH_HI"]},
                "hash_ingress_port": {"type": "bool"},
                "hash_offset": {
                    "options": {
                        "offset": {"type": "int"},
                        "flow_based": {"type": "bool"}
                    },
                    "type": "dict"
                },
                "hash_roce_qpn": {"type": "bool"},
                "hash_seed": {"type": "int"},
                "ipv4": {
                    "options": {
                        "ipv4_dst_ip": {"type": "bool"},
                        "ipv4_src_ip": {"type": "bool"},
                        "ipv4_ip_proto": {"type": "bool"},
                        "ipv4_l4_dst_port": {"type": "bool"},
                        "ipv4_l4_src_port": {"type": "bool"},
                        "ipv4_symmetric": {"type": "bool"}
                    },
                    "type": "dict"
                },
                "ipv6": {
                    "options": {
                        "ipv6_dst_ip": {"type": "bool"},
                        "ipv6_src_ip": {"type": "bool"},
                        "ipv6_next_hdr": {"type": "bool"},
                        "ipv6_l4_dst_port": {"type": "bool"},
                        "ipv6_l4_src_port": {"type": "bool"},
                        "ipv6_symmetric": {"type": "bool"}
                    },
                    "type": "dict"
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
