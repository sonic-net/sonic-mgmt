# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

"""
The Ospf_interfaces parser templates file. This contains
a list of parser definitions and associated functions that
facilitates both facts gathering and native command generation for
the given network resource.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


def _get_parameters(data):
    if data["afi"] == "ipv6":
        val = ["ospfv3", "ipv6"]
    else:
        val = ["ospf", "ip"]
    return val


def _tmplt_ospf_int_delete(config_data):
    params = _get_parameters(config_data["address_family"])
    command = (
        "protocols " + params[0] + " interface {name}".format(**config_data)
    )

    return command


def _tmplt_ospf_int_cost(config_data):
    params = _get_parameters(config_data["address_family"])
    command = (
        "protocols "
        + params[0]
        + " interface {name}".format(**config_data)
        + " cost {cost}".format(**config_data["address_family"])
    )

    return command


def _tmplt_ospf_int_auth_password(config_data):
    params = _get_parameters(config_data["address_family"])
    command = (
        "protocols "
        + params[0]
        + " interface {name}".format(**config_data)
        + " authentication plaintext-password {plaintext_password}".format(
            **config_data["address_family"]["authentication"]
        )
    )
    return command


def _tmplt_ospf_int_auth_md5(config_data):
    params = _get_parameters(config_data["address_family"])
    command = (
        "protocols "
        + params[0]
        + " interface {name}".format(**config_data)
        + " authentication md5 key-id {key_id} ".format(
            **config_data["address_family"]["authentication"]["md5_key"]
        )
        + "md5-key {key}".format(**config_data["address_family"]["authentication"]["md5_key"])
    )

    return command


def _tmplt_ospf_int_auth_md5_delete(config_data):
    params = _get_parameters(config_data["address_family"])
    command = (
        "protocols "
        + params[0]
        + " interface {name}".format(**config_data)
        + " authentication"
    )

    return command


def _tmplt_ospf_int_bw(config_data):
    params = _get_parameters(config_data["address_family"])
    command = (
        "protocols "
        + params[0]
        + " interface {name}".format(**config_data)
        + " bandwidth {bandwidth}".format(**config_data["address_family"])
    )

    return command


def _tmplt_ospf_int_hello_interval(config_data):
    params = _get_parameters(config_data["address_family"])
    command = (
        "protocols "
        + params[0]
        + " interface {name}".format(**config_data)
        + " hello-interval {hello_interval}".format(**config_data["address_family"])
    )

    return command


def _tmplt_ospf_int_dead_interval(config_data):
    params = _get_parameters(config_data["address_family"])
    command = (
        "protocols "
        + params[0]
        + " interface {name}".format(**config_data)
        + " dead-interval {dead_interval}".format(**config_data["address_family"])
    )

    return command


def _tmplt_ospf_int_mtu_ignore(config_data):
    params = _get_parameters(config_data["address_family"])
    command = (
        "protocols "
        + params[0]
        + " interface {name}".format(**config_data)
        + " mtu-ignore"
    )

    return command


def _tmplt_ospf_int_network(config_data):
    params = _get_parameters(config_data["address_family"])
    command = (
        "protocols "
        + params[0]
        + " interface {name}".format(**config_data)
        + " network {network}".format(**config_data["address_family"])
    )

    return command


def _tmplt_ospf_int_priority(config_data):
    params = _get_parameters(config_data["address_family"])
    command = (
        "protocols "
        + params[0]
        + " interface {name}".format(**config_data)
        + " priority {priority}".format(**config_data["address_family"])
    )

    return command


def _tmplt_ospf_int_retransmit_interval(config_data):
    params = _get_parameters(config_data["address_family"])
    command = (
        "protocols "
        + params[0]
        + " interface {name}".format(**config_data)
        + " retransmit-interval {retransmit_interval}".format(**config_data["address_family"])
    )

    return command


def _tmplt_ospf_int_transmit_delay(config_data):
    params = _get_parameters(config_data["address_family"])
    command = (
        "protocols "
        + params[0]
        + " interface {name}".format(**config_data)
        + " transmit-delay {transmit_delay}".format(**config_data["address_family"])
    )

    return command


def _tmplt_ospf_int_ifmtu(config_data):
    params = _get_parameters(config_data["address_family"])
    command = (
        "protocols "
        + params[0]
        + " interface {name}".format(**config_data)
        + " ifmtu {ifmtu}".format(**config_data["address_family"])
    )

    return command


def _tmplt_ospf_int_instance(config_data):
    params = _get_parameters(config_data["address_family"])
    command = (
        "protocols "
        + params[0]
        + " interface {name}".format(**config_data)
        + " instance-id {instance}".format(**config_data["address_family"])
    )

    return command


def _tmplt_ospf_int_passive(config_data):
    params = _get_parameters(config_data["address_family"])
    command = (
        "protocols "
        + params[0]
        + " interface {name}".format(**config_data)
        + " passive"
    )

    return command


class Ospf_interfacesTemplate14(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        prefix = {"set": "set", "remove": "delete"}
        super(Ospf_interfacesTemplate14, self).__init__(
            lines=lines, tmplt=self, prefix=prefix, module=module
        )

    # fmt: off
    PARSERS = [
        {
            "name": "ip_ospf",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+(?P<proto>ospf|ospfv3)
                \s+interface
                \s+(?P<name>\S+)
                *$""",
                re.VERBOSE,
            ),
            "remval": _tmplt_ospf_int_delete,
            "compval": "address_family",
            "result": {
                "name": "{{ name }}",
                "address_family": {
                    '{{ "ipv4" if proto == "ospf" else "ipv6" }}': {
                        "afi": '{{ "ipv4" if proto == "ospf" else "ipv6" }}',
                    }
                }
            }
        },
        {
            "name": "authentication_password",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+(?P<proto>ospf|ospfv3)
                \s+interface
                \s+(?P<name>\S+)
                \s+authentication
                \s+plaintext-password
                \s+(?P<text>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_int_auth_password,
            "compval": "address_family.authentication",
            "result": {
                "name": "{{ name }}",
                "address_family": {
                    '{{ "ipv4" if proto == "ospf" else "ipv6" }}': {
                        "afi": '{{ "ipv4" if proto == "ospf" else "ipv6" }}',
                        "authentication": {
                            "plaintext_password": "{{ text }}"
                        }
                    }
                }
            }
        },
        {
            "name": "authentication_md5",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+(?P<proto>ospf|ospfv3)
                \s+interface
                \s+(?P<name>\S+)
                \s+authentication
                \s+md5
                \s+key-id
                \s+(?P<id>\d+)
                \s+md5-key
                \s+(?P<text>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_int_auth_md5,
            "remval": _tmplt_ospf_int_auth_md5_delete,
            "compval": "address_family.authentication",
            "result": {
                "name": "{{ name }}",
                "address_family": {
                    '{{ "ipv4" if proto == "ospf" else "ipv6" }}': {
                        "afi": '{{ "ipv4" if proto == "ospf" else "ipv6" }}',
                        "authentication": {
                            "md5_key": {
                                "key_id": "{{ id }}",
                                "key": "{{ text }}"
                            }
                        }
                    }
                }
            }
        },
        {
            "name": "bandwidth",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+(?P<proto>ospf|ospfv3)
                \s+interface
                \s+(?P<name>\S+)
                \s+bandwidth
                \s+(?P<bw>\'\d+\')
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_int_bw,
            "compval": "address_family.bandwidth",
            "result": {
                "name": "{{ name }}",
                "address_family": {
                    '{{ "ipv4" if proto == "ospf" else "ipv6" }}': {
                        "afi": '{{ "ipv4" if proto == "ospf" else "ipv6" }}',
                        "bandwidth": "{{ bw }}"
                    }
                }
            }
        },
        {
            "name": "cost",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+(?P<proto>ospf|ospfv3)
                \s+interface
                \s+(?P<name>\S+)
                \s+cost
                \s+(?P<val>\'\d+\')
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_int_cost,
            "compval": "address_family.cost",
            "result": {
                "name": "{{ name }}",
                "address_family": {
                    '{{ "ipv4" if proto == "ospf" else "ipv6" }}': {
                        "afi": '{{ "ipv4" if proto == "ospf" else "ipv6" }}',
                        "cost": "{{ val }}"
                    }
                }
            }
        },
        {
            "name": "hello_interval",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+(?P<proto>ospf|ospfv3)
                \s+interface
                \s+(?P<name>\S+)
                \s+hello-interval
                \s+(?P<val>\'\d+\')
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_int_hello_interval,
            "compval": "address_family.hello_interval",
            "result": {
                "name": "{{ name }}",
                "address_family": {
                    '{{ "ipv4" if proto == "ospf" else "ipv6" }}': {
                        "afi": '{{ "ipv4" if proto == "ospf" else "ipv6" }}',
                        "hello_interval": "{{ val }}"
                    }
                }
            }
        },
        {
            "name": "dead_interval",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+(?P<proto>ospf|ospfv3)
                \s+interface
                \s+(?P<name>\S+)
                \s+dead-interval
                \s+(?P<val>\'\d+\')
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_int_dead_interval,
            "compval": "address_family.dead_interval",
            "result": {
                "name": "{{ name }}",
                "address_family": {
                    '{{ "ipv4" if proto == "ospf" else "ipv6" }}': {
                        "afi": '{{ "ipv4" if proto == "ospf" else "ipv6" }}',
                        "dead_interval": "{{ val }}"
                    }
                }
            }
        },
        {
            "name": "mtu_ignore",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+(?P<proto>ospf|ospfv3)
                \s+interface
                \s+(?P<name>\S+)
                \s+(?P<mtu>mtu-ignore)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_int_mtu_ignore,
            "compval": "address_family.mtu_ignore",
            "result": {
                "name": "{{ name }}",
                "address_family": {
                    '{{ "ipv4" if proto == "ospf" else "ipv6" }}': {
                        "afi": '{{ "ipv4" if proto == "ospf" else "ipv6" }}',
                        "mtu_ignore": "{{ True if mtu is defined }}"
                    }
                }
            }
        },
        {
            "name": "network",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+(?P<proto>ospf|ospfv3)
                \s+interface
                \s+(?P<name>\S+)
                \s+network
                \s+(?P<val>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_int_network,
            "compval": "address_family.network",
            "result": {
                "name": "{{ name }}",
                "address_family": {
                    '{{ "ipv4" if proto == "ospf" else "ipv6" }}': {
                        "afi": '{{ "ipv4" if proto == "ospf" else "ipv6" }}',
                        "network": "{{ val }}"
                    }
                }
            }
        },
        {
            "name": "priority",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+(?P<proto>ospf|ospfv3)
                \s+interface
                \s+(?P<name>\S+)
                \s+priority
                \s+(?P<val>\'\d+\')
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_int_priority,
            "compval": "address_family.priority",
            "result": {
                "name": "{{ name }}",
                "address_family": {
                    '{{ "ipv4" if proto == "ospf" else "ipv6" }}': {
                        "afi": '{{ "ipv4" if proto == "ospf" else "ipv6" }}',
                        "priority": "{{ val }}"
                    }
                }
            }
        },
        {
            "name": "retransmit_interval",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+(?P<proto>ospf|ospfv3)
                \s+interface
                \s+(?P<name>\S+)
                \s+retransmit-interval
                \s+(?P<val>\'\d+\')
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_int_retransmit_interval,
            "compval": "address_family.retransmit_interval",
            "result": {
                "name": "{{ name }}",
                "address_family": {
                    '{{ "ipv4" if proto == "ospf" else "ipv6" }}': {
                        "afi": '{{ "ipv4" if proto == "ospf" else "ipv6" }}',
                        "retransmit_interval": "{{ val }}"
                    }
                }
            }
        },
        {
            "name": "transmit_delay",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+(?P<proto>ospf|ospfv3)
                \s+interface
                \s+(?P<name>\S+)
                \s+transmit-delay
                \s+(?P<val>\'\d+\')
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_int_transmit_delay,
            "compval": "address_family.transmit_delay",
            "result": {
                "name": "{{ name }}",
                "address_family": {
                    '{{ "ipv4" if proto == "ospf" else "ipv6" }}': {
                        "afi": '{{ "ipv4" if proto == "ospf" else "ipv6" }}',
                        "transmit_delay": "{{ val }}"
                    }
                }
            }
        },
        {
            "name": "ifmtu",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+(?P<proto>ospf|ospfv3)
                \s+interface
                \s+(?P<name>\S+)
                \s+ifmtu
                \s+(?P<val>\'\d+\')
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_int_ifmtu,
            "compval": "address_family.ifmtu",
            "result": {
                "name": "{{ name }}",
                "address_family": {
                    '{{ "ipv4" if proto == "ospf" else "ipv6" }}': {
                        "afi": '{{ "ipv4" if proto == "ospf" else "ipv6" }}',
                        "ifmtu": "{{ val }}"
                    }
                }
            }
        },
        {
            "name": "instance",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+(?P<proto>ospf|ospfv3)
                \s+interface
                \s+(?P<name>\S+)
                \s+instance-id
                \s+(?P<val>\'\d+\')
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_int_instance,
            "compval": "address_family.instance",
            "result": {
                "name": "{{ name }}",
                "address_family": {
                    '{{ "ipv4" if proto == "ospf" else "ipv6" }}': {
                        "afi": '{{ "ipv4" if proto == "ospf" else "ipv6" }}',
                        "instance": "{{ val }}"
                    }
                }
            }
        },
        {
            "name": "passive",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+(?P<proto>ospf|ospfv3)
                \s+interface
                \s+(?P<name>\S+)
                \s+(?P<pass>passive)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_int_passive,
            "compval": "address_family.passive",
            "result": {
                "name": "{{ name }}",
                "address_family": {
                    '{{ "ipv4" if proto == "ospf" else "ipv6" }}': {
                        "afi": '{{ "ipv4" if proto == "ospf" else "ipv6" }}',
                        "passive": "{{ True if pass is defined }}"
                    }
                }
            }
        },
        {
            "name": "interface_name",
            "getval": re.compile(
                r"""
                ^set
                \s+protocols
                \s+(?P<proto>ospf|ospfv3)
                \s+interface
                \s+(?P<name>\S+)
                .*$""",
                re.VERBOSE,
            ),
            "setval": "set protocols {{ proto }} interface {{ name }}",
            "result": {
                "name": "{{ name }}",
            }
        },
    ]
    # fmt: on
