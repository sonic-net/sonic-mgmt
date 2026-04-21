from __future__ import absolute_import, division, print_function


__metaclass__ = type
import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


def get_ospf_type(afi):
    return "ospf" if afi == "ipv4" else "ospfv3"


def get_interface_type(name):
    return "GigabitEthernet" if name.startswith("GigabitEthernet") else "Loopback"


def _compute_command(cfg):
    ospf_type = get_ospf_type(cfg["address_family"]["afi"])
    type = get_interface_type(cfg["name"])
    area = cfg["address_family"]["processes"]["area"]
    pid = cfg["address_family"]["processes"]["process_id"]
    cmd = "router {0} {1} area {2} interface {3} {4}".format(
        ospf_type,
        pid,
        area["area_id"],
        type,
        cfg["name"].split(type)[1],
    )
    return cmd


def _tmplt_ospf_int_delete(config_data):
    ospf_type = get_ospf_type(config_data["afi"])
    type = get_interface_type(config_data["name"])
    area = config_data["area"]
    command = "router {0} {1} area {2} interface {3} {4}".format(
        ospf_type,
        config_data["process"],
        area["area_id"],
        type,
        config_data["name"].split(type)[1],
    )
    return command


def _tmplt_ospf_config(config_data):
    command = _compute_command(config_data)
    return command


def _tmplt_ospf_authentication_md_config(config_data):
    command = _compute_command(config_data)
    auth = config_data["address_family"]["authentication"]
    if auth["message_digest"].get("keychain"):
        command += " authentication message-digest keychain " + auth["message_digest"]["keychain"]
    return command


def _tmplt_ospf_authentication_md_set(config_data):
    command = _compute_command(config_data)
    auth = config_data["address_family"]["authentication"]
    if auth.get("message_digest") and auth["message_digest"].get("keychain"):
        command += " authentication message-digest"
    elif auth.get("null_auth"):
        command += " authentication null"
    return command


def _tmplt_ospf_authentication_key(config_data):
    command = _compute_command(config_data)
    auth = config_data["address_family"]["authentication_key"]
    if auth.get("password"):
        command += " authentication-key " + auth["password"]
    elif auth.get("encrypted"):
        command += " authentication-key encrypted " + auth["encrypted"]
    elif auth.get("clear"):
        command += " authentication-key clear " + auth["clear"]
    return command


def _tmplt_ospf_int_bfd_min_int(config_data):
    command = _compute_command(config_data)
    bfd = config_data["address_family"]["bfd"]
    if bfd.get("minimum_interval"):
        command += " bfd minimum-interval " + str(bfd["minimum_interval"])
    return command


def _tmplt_ospf_int_bfd_mult(config_data):
    command = _compute_command(config_data)
    bfd = config_data["address_family"]["bfd"]
    if bfd.get("multiplier"):
        command += " bfd multiplier " + str(bfd["multiplier"])
    return command


def _tmplt_ospf_int_bfd_fd(config_data):
    command = _compute_command(config_data)
    bfd = config_data["address_family"]["bfd"]
    if bfd.get("fast_detect") and bfd["fast_detect"].get("set"):
        command += " bfd fast-detect"
    elif bfd.get("fast_detect") and bfd["fast_detect"].get("disable"):
        command += " bfd fast-detect disable"
    elif bfd.get("fast_detect") and bfd["fast_detect"].get("strict_mode"):
        command += " bfd fast-detect strict-mode"
    return command


def _tmplt_ospf_cost_config(config_data):
    command = _compute_command(config_data)
    command += " cost " + str(config_data["address_family"]["cost"])
    return command


def _tmplt_ospf_cost_fallback_config(config_data):
    command = _compute_command(config_data)
    fallback = config_data["address_family"]["cost_fallback"]
    command += (
        " cost-fallback " + str(fallback["cost"]) + " threshold " + str(fallback["threshold"])
    )
    return command


def _tmplt_ospf_dead_int_config(config_data):
    command = _compute_command(config_data)
    command += " dead-interval " + str(
        config_data["address_family"]["dead_interval"],
    )
    return command


def _tmplt_ospf_demand_config(config_data):
    command = _compute_command(config_data)
    if config_data["address_family"]["demand_circuit"]:
        command += " demand-circuit enable"
    else:
        command += " demand-circuit disable"
    return command


class Ospf_interfacesTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(Ospf_interfacesTemplate, self).__init__(
            lines=lines,
            tmplt=self,
            module=module,
        )

    # fmt: off
    PARSERS = [
        {
            "name": "name",
            "getval": re.compile(
                r'''
                    ^router
                    \s(?P<ospf_type>ospf|ospfv3)
                    \s(?P<process_id>\S+)
                    \sarea\s(?P<area_id>\S+)
                    \sinterface\s(?P<name>\S+)
                    $''',
                re.VERBOSE,
            ),
            "remval": _tmplt_ospf_int_delete,
            "setval": _tmplt_ospf_config,
            "compval": "name",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                    },
                },
            },
            "shared": True,
        },
        {
            "name": "authentication.message_digest",
            "getval": re.compile(
                r"""
                ^router
                \s(?P<ospf_type>ospf|ospfv3)
                \s(?P<process_id>\S+)
                \sarea\s(?P<area_id>\S+)
                \sinterface\s(?P<name>\S+)
                \sauthentication(?P<authentication>)
                \s(?P<opt>message-digest)
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_authentication_md_set,
            "compval": "address_family.authentication.message_digest",
            "result": {
                "{{ name }}": {
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "authentication": {
                                "set": "{{ True if authentication is defined and opt is undefined }}",
                                "message_digest": {
                                    "set": "{{ True if opt == 'message-digest' else None }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "authentication.message_digest.keychain",
            "getval": re.compile(
                r"""
                ^router
                \s(?P<ospf_type>ospf|ospfv3)
                \s(?P<process_id>\S+)
                \sarea\s(?P<area_id>\S+)
                \sinterface\s(?P<name>\S+)
                \sauthentication(?P<authentication>)
                \s(?P<message_digest>message-digest)
                \skeychain\s(?P<keychain>\S+)$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_authentication_md_config,
            "compval": "address_family.authentication.message_digest.keychain",
            "result": {
                "{{ name }}": {
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "authentication": {
                                "message_digest": {
                                    "keychain": "{{ keychain }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "authentication.null_auth",
            "getval": re.compile(
                r"""
                ^router
                \s(?P<ospf_type>ospf|ospfv3)
                \s(?P<process_id>\S+)
                \sarea\s(?P<area_id>\S+)
                \sinterface\s(?P<name>\S+)
                \sauthentication(?P<authentication>)
                \s(?P<opt>null)
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_authentication_md_set,
            "compval": "address_family.authentication.null_auth",
            "result": {
                "{{ name }}": {
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "authentication": {
                                "set": "{{ True if authentication is defined and opt is undefined }}",
                                "null_auth": "{{ True if opt == 'null' else None }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "authentication_key",
            "getval": re.compile(
                r"""
                ^router
                \s(?P<ospf_type>ospf|ospfv3)
                \s(?P<process_id>\S+)
                \sarea\s(?P<area_id>\S+)
                \sinterface\s(?P<name>\S+)
                \sauthentication-key
                (\sencrypted\s(?P<encrypted>\S+))?
                (\s(?P<key>\S+))?
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_authentication_key,
            "compval": "address_family.authentication_key",
            "result": {
                "{{ name }}": {
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "authentication_key": {
                                "encrypted": "{{ encrypted }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bfd.minimum_interval",
            "getval": re.compile(
                r"""
                    ^router
                    \s(?P<ospf_type>ospf|ospfv3)
                    \s(?P<process_id>\S+)
                    \sarea\s(?P<area_id>\S+)
                    \sinterface\s(?P<name>\S+)
                    \sbfd(?P<bfd>)
                    \sminimum-interval\s(?P<minimum_interval>\d+)
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_int_bfd_min_int,
            "compval": "address_family.bfd.minimum_interval",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },

                                },
                            },
                            "bfd": {
                                "minimum_interval": "{{ minimum_interval|int }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bfd.multiplier",
            "getval": re.compile(
                r"""
                    ^router
                    \s(?P<ospf_type>ospf|ospfv3)
                    \s(?P<process_id>\S+)
                    \sarea\s(?P<area_id>\S+)
                    \sinterface\s(?P<name>\S+)
                    \sbfd(?P<bfd>)
                    \smultiplier\s(?P<multiplier>\d+)
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_int_bfd_mult,
            "compval": "address_family.bfd.multiplier",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },

                                },
                            },
                            "bfd": {
                                "multiplier": "{{ multiplier|int }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bfd.fast_detect.set",
            "getval": re.compile(
                r"""
                    ^router
                    \s(?P<ospf_type>ospf|ospfv3)
                    \s(?P<process_id>\S+)
                    \sarea\s(?P<area_id>\S+)
                    \sinterface\s(?P<name>\S+)
                    \sbfd(?P<bfd>)
                    \sfast-detect(?P<fast_detect>)
                    (\s(?P<opt>(disable|strict-mode)))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_int_bfd_fd,
            "compval": "address_family.bfd.fast_detect.set",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },

                                },
                            },
                            "bfd": {
                                "fast_detect": {
                                    "set": "{{ True if opt != 'disable' and opt != 'strict-mode' and fast_detect is defined else None }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bfd.fast_detect.disable",
            "getval": re.compile(
                r"""
                    ^router
                    \s(?P<ospf_type>ospf|ospfv3)
                    \s(?P<process_id>\S+)
                    \sarea\s(?P<area_id>\S+)
                    \sinterface\s(?P<name>\S+)
                    \sbfd(?P<bfd>)
                    \sfast-detect(?P<fast_detect>)
                    (\s(?P<opt>(disable|strict-mode)))?
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_int_bfd_fd,
            "compval": "address_family.bfd.fast_detect.disable",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },

                                },
                            },
                            "bfd": {
                                "fast_detect": {
                                    "disable": "{{ True if opt == 'disable' else None }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "bfd.fast_detect.strict_mode",
            "getval": re.compile(
                r"""
                    ^router
                    \s(?P<ospf_type>ospf|ospfv3)
                    \s(?P<process_id>\S+)
                    \sarea\s(?P<area_id>\S+)
                    \sinterface\s(?P<name>\S+)
                    \sbfd(?P<bfd>)
                    \sfast-detect(?P<fast_detect>)
                    \s(?P<opt>strict-mode)
                    $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_int_bfd_fd,
            "compval": "address_family.bfd.fast_detect.strict_mode",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "bfd": {
                                "fast_detect": {
                                    "strict_mode": "{{ True if opt == 'strict-mode' else None }}",
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "cost",
            "getval": re.compile(
                r"""
                   ^router
                   \s(?P<ospf_type>ospf|ospfv3)
                   \s(?P<process_id>\S+)
                   \sarea\s(?P<area_id>\S+)
                   \sinterface\s(?P<name>\S+)
                   \scost\s(?P<cost>\S+)$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_cost_config,
            "compval": "address_family.cost",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "cost": "{{ cost }}",
                        },
                    },
                },
            },
        },
        {
            "name": "cost_fallback",
            "getval": re.compile(
                r"""
                   ^router
                   \s(?P<ospf_type>ospf|ospfv3)
                   \s(?P<process_id>\S+)
                   \sarea\s(?P<area_id>\S+)
                   \sinterface\s(?P<name>\S+)
                   \scost-fallback\s(?P<cost>\S+)
                   \sthreshold\s(?P<threshold>\S+)
                   $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_cost_fallback_config,
            "compval": "address_family.cost_fallback",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "cost_fallback": {
                                "cost": "{{ cost }}",
                                "threshold": "{{ threshold }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "dead_interval",
            "getval": re.compile(
                r'''
                        ^router
                        \s(?P<ospf_type>ospf|ospfv3)
                        \s(?P<process_id>\S+)
                        \sarea\s(?P<area_id>\S+)
                        \sinterface\s(?P<name>\S+)
                        \sdead-interval\s(?P<dead_interval>\S+)
                        $''',
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_dead_int_config,
            "compval": "address_family.dead_interval",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "dead_interval": "{{ dead_interval }}",
                        },
                    },
                },
            },
        },
        {
            "name": "demand_circuit",
            "getval": re.compile(
                r'''
                            ^router
                            \s(?P<ospf_type>ospf|ospfv3)
                            \s(?P<process_id>\S+)
                            \sarea\s(?P<area_id>\S+)
                            \sinterface\s(?P<name>\S+)
                            \sdemand-circuit\s(?P<demand_circuit>\S+)
                            $''',
                re.VERBOSE,
            ),
            "setval": _tmplt_ospf_demand_config,
            "compval": "address_family.demand_circuit",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "demand_circuit": "{{ True if demand_circuit == 'enable' else False if demand_circuit == 'disable' else None }}",
                        },
                    },
                },
            },
        },
        {
            "name": "flood_reduction",
            "getval": re.compile(
                r'''
                                ^router
                                \s(?P<ospf_type>ospf|ospfv3)
                                \s(?P<process_id>\S+)
                                \sarea\s(?P<area_id>\S+)
                                \sinterface\s(?P<name>\S+)
                                \sflood-reduction\s(?P<flood_reduction>\S+)
                                $''',
                re.VERBOSE,
            ),
            "setval": "router {{ ospf_type }} {{ process_id }} area {{ area_id }} interface {{ type }} {{ name }} "
                      "flood-reduction {{ 'enable' if flood_reduction == True else 'disable' }}",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "flood_reduction": "{{ True if flood_reduction == 'enable' else False if flood_reduction == 'disable' else None }}",
                        },
                    },
                },
            },
        },
        {
            "name": "hello_interval",
            "getval": re.compile(
                r'''
                            ^router
                            \s(?P<ospf_type>ospf|ospfv3)
                            \s(?P<process_id>\S+)
                            \sarea\s(?P<area_id>\S+)
                            \sinterface\s(?P<name>\S+)
                            \shello-interval\s(?P<dead_interval>\S+)
                            $''',
                re.VERBOSE,
            ),
            "setval": "router {{ ospf_type }} {{ process_id }} area {{ area_id }} interface {{ type }} {{ name }} "
                      "hello-interval {{ hello_interval }}",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "hello_interval": "{{ hello_interval }}",
                        },
                    },
                },
            },
        },
        {
            "name": "link_down.set",
            "getval": re.compile(
                r'''
                                ^router
                                \s(?P<ospf_type>ospf|ospfv3)
                                \s(?P<process_id>\S+)
                                \sarea\s(?P<area_id>\S+)
                                \sinterface\s(?P<name>\S+)
                                \s(?P<link_down>link-down)
                                (\s(?P<disable>disable))?
                                $''',
                re.VERBOSE,
            ),
            "setval": "router {{ ospf_type }} {{ process_id }} area {{ area_id }} interface {{ type }} {{ name }} "
                      "link-down",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "link_down": {
                                "set": "{{ True if link_down is defined and disable is undefined else None}}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "link_down.disable",
            "getval": re.compile(
                r'''
                                    ^router
                                    \s(?P<ospf_type>ospf|ospfv3)
                                    \s(?P<process_id>\S+)
                                    \sarea\s(?P<area_id>\S+)
                                    \sinterface\s(?P<name>\S+)
                                    \s(?P<link_down>link-down)
                                    \s(?P<disable>disable)
                                    $''',
                re.VERBOSE,
            ),
            "setval": "router {{ ospf_type }} {{ process_id }} area {{ area_id }} interface {{ type }} {{ name }} "
                      "link-down disable",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "link_down": {
                                "disable": "{{ True if disable is defined else None }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "message_digest_key",
            "getval": re.compile(
                r"""
                ^router
                \s(?P<ospf_type>ospf|ospfv3)
                \s(?P<process_id>\S+)
                \sarea\s(?P<area_id>\S+)
                \sinterface\s(?P<name>\S+)
                \smessage-digest-key
                \s(?P<id>\d+)
                \smd5
                \s(?P<encryption>\d)
                \s(?P<key>\S+)$""",
                re.VERBOSE,
            ),
            "setval": "router {{ ospf_type }} {{ process_id }} area {{ area_id }} interface "
                      "{{ type }} {{ name }} #message-digest-key {{ message_digest_key.id }} "
                      "md5 encrypted {{ message_digest_key.encrypted}}",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "message_digest_key": {
                                "id": "{{ id }}",
                                "encrypted": "{{ encryption }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "mpls.set_ldp",
            "getval": re.compile(
                r'''
                                            ^router
                                            \s(?P<ospf_type>ospf|ospfv3)
                                            \s(?P<process_id>\S+)
                                            \sarea\s(?P<area_id>\S+)
                                            \sinterface\s(?P<name>\S+)
                                            \s(?P<mpls>mpls)
                                            \s(?P<ldp>set_ldp)
                                            (\s(?P<sync>sync))?
                                            $''',
                re.VERBOSE,
            ),
            "setval": "router {{ ospf_type }} {{ process_id }} area {{ area_id }} interface {{ type }} {{ name }} "
                      "mpls ldp",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "mpls": {
                                "set_ldp": "{{ True if set_ldp is defined and sync is undefined else None}}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "mpls.ldp_sync",
            "getval": re.compile(
                r'''
                                    ^router
                                    \s(?P<ospf_type>ospf|ospfv3)
                                    \s(?P<process_id>\S+)
                                    \sarea\s(?P<area_id>\S+)
                                    \sinterface\s(?P<name>\S+)
                                    \s(?P<mpls>mpls)
                                    \s(?P<ldp>ldp)
                                    \s(?P<sync>sync)
                                    (\s(?P<disable>disable))?
                                    $''',
                re.VERBOSE,
            ),
            "setval": "router {{ ospf_type }} {{ process_id }} area {{ area_id }} interface {{ type }} {{ name }} "
                      "mpls ldp sync",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "mpls": {
                                "ldp_sync": "{{ True if sync is defined and disable is undefined else None}}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "mpls.ldp_sync_disable",
            "getval": re.compile(
                r'''
                                        ^router
                                        \s(?P<ospf_type>ospf|ospfv3)
                                        \s(?P<process_id>\S+)
                                        \sarea\s(?P<area_id>\S+)
                                        \sinterface\s(?P<name>\S+)
                                        \s(?P<mpls>mpls)
                                        \s(?P<ldp>ldp)
                                        \s(?P<sync>sync)
                                        \s(?P<disable>disable)
                                        $''',
                re.VERBOSE,
            ),
            "setval": "router {{ ospf_type }} {{ process_id }} area {{ area_id }} interface {{ type }} {{ name }} "
                      "mpls ldp sync disable",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "mpls": {
                                "ldp_sync": "{{ False if disable is defined }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "mtu_ignore",
            "getval": re.compile(
                r'''
                                ^router
                                 \s(?P<ospf_type>ospf|ospfv3)
                                 \s(?P<process_id>\S+)
                                 \sarea\s(?P<area_id>\S+)
                                 \sinterface\s(?P<name>\S+)
                                 \smtu-ignore\s(?P<mtu_ignore>\S+)
                                $''',
                re.VERBOSE,
            ),
            "setval": "router {{ ospf_type }} {{ process_id }} area {{ area_id }} interface {{ type }} {{ name }} "
                      "mtu_ignore {{ 'enable' if mtu_ignore == 'True' else 'disable' if mtu_ignore == 'False' }}",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "mtu_ignore": "{{ True if mtu_ignore == 'enable' else False if mtu_ignore == 'disable' else None }}",
                        },
                    },
                },
            },
        },
        {
            "name": "network",
            "getval": re.compile(
                r'''
                                ^router
                                \s(?P<ospf_type>ospf|ospfv3)
                                \s(?P<process_id>\S+)
                                \sarea\s(?P<area_id>\S+)
                                \sinterface\s(?P<name>\S+)
                                \snetwork\s(?P<network>\S+)
                                 $''',
                re.VERBOSE,
            ),
            "setval": "router {{ ospf_type }} {{ process_id }} area {{ area_id }} interface {{ type }} {{ name }} "
                      "network {{ network }}",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "network": "{{ network }}",
                        },
                    },
                },
            },
        },
        {
            "name": "packet_size",
            "getval": re.compile(
                r'''
                                ^router
                                \s(?P<ospf_type>ospf|ospfv3)
                                \s(?P<process_id>\S+)
                                \sarea\s(?P<area_id>\S+)
                                \sinterface\s(?P<name>\S+)
                                \spacket-size\s(?P<packet_size>\S+)
                                $''',
                re.VERBOSE,
            ),
            "setval": "router {{ ospf_type }} {{ process_id }} area {{ area_id }} interface {{ type }} {{ name }} "
                      "packet-size {{ packet_size }}",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "packet_size": "{{ packet_size }}",
                        },
                    },
                },
            },
        },
        {
            "name": "passive",
            "getval": re.compile(
                r'''
                                    ^router
                                     \s(?P<ospf_type>ospf|ospfv3)
                                     \s(?P<process_id>\S+)
                                     \sarea\s(?P<area_id>\S+)
                                     \sinterface\s(?P<name>\S+)
                                     \spassive\s(?P<passive>\S+)
                                    $''',
                re.VERBOSE,
            ),
            "setval": "router {{ ospf_type }} {{ process_id }} area {{ area_id }} interface {{ type }} {{ name }} "
                      "passive {{ 'enable' if passive == 'True' else 'disable' if passive == 'False' }}",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "passive": "{{ True if passive == 'enable' else False if passive == 'disable' else None }}",
                        },
                    },
                },
            },
        },
        {
            "name": "prefix_suppression.disable",
            "getval": re.compile(
                r'''
                                        ^router
                                         \s(?P<ospf_type>ospf|ospfv3)
                                         \s(?P<process_id>\S+)
                                         \sarea\s(?P<area_id>\S+)
                                         \sinterface\s(?P<name>\S+)
                                         \sprefix-suppression\s(?P<prefix_suppression>\S+)
                                        $''',
                re.VERBOSE,
            ),
            "setval": "router {{ ospf_type }} {{ process_id }} area {{ area_id }} interface {{ type }} {{ name }} "
                      "prefix-suppression {{ prefix_suppression }}",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "prefix_suppression": {
                                "disable": "{{ True if prefix_suppression == 'disable' else None }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "prefix_suppression.secondary_address",
            "getval": re.compile(
                r'''
                                        ^router
                                         \s(?P<ospf_type>ospf|ospfv3)
                                         \s(?P<process_id>\S+)
                                         \sarea\s(?P<area_id>\S+)
                                         \sinterface\s(?P<name>\S+)
                                         \s(?P<prefix_suppression>prefix-suppression)
                                         \s(?P<secondary_address>secondary-address)
                                         (\s(?P<disable>disable))?
                                        $''',
                re.VERBOSE,
            ),
            "setval": "router {{ ospf_type }} {{ process_id }} area {{ area_id }} interface {{ type }} {{ name }} "
                      "prefix-suppression secondary-address {{ disable if secondary_address is False }}",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "prefix_suppression": {
                                "secondary_address": "{{ True if  secondary_address is defined and "
                                                     "disable is undefined else False if disable is defined else None }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "priority",
            "getval": re.compile(
                r'''
                                        ^router
                                        \s(?P<ospf_type>ospf|ospfv3)
                                        \s(?P<process_id>\S+)
                                        \sarea\s(?P<area_id>\S+)
                                        \sinterface\s(?P<name>\S+)
                                        \spriority\s(?P<priority>\d+)
                                        $''',
                re.VERBOSE,
            ),
            "setval": "router {{ ospf_type }} {{ process_id }} area {{ area_id }} interface {{ type }} {{ name }} "
                      "priority {{ priority }}",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "priority": "{{ priority|int }}",
                        },
                    },
                },
            },
        },
        {
            "name": "retransmit_interval",
            "getval": re.compile(
                r'''
                                        ^router
                                        \s(?P<ospf_type>ospf|ospfv3)
                                        \s(?P<process_id>\S+)
                                        \sarea\s(?P<area_id>\S+)
                                        \sinterface\s(?P<name>\S+)
                                        \sretransmit-interval\s(?P<retransmit_interval>\d+)
                                        $''',
                re.VERBOSE,
            ),
            "setval": "router {{ ospf_type }} {{ process_id }} area {{ area_id }} interface {{ type }} {{ name }} "
                      "retransmit-interval {{ retransmit_interval }}",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "retransmit_interval": "{{ retransmit_interval|int }}",
                        },
                    },
                },
            },
        },
        {
            "name": "security.ttl_hops",
            "getval": re.compile(
                r'''
                                            ^router
                                             \s(?P<ospf_type>ospf|ospfv3)
                                             \s(?P<process_id>\S+)
                                             \sarea\s(?P<area_id>\S+)
                                             \sinterface\s(?P<name>\S+)
                                             \s(?P<security>security)
                                             \s(?P<ttl>ttl)
                                             \shops\s(?P<hops>\d+)
                                            $''',
                re.VERBOSE,
            ),
            "setval": "router {{ ospf_type }} {{ process_id }} area {{ area_id }} interface {{ type }} {{ name }} "
                      "security ttl hops {{ hops }}",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "security_ttl": {
                                "hops": "{{ hops|int }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "security.ttl",
            "getval": re.compile(
                r'''
                                                ^router
                                                 \s(?P<ospf_type>ospf|ospfv3)
                                                 \s(?P<process_id>\S+)
                                                 \sarea\s(?P<area_id>\S+)
                                                 \sinterface\s(?P<name>\S+)
                                                 \s(?P<security>security)
                                                 \s(?P<ttl>ttl)
                                                 (\s(?P<hops>hops))?
                                                $''',
                re.VERBOSE,
            ),
            "setval": "router {{ ospf_type }} {{ process_id }} area {{ area_id }} interface {{ type }} {{ name }} "
                      "security ttl",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "security_ttl": {
                                "set": "{{ True if ttl is defined and hops is undefined }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "transmit_delay",
            "getval": re.compile(
                r'''
                                    ^router
                                    \s(?P<ospf_type>ospf|ospfv3)
                                    \s(?P<process_id>\S+)
                                    \sarea\s(?P<area_id>\S+)
                                    \sinterface\s(?P<name>\S+)
                                    \stransmit-delay\s(?P<transmit_delay>\d+)
                                    $''',
                re.VERBOSE,
            ),
            "setval": "router {{ ospf_type }} {{ process_id }} area {{ area_id }} interface {{ type }} {{ name }} "
                      "transmit-delay {{ transmit_delay }}",
            "result": {
                "{{ name }}": {
                    "name": "{{ name }}",
                    "type": "{{ 'gigabitethernet' if 'GigabitEthernet' in name else 'loopback' if 'Loopback' in name }}",
                    "address_family": {
                        "{{ ospf_type }}": {
                            "afi": "{{ 'ipv4' if ospf_type == 'ospf' else 'ipv6' }}",
                            "processes": {
                                "{{ process_id }}": {
                                    "process_id": "{{ process_id }}",
                                    "area": {
                                        "area_id": "{{ area_id }}",
                                    },
                                },
                            },
                            "transmit_delay": "{{ transmit_delay|int }}",
                        },
                    },
                },
            },
        },
    ]
    # fmt: on
