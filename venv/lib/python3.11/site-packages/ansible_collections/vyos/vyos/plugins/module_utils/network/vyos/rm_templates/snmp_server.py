# -*- coding: utf-8 -*-
# Copyright 2022 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The Snmp_server parser templates file. This contains
a list of parser definitions and associated functions that
facilitates both facts gathering and native command generation for
the given network resource.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


def _tmplt_snmp_server_communities(config_data):
    config_data = config_data["communities"]
    command = []
    cmd = "service snmp community {name}".format(**config_data)
    if "authorization_type" in config_data:
        auth_cmd = cmd + " authorization {authorization_type}".format(**config_data)
        command.append(auth_cmd)
    if "clients" in config_data:
        for c in config_data["clients"]:
            client_cmd = cmd + " client " + c
            command.append(client_cmd)
    if "networks" in config_data:
        for n in config_data["networks"]:
            network_command = cmd + " network " + n
            command.append(network_command)
    if not command:
        command.append(cmd)
    return command


def _tmplt_snmp_server_trap_target(config_data):
    config_data = config_data["trap_target"]
    command = "service snmp trap-target {address}".format(**config_data)
    if "authorization_type" in config_data:
        command += " authorization {authorization_type}".format(**config_data)
    if "client" in config_data:
        command += " client {client}".format(**config_data)
    if "network" in config_data:
        command += " network {network}".format(**config_data)
    return command


def _tmplt_snmp_server_v3_groups(config_data):
    config_data = config_data["snmp_v3"]["groups"]
    command = []
    cmd = "service snmp v3 group {group}".format(**config_data)
    if "mode" in config_data:
        mode_cmd = cmd + " mode {mode}".format(**config_data)
        command.append(mode_cmd)
    if "seclevel" in config_data:
        sec_cmd = cmd + " seclevel {seclevel}".format(**config_data)
        command.append(sec_cmd)
    if "view" in config_data:
        view_cmd = cmd + " view {view}".format(**config_data)
        command.append(view_cmd)
    return command


def _tmplt_snmp_server_v3_trap_target(config_data):
    config_data = config_data["snmp_v3"]["trap_targets"]
    command = "service snmp v3 trap-target {address} ".format(**config_data)
    if "authentication" in config_data:
        command += " auth"
        config_data = config_data["authentication"]
    if "privacy" in config_data:
        command += " privacy"
        config_data = config_data["privacy"]
    if "type" in config_data:
        command += " type {mode}".format(**config_data)
    if "encrypted_key" in config_data:
        command += " encrypted-password {encrypted_key}".format(**config_data)
    if "plaintext_key" in config_data:
        command += " plaintext-password {plaintext_key}".format(**config_data)
    return command


def _tmplt_snmp_server_v3_user(config_data):
    config_data = config_data["snmp_v3"]["users"]
    command = []
    cmd = "service snmp v3 user {user}".format(**config_data)
    for k in ["authentication", "privacy"]:
        if config_data.get(k):
            config = config_data[k]
            if k == "authentication":
                val = " auth"
            else:
                val = " privacy"
            if "type" in config:
                type_cmd = cmd + val + " type {type}".format(**config)
                command.append(type_cmd)
            if "encrypted_key" in config:
                enc_cmd = cmd + val + " encrypted-password {encrypted_key}".format(**config)
                command.append(enc_cmd)
            if "plaintext_key" in config:
                plain_cmd = cmd + val + " plaintext-password {plaintext_key}".format(**config)
                command.append(plain_cmd)
    return command


def _tmplt_snmp_server_v3_views(config_data):
    config_data = config_data["snmp_v3"]["views"]
    command = "service snmp v3 view {view} oid {oid}".format(**config_data)
    if "exclude" in config_data:
        command += " exclude {exclude}".format(**config_data)
    if "mask" in config_data:
        command += " mask {mask}".format(**config_data)
    return command


class Snmp_serverTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        prefix = {"set": "set", "remove": "delete"}
        super(Snmp_serverTemplate, self).__init__(
            lines=lines,
            tmplt=self,
            prefix=prefix,
            module=module,
        )

    # fmt: off
    PARSERS = [
        # service snmp community <>
        {
            "name": "communities",
            "getval": re.compile(
                r"""
                ^set\sservice\ssnmp\scommunity
                \s+(?P<name>\S+)
                \s*(?P<auth>authorization\srw|authorization\sro)*
                \s*(client\s(?P<client>\S+))*
                \s*(network\s(?P<network>\S+))*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_communities,
            "result": {
                "communities": {
                    "{{ name }}": {
                        "name": "{{ name }}",
                        "clients": ['{{ client if client is defined else "None" }}'],
                        "networks": ['{{ network if network is defined else "None" }}'],
                        "authorization_type": '{{ auth.split(" ")[1] if auth is defined else None }}',
                    },
                },
            },
        },
        # service snmp contact <>
        {
            "name": "contact",
            "getval": re.compile(
                r"""
                ^set\sservice\ssnmp\scontact
                \s+(?P<name>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "service snmp contact {{ contact }}",
            "result": {
                "contact": "{{ name }}",
            },
        },
        # service snmp description <>
        {
            "name": "description",
            "getval": re.compile(
                r"""
                ^set\sservice\ssnmp\sdescription
                \s+(?P<name>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "service snmp description {{ description }}",
            "result": {
                "description": "{{ name }}",
            },
        },
        # service snmp listen-address <> port <>
        {
            "name": "listen_addresses",
            "getval": re.compile(
                r"""
                ^set\sservice\ssnmp\slisten-address
                \s+(?P<addr>\S+)
                \s*(port)*
                \s*(?P<port>\d+)*
                $""",
                re.VERBOSE,
            ),
            "setval": "service snmp listen-address {{ listen_addresses.address }}"
                      "{{ (' port ' + listen_addresses.port|string) if listen_addresses.port is defined else '' }}",
            "result": {
                "listen_addresses": {
                    "{{ addr }}": {
                        "address": "{{ addr }}",
                        "port": "{{ port }}",
                    },
                },
            },
        },
        # service snmp location <>
        {
            "name": "location",
            "getval": re.compile(
                r"""
                ^set\sservice\ssnmp\slocation
                \s(?P<name>.*)
                $""",
                re.VERBOSE,
            ),
            "setval": "service snmp location {{ '\\'' + location + '\\''}}",
            "result": {
                "location": "{{ name }}",
            },
        },
        # service snmp smux-peer <>
        {
            "name": "smux_peer",
            "getval": re.compile(
                r"""
                ^set\sservice\ssnmp\ssmux-peer
                \s+(?P<name>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "service snmp smux-peer {{ smux_peer }}",
            "result": {
                "smux_peer": "{{ name }}",
            },
        },
        # service snmp trap-source <>
        {
            "name": "trap_source",
            "getval": re.compile(
                r"""
                ^set\sservice\ssnmp\strap-source
                \s+(?P<name>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "service snmp trap-source {{ trap_source }}",
            "result": {
                "trap_source": "{{ name }}",
            },
        },
        # service snmp trap-target <>
        {
            "name": "trap_target",
            "getval": re.compile(
                r"""
                ^set\sservice\ssnmp\strap-target
                \s+(?P<name>\S+)
                \s*(?P<comm>community\s\S+)*
                \s*(?P<port>port\s\d+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_trap_target,
            "result": {
                "trap_target": {
                    "address": "{{ name }}",
                    "community": "{{ comm.split(" ")[1] if comm is defined else None }}",
                    "port": "{{ port.split(" ")[1] if port is defined else None }}",
                },
            },
        },
        # service snmp v3 engineid <>
        {
            "name": "snmp_v3.engine_id",
            "getval": re.compile(
                r"""
                ^set\sservice\ssnmp\sv3\sengineid
                \s+(?P<name>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "service snmp v3 engineid {{ snmp_v3.engine_id }}",
            "result": {
                "snmp_v3": {
                    "engine_id": "{{ name }}",
                },
            },
        },
        # service snmp v3 group <>
        {
            "name": "snmp_v3.groups",
            "getval": re.compile(
                r"""
                ^set\sservice\ssnmp\sv3\sgroup
                \s+(?P<name>\S+)
                \s*(?P<mode>mode\s\S+)*
                \s*(?P<sec>seclevel\s\S+)*
                \s*(?P<view>view\s\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_v3_groups,
            "result": {
                "snmp_v3": {
                    "groups": {
                        "{{ name }}": {
                            "group": "{{ name }}",
                            "mode": '{{ mode.split(" ")[1] if mode is defined else None }}',
                            "seclevel": '{{ sec.split(" ")[1] if sec is defined else None }}',
                            "view": '{{ view.split(" ")[1] if view is defined else None }}',
                        },
                    },
                },
            },
        },
        # service snmp v3 trap-target <> auth <>
        {
            "name": "snmp_v3.trap_targets.authentication",
            "getval": re.compile(
                r"""
                ^set\sservice\ssnmp\sv3\strap-target
                \s+(?P<name>\S+)
                \s+auth
                \s*(?P<enc>encrypted-password\s\S+)*
                \s*(?P<plain>plaintext-password\s\S+)*
                \s*(?P<type>type\s\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_v3_trap_target,
            "result": {
                "snmp_v3": {
                    "trap_targets": {
                        "{{ name }}": {
                            "address": "{{ name }}",
                            "authentication": {
                                "encrypted_key": '{{ enc.split(" ")[1] if enc is defined else None }}',
                                "plaintext_key": '{{ plain.split(" ")[1] if plain is defined else None }}',
                                "type": '{{ type.split(" ")[1] if type is defined else None }}',
                            },
                        },
                    },
                },
            },
        },
        # service snmp v3 trap-target <> port <>
        {
            "name": "snmp_v3.trap_targets.port",
            "getval": re.compile(
                r"""
                ^set\sservice\ssnmp\sv3\strap-target
                \s+(?P<name>\S+)
                \s+(?P<port>port\s\d+)*
                $""",
                re.VERBOSE,
            ),
            "setval": "service snmp v3 trap-target port {{ snmp_v3.trap_targets.port }}",
            "result": {
                "snmp_v3": {
                    "trap_targets": {
                        "{{ name }}": {
                            "address": "{{ name }}",
                            "port": "{{ port }}",
                        },
                    },
                },
            },
        },
        # service snmp v3 trap-target <> protocol <>
        {
            "name": "snmp_v3.trap_targets.protocol",
            "getval": re.compile(
                r"""
                ^set\sservice\ssnmp\sv3\strap-target
                \s+(?P<name>\S+)
                \s+(?P<protocol>protocol\s\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": "service snmp v3 trap-target protocol {{ snmp_v3.trap_targets.protocol }}",
            "result": {
                "snmp_v3": {
                    "trap_targets": {
                        "{{ name }}": {
                            "address": "{{ name }}",
                            "protocol": "{{ protocol }}",
                        },
                    },
                },
            },
        },
        # service snmp v3 trap-target <> type <>
        {
            "name": "snmp_v3.trap_targets.type",
            "getval": re.compile(
                r"""
                ^set\sservice\ssnmp\sv3\strap-target
                \s+(?P<name>\S+)
                \s+(?P<type>type\s\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": "service snmp v3 trap-target type {{ snmp_v3.trap_targets.type }}",
            "result": {
                "snmp_v3": {
                    "trap_targets": {
                        "{{ name }}": {
                            "address": "{{ name }}",
                            "type": "{{ type }}",
                        },
                    },
                },
            },
        },
        # service snmp v3 trap-target <> user <>
        {
            "name": "snmp_v3.trap_targets.user",
            "getval": re.compile(
                r"""
                ^set\sservice\ssnmp\sv3\strap-target
                \s+(?P<name>\S+)
                \s+(?P<user>user\s\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": "service snmp v3 trap-target user {{ snmp_v3.trap_targets.user }}",
            "result": {
                "snmp_v3": {
                    "trap_targets": {
                        "{{ name }}": {
                            "address": "{{ name }}",
                            "user": "{{ user }}",
                        },
                    },
                },
            },
        },
        # service snmp v3 trap-target <> privacy <>
        {
            "name": "snmp_v3.trap_targets.privacy",
            "getval": re.compile(
                r"""
                ^set\sservice\ssnmp\sv3\strap-target
                \s+(?P<name>\S+)
                \s+privacy
                \s*(?P<enc>encrypted-password\s\S+)*
                \s*(?P<plain>plaintext-password\s\S+)*
                \s*(?P<type>type\s\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_v3_trap_target,
            "result": {
                "snmp_v3": {
                    "trap_targets": {
                        "{{ name }}": {
                            "address": "{{ name }}",
                            "privacy": {
                                "encrypted_key": '{{ enc.split(" ")[1] if enc is defined else None }}',
                                "plaintext_key": '{{ plain.split(" ")[1] if plain is defined else None }}',
                                "type": '{{ type.split(" ")[1] if type is defined else None }}',
                            },
                        },
                    },
                },
            },
        },
        # service snmp v3 user <> auth <>
        {
            "name": "snmp_v3.users.authentication",
            "getval": re.compile(
                r"""
                ^set\sservice\ssnmp\sv3\suser
                \s+(?P<name>\S+)
                \s+auth
                \s*(?P<enc>encrypted-password\s\S+)*
                \s*(?P<plain>plaintext-password\s\S+)*
                \s*(?P<type>type\s\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_v3_user,
            "result": {
                "snmp_v3": {
                    "users": {
                        "{{ name }}": {
                            "user": "{{ name }}",
                            "authentication": {
                                "encrypted_key": '{{ enc.split(" ")[1] if enc is defined else None }}',
                                "plaintext_key": '{{ plain.split(" ")[1] if plain is defined else None }}',
                                "type": '{{ type.split(" ")[1] if type is defined else None }}',
                            },
                        },
                    },
                },
            },
        },
        # service snmp v3 user <> privacy <>
        {
            "name": "snmp_v3.users.privacy",
            "getval": re.compile(
                r"""
                ^set\sservice\ssnmp\sv3\suser
                \s+(?P<name>\S+)
                \s+privacy
                \s*(?P<enc>encrypted-password\s\S+)*
                \s*(?P<plain>plaintext-password\s\S+)*
                \s*(?P<type>type\s\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_v3_user,
            "result": {
                "snmp_v3": {
                    "users": {
                        "{{ name }}": {
                            "user": "{{ name }}",
                            "privacy": {
                                "encrypted_key": '{{ enc.split(" ")[1] if enc is defined else None }}',
                                "plaintext_key": '{{ plain.split(" ")[1] if plain is defined else None }}',
                                "type": '{{ type.split(" ")[1] if type is defined else None }}',
                            },
                        },
                    },
                },
            },
        },
        # service snmp v3 user <> group <>
        {
            "name": "snmp_v3.users.group",
            "getval": re.compile(
                r"""
                ^set\sservice\ssnmp\sv3\suser
                \s+(?P<name>\S+)
                \s+(?P<group>group\s.+)*
                $""",
                re.VERBOSE,
            ),
            "setval": "service snmp v3 user {{ snmp_v3.users.user }} group {{ snmp_v3.users.group }}",
            "result": {
                "snmp_v3": {
                    "users": {
                        "{{ name }}": {
                            "user": "{{ name }}",
                            "group": "{{ group.split(" ")[1] if group is defined else None }}",
                        },
                    },
                },
            },
        },
        # service snmp v3  user <> mode <>
        {
            "name": "snmp_v3.users.mode",
            "getval": re.compile(
                r"""
                ^set\sservice\ssnmp\sv3\suser
                \s+(?P<name>\S+)
                \s+(?P<mode>mode\s\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": "service snmp v3 user {{ snmp_v3.users.user }} mode {{ snmp_v3.users.mode }}",
            "result": {
                "snmp_v3": {
                    "users": {
                        "{{ name }}": {
                            "user": "{{ name }}",
                            "mode": "{{ mode }}",
                        },
                    },
                },
            },
        },
        # service snmp v3 view <>
        {
            "name": "snmp_v3.views",
            "getval": re.compile(
                r"""
                ^set\sservice\ssnmp\sv3\sview
                \s+(?P<name>\S+)
                \s+(?P<oid>oid\s\S+)
                \s*(?P<ex>exclude\s\S+)*
                \s*(?P<mask>mask\s\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_v3_views,
            "result": {
                "snmp_v3": {
                    "views": {
                        "{{ name }}": {
                            "view": "{{ name }}",
                            "oid": '{{ oid.split(" ")[1] if oid is defined else None }}',
                            "exclude": '{{ ex.split(" ")[1] if ex is defined else None }}',
                            "mask": '{{ mask.split(" ")[1] if mask is defined else None }}',
                        },
                    },
                },
            },
        },
    ]
    # fmt: on
