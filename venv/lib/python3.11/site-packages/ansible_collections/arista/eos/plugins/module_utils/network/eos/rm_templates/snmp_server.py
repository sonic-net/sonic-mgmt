# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
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


def _tmplt_snmp_server_ipv6_comm(config_data):
    command = ""
    if "acl_v6" in config_data["communities"]:
        command = "snmp-server community "
        el = config_data["communities"]
        command += el["name"]
        if el.get("view"):
            command += " view " + el["view"]
        if el.get("ro"):
            command += " ro"
        if el.get("rw"):
            command += " rw"
        command += " ipv6 " + el["acl_v6"]
    return command


def _tmplt_snmp_server_ipv4_comm(config_data):
    command = ""
    if not config_data["communities"].get("acl_v6"):
        command = "snmp-server community "
        el = config_data["communities"]
        command += el["name"]
        if el.get("view"):
            command += " view " + el["view"]
        if el.get("ro"):
            command += " ro"
        if el.get("rw"):
            command += " rw"
        if el.get("acl_v4"):
            command += " " + el["acl_v4"]
    return command


def _tmplt_snmp_server_traps_bgp(config_data):
    command = "snmp-server enable traps bgp"
    el = config_data["traps"]["bgp"]
    if el.get("arista_backward_transition"):
        command += " arista-backward-transition"
    if el.get("arista_established"):
        command += " arista-established"
    if el.get("backward_transition"):
        command += " backward-transition"
    if el.get("established"):
        command += " established"
    return command


def _tmplt_snmp_server_traps_bridge(config_data):
    command = "snmp-server enable traps bridge"
    el = config_data["traps"]["bridge"]
    if el.get("arista_mac_age"):
        command += " arista-mac-age"
    if el.get("arista_mac_learn"):
        command += " arista-mac-learn"
    if el.get("arista_mac_move"):
        command += " arista-mac-move"
    return command


def _tmplt_snmp_server_traps_capacity(config_data):
    command = "snmp-server enable traps capacity"
    el = config_data["traps"]["capacity"]
    if el.get("arista_hardware_utilization_alert"):
        command += " arista-hardware-utilization-alert"
    return command


def _tmplt_snmp_server_traps_entity(config_data):
    command = "snmp-server enable traps entity"
    el = config_data["traps"]["entity"]
    if el.get("arista_ent_sensor_alarm"):
        command += " arista-ent-sensor-alarm"
    if el.get("ent_config_change"):
        command += " ent-config-change"
    if el.get("ent_state_oper"):
        command += " ent-state-oper"
    if el.get("ent_state_oper_disabled"):
        command += " ent-state-oper-disabled"
    if el.get("ent_state_oper_enabled"):
        command += " ent-state-oper-enabled"
    return command


def _tmplt_snmp_server_traps_external_alarm(config_data):
    command = "snmp-server enable traps external-alarm"
    el = config_data["traps"]["external_alarm"]
    if el.get("arista_external_alarm_asserted_notif"):
        command += " arista-external-alarm-asserted-notif"
    if el.get("arista_external_alarm_deasserted_notif"):
        command += " arista-external-alarm-deasserted-notif"
    return command


def _tmplt_snmp_server_traps_isis(config_data):
    command = "snmp-server enable traps isis"
    el = config_data["traps"]["isis"]
    if el.get("adjacency_change"):
        command += " adjacency-change"
    if el.get("area_mismatch"):
        command += " area-mismatch"
    if el.get("attempt_to_exceed_max_sequence"):
        command += " attempt-to-exceed-max-sequence"
    if el.get("authentication_type_failure"):
        command += " authentication-type-failure"
    if el.get("database_overload"):
        command += " database-overload"
    if el.get("own_lsp_purge"):
        command += " own-lsp-purge"
    if el.get("rejected_adjacency"):
        command += " rejected-adjacency"
    if el.get("sequence_number_skip"):
        command += " sequence-number-skip"

    return command


def _tmplt_snmp_server_traps_lldp(config_data):
    command = "snmp-server enable traps lldp"
    el = config_data["traps"]["lldp"]
    if el.get("rem_tables_change"):
        command += " rem-tables-change"
    return command


def _tmplt_snmp_server_traps_mpls_ldp(config_data):
    command = "snmp-server enable traps mpls-ldp"
    el = config_data["traps"]["mpls_ldp"]
    if el.get("mpls_ldp_session_down"):
        command += " mpls-ldp-session-down"
    if el.get("mpls_ldp_session_up"):
        command += " mpls-ldp-session-up"
    return command


def _tmplt_snmp_server_traps_msdp(config_data):
    command = "snmp-server enable traps msdp"
    el = config_data["traps"]["msdp"]
    if el.get("backward_transition"):
        command += " backward-transition"
    if el.get("established"):
        command += " established"
    return command


def _tmplt_snmp_server_traps_ospf(config_data):
    command = "snmp-server enable traps ospf"
    el = config_data["traps"]["ospf"]
    if el.get("if_auth_failure"):
        command += " if-auth-failure"
    if el.get("if_config_error"):
        command += " if-config-error"
    if el.get("if_state_change"):
        command += " if-state-change"
    if el.get("nbr_state_change"):
        command += " nbr-state-change"
    return command


def _tmplt_snmp_server_traps_ospfv3(config_data):
    command = "snmp-server enable traps ospfv3"
    el = config_data["traps"]["ospfv3"]
    if el.get("if_config_error"):
        command += " if-config-error"
    if el.get("if_rx_bad_packet"):
        command += " if-rx-bad-packet"
    if el.get("if_state_change"):
        command += " if-state-change"
    if el.get("nbr_state_change"):
        command += " nbr-state-change"
    if el.get("nbr_restart_helper_status_change"):
        command += " nbr-restart-helper-status-change"
    if el.get("nssa_translator_status_change"):
        command += " nssa-translator-status-change"
    if el.get("restart_status_change"):
        command += " restart-status-change"
    return command


def _tmplt_snmp_server_traps_pim(config_data):
    command = "snmp-server enable traps pim"
    el = config_data["traps"]["pim"]
    if el.get("neighbor_loss"):
        command += " neighbor-loss"
    return command


def _tmplt_snmp_server_traps_snmp(config_data):
    command = "snmp-server enable traps snmp"
    el = config_data["traps"]["snmp"]
    if el.get("authentication"):
        command += " authentication"
    if el.get("link_down"):
        command += " link-down"
    if el.get("link_up"):
        command += " link-up"
    return command


def _tmplt_snmp_server_traps_snmpConfigManEvent(config_data):
    command = "snmp-server enable traps snmpConfigManEvent"
    el = config_data["traps"]["snmpConfigManEvent"]
    if el.get("arista_config_man_event"):
        command += " arista-config-man-event"
    return command


def _tmplt_snmp_server_traps_switchover(config_data):
    command = "snmp-server enable traps switchover"
    el = config_data["traps"]["switchover"]
    if el.get("arista_redundancy_switch_over_notif"):
        command += " arista-redundancy-switch-over-notif"
    return command


def _tmplt_snmp_server_traps_test(config_data):
    command = "snmp-server enable traps test"
    el = config_data["traps"]["test"]
    if el.get("arista_test_notification"):
        command += " arista-test-notification"
    return command


def _tmplt_snmp_server_traps_vrrp(config_data):
    command = "snmp-server enable traps vrrp"
    el = config_data["traps"]["vrrp"]
    if el.get("trap_new_master"):
        command += " trap-new-master"
    return command


def _tmplt_snmp_server_engineid(config_data):
    command = []
    cmd = "snmp-server engineID"
    el = config_data["engineid"]
    if el.get("local"):
        c = cmd + " local " + el["local"]
        command.append(c)
    if el.get("remote"):
        c = cmd + " remote " + el["remote"]["host"]
        if el["remote"].get("udp_port"):
            c += " udp-port " + str(el["remote"]["udp_port"])
        if el["remote"].get("id"):
            c += " " + el["remote"]["id"]
            command.append(c)
    return command


def _tmplt_snmp_server_extension(config_data):
    command = "snmp-server extension "
    command += config_data["extension"]["root_oid"]
    command += " " + config_data["extension"]["script_location"]
    if config_data["extension"].get("oneshot"):
        command += " one-shot"
    return command


def _tmplt_snmp_server_groups(config_data):
    command = "snmp-server group " + config_data["groups"]["group"]
    el = config_data["groups"]
    command += " " + el["version"]
    if el.get("auth_privacy"):
        command += " " + el["auth_privacy"]
    for param in ["context", "read", "write", "notify"]:
        if el.get(param):
            command += " " + param + " " + el[param]
    return command


def _tmplt_snmp_server_hosts(config_data):
    el = list(config_data["hosts"].values())[0]
    command = "snmp-server host " + el["host"]
    if el.get("vrf"):
        command += " vrf " + el["vrf"]
    if el.get("informs"):
        command += " informs"
    if el.get("traps"):
        command += " traps"
    if el.get("version"):
        command += " version " + el["version"]
    if el.get("user"):
        command += " " + el["user"]
    if el.get("udp_port"):
        command += " udp-port " + str(el["udp_port"])
    return command


def _tmplt_snmp_server_acls(config_data):
    command = "snmp-server " + config_data["acls"]["afi"] + " access-list "
    el = config_data["acls"]
    command += el["acl"]
    if el.get("vrf"):
        command += " vrf " + el["vrf"]
    return command


def _tmplt_snmp_server_vrfs(config_data):
    command = "snmp-server vrf " + config_data["vrfs"]["vrf"]
    el = config_data["vrfs"]
    if el.get("local_interface"):
        command += " local-interface " + el["local_interface"]
    return command


def _tmplt_snmp_server_users_auth(config_data):
    el = config_data["users"]
    command = "snmp-server user " + el["user"] + " " + el["group"]
    if el.get("remote"):
        command += " remote " + el["remote"]
    if el.get("udp_port"):
        command += " udp-port " + str(el["udp_port"])
    command += " " + el["version"]
    if el.get("auth"):
        command += " auth " + el["auth"]["algorithm"] + " " + el["auth"]["auth_passphrase"]
        if el["auth"].get("encryption"):
            command += " priv " + el["auth"]["encryption"] + " " + el["auth"]["priv_passphrase"]
    return command


def _tmplt_snmp_server_users_localized(config_data):
    el = config_data["users"]
    command = "snmp-server user " + el["user"] + " " + el["group"]
    if el.get("remote"):
        command += " remote " + el["remote"]
    if el.get("udp_port"):
        command += " udp-port " + str(el["udp_port"])
    command += " " + el["version"]
    if el.get("localized"):
        command += " localized " + el["localized"]["engineid"]
        el = el["localized"]
        command += " auth " + el["algorithm"] + " " + el["auth_passphrase"]
        if el.get("encryption"):
            command += " priv " + el["encryption"] + " " + el["priv_passphrase"]
    return command


class Snmp_serverTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(Snmp_serverTemplate, self).__init__(
            lines=lines,
            tmplt=self,
            module=module,
        )

    # fmt: off
    PARSERS = [
        {
            "name": "chassis_id",
            "getval": re.compile(
                r"""
                \s*snmp-server\schassis-id
                \s*(?P<id>\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": 'snmp-server chassis-id {{ chassis_id }}',
            "result": {
                "chassis_id": "{{ id }}",
            },
        },
        {
            "name": "communities_ipv6_acl",
            "getval": re.compile(
                r"""
                \s*snmp-server\scommunity
                \s+(?P<comm>\S+)
                \s*(?P<view>view\s\S+)*
                \s*(?P<access>ro|rw)*
                \s*(?P<acl>ipv6\s\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_ipv6_comm,
            "compval": "communities",
            "result": {
                "communities": {
                    "{{ comm }}": {
                        "name": "{{ comm }}",
                        "acl_v6": "{{ acl.split(" ")[1] }}",
                        "view": "{{ view.split(" ")[1] if view is defined }}",
                        "ro": '{{ True if access == "ro" }}',
                        "rw": '{{ True if access == "rw" }}',
                    },
                },
            },
        },
        {
            "name": "communities_ipv4_acl",
            "getval": re.compile(
                r"""
                \s*snmp-server\scommunity
                \s+(?P<comm>\S+)
                \s*(?P<view>view\s\S+)*
                \s*(?P<access>ro|rw)*
                \s*(?P<acl>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_ipv4_comm,
            "compval": "communities",
            "result": {
                "communities": {
                    "{{ comm }}": {
                        "name": "{{ comm }}",
                        "acl_v4": '{{ acl if acl != "ipv6" }}',
                        "view": "{{ view.split(" ")[1] if view is defined }}",
                        "ro": '{{ True if access == "ro" }}',
                        "rw": '{{ True if access == "rw" }}',
                    },
                },
            },
        },
        {
            "name": "contact",
            "getval": re.compile(
                r"""
                \s*snmp-server\scontact
                \s+(?P<name>.+)
                *$""",
                re.VERBOSE,
            ),
            "setval": 'snmp-server contact {{ contact }}',
            "compval": "contact",
            "result": {
                "contact": "{{ name }}",
            },
        },
        {
            "name": "traps.bgp",
            "getval": re.compile(
                r"""
                \s*snmp-server\senable\straps\sbgp
                \s*(?P<trap1>arista-backward-transition)*
                \s*(?P<trap2>arista-established)*
                \s*(?P<trap3>backward-transition)*
                \s*(?P<trap4>established)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_traps_bgp,
            "result": {
                "traps": {
                    "bgp": {
                        "arista_backward_transition": "{{ True if trap1 is defined }}",
                        "arista_established": "{{ True if trap2 is defined }}",
                        "backward_transition": "{{ True if trap3 is defined }}",
                        "established": "{{ True if trap4 is defined }}",
                        "enabled": "{{ True if trap1 is undefined and trap2 is undefined and trap3 is undefined and trap4 is undefined }}",
                    },
                },
            },
        },
        {
            "name": "traps.bridge",
            "getval": re.compile(
                r"""
                \s*snmp-server\senable\straps\sbridge
                \s*(?P<trap1>arista-mac-age)*
                \s*(?P<trap2>arista-mac-learn)*
                \s*(?P<trap3>arista-mac-move)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_traps_bridge,
            "result": {
                "traps": {
                    "bridge": {
                        "enabled": "{{ True if trap1 is undefined and trap2 is undefined and trap3 is undefined }}",
                        "arista_mac_age": "{{ True if trap1 is defined }}",
                        "arista_mac_learn": "{{ True if trap2 is defined }}",
                        "arista_mac_move": "{{ True if trap3 is defined }}",
                    },
                },
            },
        },

        {
            "name": "traps.capacity",
            "getval": re.compile(
                r"""
                \s*snmp-server\senable\straps\scapacity
                \s*(?P<trap1>arista-hardware-utilization-alert)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_traps_capacity,
            "result": {
                "traps": {
                    "capacity": {
                        "arista_hardware_utilization_alert": "{{ True if trap1 is defined }}",
                        "enabled": "{{ True if trap1 is undefined }}",
                    },
                },
            },
        },
        {
            "name": "traps.entity",
            "getval": re.compile(
                r"""
                \s*snmp-server\senable\straps\sentity
                \s*(?P<trap1>arista-ent-sensor-alarm)*
                \s*(?P<trap2>ent-config-change)*
                \s*(?P<trap3>ent-state-oper)*
                \s*(?P<trap4>ent-state-oper-disabled)*
                \s*(?P<trap5>ent-state-oper-enabled)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_traps_entity,
            "result": {
                "traps": {
                    "entity": {
                        "arista_ent_sensor_alarm": "{{ True if trap1 is defined }}",
                        "ent_config_change": "{{ True if trap2 is defined }}",
                        "ent_state_oper": "{{ True if trap3 is defined }}",
                        "ent_state_oper_disabled": "{{ True if trap4 is defined }}",
                        "ent_state_oper_enabled": "{{ True if trap4 is defined }}",
                        "enabled": "{{ True if trap1 is undefined and trap2 is undefined and trap3 is undefined\
                             and trap4 is undefined and trap5 is undefined }}",
                    },
                },
            },
        },
        {
            "name": "traps.external_alarm",
            "getval": re.compile(
                r"""
                \s*snmp-server\senable\straps\sexternal-alarm
                \s*(?P<trap1>arista-external-alarm-asserted-notif)*
                \s*(?P<trap2>arista-external-alarm-deasserted-notif)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_traps_external_alarm,
            "result": {
                "traps": {
                    "external_alarm": {
                        "arista_external_alarm_asserted_notif": "{{ True if trap1 is defined }}",
                        "arista_external_alarm_deasserted_notif": "{{ True if trap2 is defined }}",
                        "enabled": "{{ True if trap1 is undefined and trap2 is undefined }}",
                    },
                },
            },
        },
        {
            "name": "traps.isis",
            "getval": re.compile(
                r"""
                \s*snmp-server\senable\straps\sisis
                \s*(?P<trap1>adjacency-change)*
                \s*(?P<trap2>area-mismatch)*
                \s*(?P<trap3>attempt-to-exceed-max-sequence)*
                \s*(?P<trap4>authentication-type-failure)*
                \s*(?P<trap5>database-overload)*
                \s*(?P<trap6>own-lsp-purge)*
                \s*(?P<trap7>rejected-adjacency)*
                \s*(?P<trap8>equence-number-skip)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_traps_isis,
            "result": {
                "traps": {
                    "isis": {
                        "adjacency_change": "{{ True if trap1 is defined }}",
                        "area_mismatch": "{{ True if trap2 is defined }}",
                        "attempt_to_exceed_max_sequence": "{{ True if trap3 is defined }}",
                        "authentication_type_failure": "{{ True if trap4 is defined }}",
                        "database_overload": "{{ True if trap4 is defined }}",
                        "own_lsp_purge": "{{ True if trap4 is defined }}",
                        "rejected_adjacency": "{{ True if trap4 is defined }}",
                        "sequence_number_skip": "{{ True if trap4 is defined }}",
                        "enabled": "{{ True if trap1 is undefined and trap2 is undefined and trap3 is undefined and trap4 is undefined\
                                    and trap5 is undefined and trap6 is undefined and trap7 is undefined and trap8 is undefined }}",

                    },
                },
            },
        },
        {
            "name": "traps.lldp",
            "getval": re.compile(
                r"""
                \s*snmp-server\senable\straps\slldp
                \s*(?P<trap1>rem-tables-change)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_traps_lldp,
            "result": {
                "traps": {
                    "lldp": {
                        "rem_tables_change": "{{ True if trap1 is defined }}",
                        "enabled": "{{ True if trap1 is undefined }}",
                    },
                },
            },
        },
        {
            "name": "traps.mpls_ldp",
            "getval": re.compile(
                r"""
                \s*snmp-server\senable\straps\smpls-ldp
                \s*(?P<trap1>mpls-ldp-session-down)*
                \s*(?P<trap2>mpls-ldp-session-up)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_traps_mpls_ldp,
            "result": {
                "traps": {
                    "mpls_ldp": {
                        "mpls_ldp_session_down": "{{ True if trap1 is defined }}",
                        "mpls_ldp_session_up": "{{ True if trap2 is defined }}",
                        "enabled": "{{ True if trap1 is undefined and trap2 is undefined }}",
                    },
                },
            },
        },
        {
            "name": "traps.msdp",
            "getval": re.compile(
                r"""
                \s*snmp-server\senable\straps\smsdp
                \s*(?P<trap1>backward-transition)*
                \s*(?P<trap2>established)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_traps_msdp,
            "result": {
                "traps": {
                    "msdp": {
                        "backward_transition": "{{ True if trap1 is defined }}",
                        "established": "{{ True if trap2 is defined }}",
                        "enabled": "{{ True if trap1 is undefined and trap2 is undefined }}",
                    },
                },
            },
        },
        {
            "name": "traps.ospf",
            "getval": re.compile(
                r"""
                \s*snmp-server\senable\straps\sospf
                \s*(?P<trap1>if-auth-failure)*
                \s*(?P<trap2>if-config-error)*
                \s*(?P<trap3>if-state-change)*
                \s*(?P<trap4>nbr-state-change)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_traps_ospf,
            "result": {
                "traps": {
                    "ospf": {
                        "if_config_error": "{{ True if trap2 is defined }}",
                        "if_auth_failure": "{{ True if trap1 is defined }}",
                        "if_state_change": "{{ True if trap3 is defined }}",
                        "nbr_state_change": "{{ True if trap4 is defined }}",
                        "enabled": "{{ True if trap1 is undefined and trap2 is undefined and trap3 is undefined and trap4 is undefined }}",
                    },
                },
            },
        },
        {
            "name": "traps.ospfv3",
            "getval": re.compile(
                r"""
                \s*snmp-server\senable\straps\sospfv3
                \s*(?P<trap1>if-config-error)*
                \s*(?P<trap2>if-rx-bad-packet)*
                \s*(?P<trap3>if-state-change)*
                \s*(?P<trap4>nbr-restart-helper-status-change)*
                \s*(?P<trap5>nbr-state-change)*
                \s*(?P<trap6>nssa-translator-status-change)*
                \s*(?P<trap7>restart-status-change)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_traps_ospfv3,
            "result": {
                "traps": {
                    "ospfv3": {
                        "if_config_error": "{{ True if trap1 is defined }}",
                        "if_rx_bad_packet": "{{ True if trap2 is defined }}",
                        "if_state_change": "{{ True if trap3 is defined }}",
                        "nbr_state_change": "{{ True if trap5 is defined }}",
                        "nbr_restart_helper_status_change": "{{ True if trap4 is defined }}",
                        "nssa_translator_status_change": "{{ True if trap6 is defined }}",
                        "restart_status_change": "{{ True if trap7 is defined }}",
                        "enabled": "{{ True if trap1 is undefined and trap2 is undefined and trap3 is undefined and trap4 is undefined\
                         and trap5 is undefined and trap6 is undefined and trap7 is undefined }}",
                    },
                },
            },
        },
        {
            "name": "traps.pim",
            "getval": re.compile(
                r"""
                \s*snmp-server\senable\straps\spim
                \s*(?P<trap1>neighbor-loss)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_traps_pim,
            "result": {
                "traps": {
                    "pim": {
                        "neighbor_loss": "{{ True if trap1 is defined }}",
                        "enabled": "{{ True if trap1 is undefined }}",
                    },
                },
            },
        },
        {
            "name": "traps.snmp",
            "getval": re.compile(
                r"""
                \s*snmp-server\senable\straps\ssnmp
                \s*(?P<trap1>authentication)*
                \s*(?P<trap2>link-down)*
                \s*(?P<trap3>link-up)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_traps_snmp,
            "result": {
                "traps": {
                    "snmp": {
                        "authentication": "{{ True if trap1 is defined }}",
                        "link_down": "{{ True if trap2 is defined }}",
                        "link_up": "{{ True if trap3 is defined }}",
                        "enabled": "{{ True if trap1 is undefined and trap2 is undefined and trap3 is undefined }}",
                    },
                },
            },
        },
        {
            "name": "traps.snmpConfigManEvent",
            "getval": re.compile(
                r"""
                \s*snmp-server\senable\straps\ssnmpConfigManEvent
                \s*(?P<trap1>arista-config-man-event)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_traps_snmpConfigManEvent,
            "result": {
                "traps": {
                    "snmpConfigManEvent": {
                        "arista_config_man_event": "{{ True if trap1 is defined }}",
                        "enabled": "{{ True if trap1 is undefined }}",
                    },
                },
            },
        },
        {
            "name": "traps.switchover",
            "getval": re.compile(
                r"""
                \s*snmp-server\senable\straps\sswitchover
                \s*(?P<trap1>arista-redundancy-switch-over-notif)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_traps_switchover,
            "result": {
                "traps": {
                    "switchover": {
                        "arista_redundancy_switch_over_notif": "{{ True if trap1 is defined }}",
                        "enabled": "{{ True if trap1 is undefined }}",
                    },
                },
            },
        },
        {
            "name": "traps.test",
            "getval": re.compile(
                r"""
                \s*snmp-server\senable\straps\stest
                \s*(?P<trap1>arista-test-notification)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_traps_test,
            "result": {
                "traps": {
                    "test": {
                        "arista_test_notification": "{{ True if trap1 is defined }}",
                        "enabled": "{{ True if trap1 is undefined }}",
                    },
                },
            },
        },
        {
            "name": "traps.vrrp",
            "getval": re.compile(
                r"""
                \s*snmp-server\senable\straps\svrrp
                \s*(?P<trap1>trap-new-master)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_traps_vrrp,
            "result": {
                "traps": {
                    "vrrp": {
                        "trap_new_master": "{{ True if trap1 is defined }}",
                        "enabled": "{{ True if trap1 is undefined }}",
                    },
                },
            },
        },
        {
            "name": "engineid",
            "getval": re.compile(
                r"""
                \s*snmp-server\sengineID
                \s*(?P<local>local \S+)*
                \s*(?P<remote>remote \S+)*
                \s*(?P<udp>udp-port\s\d+)*
                \s*(?P<id>\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_engineid,
            "result": {
                "engineid": {
                    "local": "{{ local.split(" ")[1] if local is defined }}",
                    "remote": {
                        "host": "{{ remote.split(" ")[1] if remote is defined }}",
                        "id": "{{ id }}",
                        "udp_port": "{{ udp.split(" ")[1] if udp is defined }}",
                    },
                },
            },
        },
        {
            "name": "extension",
            "getval": re.compile(
                r"""
                \s*snmp-server\sextension
                \s*(?P<oid>\.\S+|str)*
                \s*(?P<script>\S+)*
                \s*(?P<oneshot>one-shot)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_extension,
            "remval": "snmp-server extension {{ extension.root_oid.lstrip('0') }} {{ extension.script_location }}",
            "result": {
                "extension": {
                    "root_oid": "{{ oid }}",
                    "script_location": "{{ script }}",
                    "oneshot": "{{ True if oneshot is defined }}",
                },
            },
        },
        {
            "name": "groups",
            "getval": re.compile(
                r"""
                \s*snmp-server\sgroup
                \s*(?P<name>\S+)*
                \s*(?P<version>v1|v2c|v3\sauth|v3\snoauth|v3\spriv)*
                \s*(?P<context>context\s\S+)*
                \s*(?P<read>read\s\S+)*
                \s*(?P<write>write\s\S+)*
                \s*(?P<notify>notify\s\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_groups,
            "result": {
                "groups": {
                    "{{ name }}": {
                        "group": "{{ name }}",
                        "version": "{{ version.split(" ")[0] }}",
                        "auth_privacy": '{{ version.split(" ")[1] if "v3" in version }}',
                        "context": "{{ context.split(" ")[1] if context is defined }}",
                        "notify": "{{ notify.split(" ")[1] if notify is defined }}",
                        "read": "{{ read.split(" ")[1] if read is defined }}",
                        "write": "{{ write.split(" ")[1] if write is defined }}",
                    },
                },
            },
        },
        {
            "name": "hosts",
            "getval": re.compile(
                r"""
                \s*snmp-server\shost
                \s(?P<name>\S+)
                \s*(?P<vrf>vrf\s\S+)*
                \s*(?P<msg_inf1>informs)*
                \s*(?P<msg_tr1>traps)*
                \s*(version)*
                \s*(?P<version>1|2c|3\sauth|3\snoauth|3\spriv)*
                \s*(?P<msg_inf2>informs)*
                \s*(?P<msg_tr2>traps)*
                \s*(?P<comm>\S+)*
                \s*(?P<udp>udp-port)*?
                \s*(?P<port>\d+)*?
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_hosts,
            "result": {
                "hosts": {
                    '{{ name, comm|d(""), version|d("2c"), msg_inf1|d() or msg_inf2|d(), msg_tr1|d() or msg_tr2|d(), port|d() }}': {
                        "host": "{{ name }}",
                        "vrf": "{{ vrf.split(" ")[1] if vrf is defined }}",
                        "version": '{{ version }}',
                        "udp_port": "{{ port if udp is defined and port is defined else None }}",
                        "informs": '{{ True if msg_inf1 is defined or msg_inf2 is defined else None }}',
                        "traps": '{{ True if msg_tr1 is defined or msg_tr2 is defined else None }}',
                        "user": "{{ comm }}",
                    },
                },
            },
        },
        {
            "name": "acls",
            "getval": re.compile(
                r"""
                \s*snmp-server\s
                \s+(?P<afi>ipv4|ipv6)
                \s+access-list
                \s+(?P<acl>\S+)
                \s*(?P<vrf>vrf\s\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_acls,
            "result": {
                "acls": {
                    "{{ afi }}": {
                        "afi": "{{ afi }}",
                        "acl": "{{ acl }}",
                        "vrf": "{{ vrf.split(" ")[1] if vrf is defined }}",
                    },
                },
            },
        },
        {
            "name": "local_interface",
            "getval": re.compile(
                r"""
                \s*snmp-server\slocal-interface
                \s+(?P<int>.+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "snmp-server local-interface {{ local_interface }}",
            "result": {
                "local_interface": "{{ int }}",
            },
        },
        {
            "name": "location",
            "getval": re.compile(
                r"""
                \s*snmp-server\slocation
                \s+(?P<loc>.+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "snmp-server location {{ location }}",
            "result": {
                "location": "{{ loc }}",
            },
        },
        {
            "name": "notification",
            "getval": re.compile(
                r"""
                \s*snmp-server\snotification\slog\sentry\slimit
                \s+(?P<num>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "snmp-server notification log entry limit {{ notification }}",
            "result": {
                "notification": "{{ num }}",
            },
        },
        {
            "name": "objects.mac",
            "getval": re.compile(
                r"""
                \s*snmp-server\sobjects
                \s+mac-address-tables
                \s+disable
                *$""",
                re.VERBOSE,
            ),
            "setval": "snmp-server objects mac-address-tables disable",
            "compval": "objects",
            "result": {
                "objects": {
                    "mac_address_tables": "{{ True }}",
                },
            },
        },
        {
            "name": "objects.route",
            "getval": re.compile(
                r"""
                \s*snmp-server\sobjects
                \s+route-tables
                \s+disable
                *$""",
                re.VERBOSE,
            ),
            "setval": "snmp-server objects route-tables disable",
            "compval": "objects",
            "result": {
                "objects": {
                    "route_address_tables": "{{ True }}",
                },
            },
        },
        {
            "name": "qos",
            "getval": re.compile(
                r"""
                \s*snmp-server\sqos\sdscp
                \s+(?P<num>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "snmp-server qos dscp {{ qos }}",
            "result": {
                "qos": "{{ num }}",
            },
        },
        {
            "name": "qosmib",
            "getval": re.compile(
                r"""
                \s*snmp-server\sqosmib\scounter-interval
                \s+(?P<num>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "snmp-server qosmib counter-interval {{ qosmib }}",
            "result": {
                "qosmib": "{{ num }}",
            },
        },
        {
            "name": "transmit",
            "getval": re.compile(
                r"""
                \s*snmp-server\stransmit\smax-size
                \s+(?P<num>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": "snmp-server transmit max-size {{ transmit }}",
            "result": {
                "transmit": "{{ num }}",
            },
        },
        {
            "name": "transport",
            "getval": re.compile(
                r"""
                \s*snmp-server\stransport\stcp
                *$""",
                re.VERBOSE,
            ),
            "setval": "snmp-server transport tcp",
            "result": {
                "transport": '{{ "tcp" }}',
            },
        },
        {
            "name": "views",
            "getval": re.compile(
                r"""
                \s*snmp-server\sview
                \s+(?P<name>\S+)
                \s+(?P<mib>\S+)
                \s+(?P<action>excluded|included)
                *$""",
                re.VERBOSE,
            ),
            "setval": "snmp-server view {{ views.view }} {{ views.mib }} {{ views.action }}",
            "result": {
                "views": {
                    "{{ name }}": {
                        "view": "{{ name }}",
                        "mib": "{{ mib }}",
                        "action": "{{ actions }}",
                    },
                },
            },
        },
        {
            "name": "vrfs",
            "getval": re.compile(
                r"""
                \s*snmp-server\svrf
                \s+(?P<name>\S+)
                \s*(?P<int>local-interface\s.+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_vrfs,
            "result": {
                "vrfs": {
                    "{{ name }}": {
                        "vrf": "{{ name }}",
                        "local_interface": "{{ int.split(" ")[1] }}",
                    },
                },
            },
        },
        {
            "name": "users.auth",
            "getval": re.compile(
                r"""
                \s*snmp-server\suser
                \s*(?P<name>\S+)*
                \s*(?P<group>\S+)*
                \s*(?P<rem>remote\s\S+)*
                \s*(?P<udp>udp-port\s\d+)*
                \s*(?P<version>v1|v2c|v3)*
                \s*(?P<auth>auth)*
                \s*(?P<algo>\S+)*
                \s*(?P<pass>\S+)*
                \s*(?P<priv>priv)*
                \s*(?P<enc>\S+)*
                \s*(?P<privpass>\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_users_auth,
            "result": {
                "users": {
                    "{{ name }}": {
                        "user": "{{ host }}",
                        "group": "{{ group }}",
                        "remote": "{{ rem.split(" ")[1] if rem is defined }}",
                        "version": '{{ version }}',
                        "auth": {
                            "algorithm": "{{ algo }}",
                            "auth_passphrase": "{{ pass }}",
                            "encryption": "{{ enc }}",
                            "priv_passphrase": "{{ privpass }}",
                        },
                        "udp_port": "{{ udp.split(" ")[1] if udp is defined }}",
                    },
                },
            },
        },
        {
            "name": "users.localized",
            "getval": re.compile(
                r"""
                \s*snmp-server\suser
                \s*(?P<name>\S+)*
                \s*(?P<group>\S+)*
                \s*(?P<rem>remote\s\S+)*
                \s*(?P<udp>udp-port\s\d+)*
                \s*(?P<version>v1|v2c|v3)*
                \s*(?P<localized>localized \S+)*
                \s*(?P<algo>\S+)*
                \s*(?P<pass>\S+)*
                \s*(?P<priv>priv)*
                \s*(?P<enc>\S+)*
                \s*(?P<privpass>\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_snmp_server_users_localized,
            "result": {
                "users": {
                    "{{ name }}": {
                        "user": "{{ host }}",
                        "group": "{{ group }}",
                        "remote": "{{ rem.split(" ")[1] if rem is defined }}",
                        "version": '{{ version }}',
                        "localized": {
                            "engineid": "{{ localized.split(" ")[1] }}",
                            "algorithm": "{{ algo }}",
                            "auth_passphrase": "{{ pass }}",
                            "encryption": "{{ enc }}",
                            "priv_passphrase": "{{ privpass }}",
                        },
                        "udp_port": "{{ udp.split(" ")[1] if udp is defined }}",
                    },
                },
            },
        },
    ]
    # fmt: on
