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


def communities_tmplt(config_data):
    name = config_data.get("name", "")
    command = "snmp-server community {name}".format(name=name)
    if config_data.get("rw"):
        command += " RW"
    elif config_data.get("ro"):
        command += " RO"
    if config_data.get("sdrowner"):
        command += " SDROwner"
    elif config_data.get("systemowner"):
        command += " SystemOwner"
    if config_data.get("acl_v4"):
        command += " IPv4 {IPv4}".format(IPv4=config_data["acl_v4"])
    if config_data.get("acl_v6"):
        command += " IPv6 {IPv6}".format(IPv6=config_data["acl_v6"])
    if config_data.get("v4_acl"):
        command += " {v4_acl}".format(v4_acl=config_data["v4_acl"])
    return command


def community_maps_tmplt(config_data):
    name = config_data.get("name", "")
    command = "snmp-server community-map {name}".format(name=name)
    if config_data.get("context"):
        command += " context {context}".format(context=config_data["context"])
    if config_data.get("security_name"):
        command += " security-name {security_name}".format(
            security_name=config_data["security_name"],
        )
    if config_data.get("target_list"):
        command += " target-list {target_list}".format(
            target_list=config_data["target_list"],
        )
    return command


def tmplt_correlator_rule(config_data):
    rule_name = config_data.get("rule_name")
    command = "snmp-server correlator rule {rule_name}".format(
        rule_name=rule_name,
    )
    if config_data.get("timeout"):
        command += " timeout {timeout}".format(timeout=config_data["timeout"])
    return command


def group_tmplt(config_data):
    group = config_data.get("group", "")
    command = "snmp-server group {group}".format(group=group)
    if config_data.get("version"):
        command += " {version}".format(version=config_data["version"])
    if config_data.get("notify"):
        command += " notify {notify}".format(notify=config_data["notify"])
    if config_data.get("read"):
        command += " read {read}".format(read=config_data["read"])
    if config_data.get("write"):
        command += " write {write}".format(write=config_data["write"])
    if config_data.get("context"):
        command += " context {context}".format(context=config_data["context"])
    if config_data.get("acl_v4"):
        command += " IPv4 {acl_v4}".format(acl_v4=config_data["acl_v4"])
    if config_data.get("acl_v6"):
        command += " IPv6 {acl_v6}".format(acl_v6=config_data["acl_v6"])
    if config_data.get("v4_acl"):
        command += " {v4_acl}".format(v4_acl=config_data["v4_acl"])
    return command


def host_tmplt(config_data):
    host = config_data.get("host", "")
    command = "snmp-server host {host}".format(host=host)
    if config_data.get("informs"):
        command += " informs"
    if config_data.get("traps"):
        command += " traps"
    if config_data.get("version"):
        command += " version {version}".format(version=config_data["version"])
    if config_data.get("community"):
        command += " {community}".format(community=config_data["community"])
    if config_data.get("udp_port"):
        command += " udp-port {udp_port}".format(
            udp_port=config_data["udp_port"],
        )
    if config_data.get("write"):
        command += " write {write}".format(write=config_data["write"])
    return command


def interfaces_tmplt(config_data):
    interface = config_data.get("name", "")
    notification_linkupdown_disable = config_data.get(
        "notification_linkupdown_disable",
        "",
    )
    index_persistent = config_data.get("index_persistent", "")

    cmds = []
    if notification_linkupdown_disable:
        command = "snmp-server interface {interface} notification linkupdown disable".format(
            interface=interface,
        )
        cmds.append(command)
    if config_data.get("index_persistent"):
        command = "snmp-server interface {interface} index persistence".format(
            interface=interface,
        )
        cmds.append(command)
    if not notification_linkupdown_disable and not index_persistent and interface:
        command = "snmp-server interface {interface}".format(
            interface=interface,
        )
        cmds.append(command)
    return cmds


def mib_schema_tmplt(config_data):
    name = config_data.get("name", "")
    object_list = config_data.get("object_list", "")
    poll_interval = config_data.get("poll_interval", "")

    cmds = []
    if object_list:
        command = "snmp-server mib bulkstat schema {name} object-list {object_list}".format(
            name=name,
            object_list=object_list,
        )
        cmds.append(command)
    if poll_interval:
        command = "snmp-server mib bulkstat schema {name} poll-interval {poll_interval}".format(
            name=name,
            poll_interval=poll_interval,
        )
        cmds.append(command)
    if not object_list and not poll_interval and name:
        command = "snmp-server mib bulkstat schema {name}".format(name=name)
        cmds.append(command)
    return cmds


def mib_bulkstat_transfer_ids_tmplt(config_data):
    name = config_data.get("name", "")
    buffer_size = config_data.get("buffer_size", "")
    enable = config_data.get("enable", "")
    format_schemaASCI = config_data.get("format_schemaASCI", "")
    retain = config_data.get("retain", "")
    retry = config_data.get("retry", "")
    schema = config_data.get("schema", "")
    transfer_interval = config_data.get("transfer_interval", "")

    cmds = []
    if buffer_size:
        command = "snmp-server mib bulkstat transfer-id {name} buffer-size {buffer_size}".format(
            name=name,
            buffer_size=buffer_size,
        )
        cmds.append(command)
    if enable:
        command = "snmp-server mib bulkstat transfer-id {name} enable".format(
            name=name,
        )
        cmds.append(command)
    if format_schemaASCI:
        command = "snmp-server mib bulkstat transfer-id {name} format schemaASCII".format(
            name=name,
        )
        cmds.append(command)
    if retain:
        command = "snmp-server mib bulkstat transfer-id {name} retain {retain}".format(
            name=name,
            retain=retain,
        )
        cmds.append(command)
    if retry:
        command = "snmp-server mib bulkstat transfer-id {name} retry {retry}".format(
            name=name,
            retry=retry,
        )
        cmds.append(command)
    if schema:
        command = "snmp-server mib bulkstat transfer-id {name} schema {schema}".format(
            name=name,
            schema=schema,
        )
        cmds.append(command)
    if transfer_interval:
        command = "snmp-server mib bulkstat transfer-id {name} transfer_interval {transfer_interval}".format(
            name=name,
            transfer_interval=transfer_interval,
        )
        cmds.append(command)
    if (
        not any(
            [
                buffer_size,
                enable,
                format_schemaASCI,
                retry,
                retain,
                schema,
                transfer_interval,
            ],
        )
        and name
    ):
        command = "snmp-server mib bulkstat transfer-id {name}".format(
            name=name,
        )
        cmds.append(command)
    return cmds


def overload_control_tmplt(config_data):
    config_data = config_data.get("overload_control", {})
    command = "snmp-server overload-control"
    if config_data.get("overload_drop_time"):
        command += " {overload_drop_time}".format(
            overload_drop_time=config_data["overload_drop_time"],
        )
    if config_data.get("overload_throttle_rate"):
        command += " {overload_throttle_rate}".format(
            overload_throttle_rate=config_data["overload_throttle_rate"],
        )
    return command


def targets_tmplt(config_data):
    name = config_data.get("name", "")
    command = ""
    if name:
        command = "snmp-server target list {name}".format(name=name)
    if config_data.get("host"):
        command += " host {host}".format(host=config_data["host"])
    if config_data.get("vrf"):
        command += " vrf {vrf}".format(vrf=config_data["vrf"])
    return command


def tmplt_traps_isis(config_data):
    isis = config_data.get("traps", {}).get("isis", {})
    command = "snmp-server traps isis"
    if isis.get("all"):
        command += " all"
    else:
        if isis.get("adjacency_change"):
            command += " adjacency-change"
        if isis.get("area_mismatch"):
            command += " area-mismatch"
        if isis.get("attempt_to_exceed_max_sequence"):
            command += " attempt-to-exceed-max-sequence"
        if isis.get("authentication_failure"):
            command += " authentication-failure"
        if isis.get("authentication_type_failure"):
            command += " authentication-type-failure"
        if isis.get("corrupted_lsp_detected"):
            command += " corrupted-lsp-detected"
        if isis.get("database_overload"):
            command += " database-overload"
        if isis.get("id_len_mismatch"):
            command += " id-len-mismatch"
        if isis.get("lsp_error_detected"):
            command += " lsp-error-detected"
        if isis.get("lsp_too_large_to_propagate"):
            command += " lsp-too-large-to-propagate"
        if isis.get("manual_address_drops"):
            command += " manual-address-drops"
        if isis.get("max_area_addresses_mismatch"):
            command += " max-area-addresses-mismatch"
        if isis.get("orig_lsp_buff_size_mismatch"):
            command += " orig-lsp-buff-size-mismatch"
        if isis.get("version_skew"):
            command += " version-skew"
        if isis.get("own_lsp_purge"):
            command += " own-lsp-purge"
        if isis.get("rejected_adjacency"):
            command += " rejected-adjacency"
        if isis.get("protocols_supported_mismatch"):
            command += " protocols-supported-mismatch"
        if isis.get("sequence_number_skip"):
            command += " sequence-number-skip"
    return command


def user_tmplt(config_data):
    user = config_data.get("user", "")
    group = config_data.get("group", "")
    version = config_data.get("version", "")
    command = "snmp-server user {user} {group} {version}".format(
        user=user,
        group=group,
        version=version,
    )
    if config_data.get("acl_v4"):
        command += " IPv4 {acl_v4}".format(acl_v4=config_data["acl_v4"])
    if config_data.get("acl_v6"):
        command += " IPv6 {acl_v6}".format(acl_v6=config_data["acl_v6"])
    if config_data.get("v4_acl"):
        command += " {v4_acl}".format(v4_acl=config_data["v4_acl"])
    if config_data.get("SDROwner"):
        command += " SDROwner"
    elif config_data.get("SystemOwner"):
        command += " SystemOwner"
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
                ^snmp-server
                (\s+chassis-id\s(?P<chassis_id>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server chassis-id {{chassis_id}}",
            "result": {
                "chassis_id": "{{chassis_id}}",
            },
        },
        {
            "name": "communities",
            "getval": re.compile(
                r"""
                ^snmp-server\scommunity
                (\s(?P<name>\S+))?
                (\sRW(?P<rw>))?
                (\sRO(?P<ro>))?
                (\sSDROwner(?P<sdrowner>))?
                (\sSystemOwner(?P<systemowner>))?
                (\sIPv4\s(?P<ipv4>\S+))?
                (\sIPv6\s(?P<ipv6>\S+))?
                (\s(?P<v4acl>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": communities_tmplt,
            "result": {
                "communities": [
                    {
                        "name": "{{ name }}",
                        "rw": "{{ True if rw is defined }}",
                        "ro": "{{ True if ro is defined }}",
                        "acl_v4": "{{ipv4}}",
                        "acl_v6": "{{ipv6}}",
                        "sdrowner": "{{True if sdrowner is defined}}",
                        "systemowner": "{{True if systemowner is defined }}",
                        "v4_acl": "{{v4acl}}",
                    },
                ],
            },
        },
        {
            "name": "community_maps",
            "getval": re.compile(
                r"""
                ^snmp-server\scommunity-map
                (\s(?P<name>\S+))?
                (\scontext\s(?P<context>\S+))?
                (\ssecurity-name\s(?P<security_name>\S+))?
                (\starget-list\s(?P<target_list>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": community_maps_tmplt,
            "result": {
                "community_maps": [
                    {
                        "name": "{{ name }}",
                        "context": "{{context}}",
                        "security_name": "{{security_name}}",
                        "target_list": "{{target_list}}",
                    },
                ],
            },
        },
        {
            "name": "correlator.buffer_size",
            "getval": re.compile(
                r"""
                ^snmp-server\scorrelator
                (\sbuffer-size\s(?P<buffer_size>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server correlator buffer-size {{correlator.buffer_size }}",
            "result": {
                "correlator": {
                    "buffer_size": "{{ buffer_size }}",
                },
            },
        },
        {
            "name": "correlator.rules",
            "getval": re.compile(
                r"""
                ^snmp-server\scorrelator
                (\srule\s(?P<name>\S+))?
                (\s+timeout\s(?P<timeout>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": tmplt_correlator_rule,
            "result": {
                "correlator": {
                    "rules": [
                        {
                            "rule_name": "{{ name }}",
                            "timeout": "{{ timeout }}",

                        },
                    ],
                },
            },
        },
        {
            "name": "correlator.rule_sets",
            "getval": re.compile(
                r"""
                ^snmp-server\scorrelator\sruleset\s(?P<name>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server correlator ruleset {{name}}",
            "result": {
                "correlator": {
                    "rule_sets":
                        [
                            {"name": "{{ name }}"},
                        ],
                },
            },
        },
        {
            "name": "contact",
            "getval": re.compile(
                r"""
                ^snmp-server\scontact\s(?P<name>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server contact {{contact}}",
            "result": {
                "contact": "{{name}}",
            },
        },
        {
            "name": "context",
            "getval": re.compile(
                r"""
                ^snmp-server\scontext\s(?P<name>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server context {{name}}",
            "result": {
                "context": {
                    "{{name}}": "{{name}}",
                },
            },
        },
        {
            "name": "drop.report_IPv4",
            "getval": re.compile(
                r"""
                ^snmp-server\sdrop
                (\sreport\sacl\sIPv4\s(?P<report_IPv4>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server drop report acl IPv4 {{drop.report_IPv4}}",
            "result": {
                "drop": {
                    "report_IPv4": "{{report_IPv4}}",
                },
            },
        },
        {
            "name": "drop.report_IPv6",
            "getval": re.compile(
                r"""
                ^snmp-server\sdrop
                (\sreport\sacl\sIPv6\s(?P<report_IPv6>\S+))

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server drop report acl IPv6 {{drop.report_IPv6}}",
            "result": {
                "drop": {
                    "report_IPv6": "{{report_IPv6}}",
                },
            },
        },
        {
            "name": "drop.unknown_user",
            "getval": re.compile(
                r"""
                ^snmp-server\sdrop
                (\sunknown-user(?P<unknown_user>))

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server drop unknown-user",
            "result": {
                "drop": {
                    "unknown_user": "{{True if unknown_user is defined}}",
                },
            },
        },
        {
            "name": "groups",
            "getval": re.compile(
                r"""
                ^snmp-server
                (\sgroup\s(?P<group>\S+))
                (\s(?P<version>v1|v2c|v3))
                (\snotify\s(?P<notify>\S+))?
                (\sread\s(?P<read>\S+))?
                (\swrite\s(?P<write>\S+))?
                (\scontext\s(?P<context>\S+))?
                (\sIPv4\s(?P<IPv4>\S+))?
                (\sIPv6\s(?P<IPv6>\S+))?
                (\s(?P<v4acl>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": group_tmplt,
            "result": {
                "groups": [
                    {
                        "group": "{{ group }}",
                        "acl_v4": "{{IPv4}}",
                        "acl_v6": "{{IPv6}}",
                        "context": "{{context}}",
                        "notify": "{{notify}}",
                        "read": "{{read}}",
                        "write": "{{write}}",
                        "v4_acl": "{{v4acl}}",
                        "version": "{{version}}",
                    },
                ],
            },
        },
        {
            "name": "hosts",
            "getval": re.compile(
                r"""
                ^snmp-server(\shost\s(?P<host>\S+))
                (\s(?P<traps>traps))?
                (\s(?P<informs>informs))?
                (\sversion\s(?P<version>1|2c|3))?
                (\s(?P<community>\S+))?
                (\sudp-port\s(?P<port>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": host_tmplt,
            "result": {
                "hosts": [
                    {
                        "host": "{{ host }}",
                        "traps": "{{True if traps is defined}}",
                        "informs": "{{True if informs is defined}}",
                        "community": "{{community}}",
                        "udp_port": "{{port}}",
                        "version": "{{version}}",
                    },
                ],
            },
        },
        {
            "name": "ifindex",
            "getval": re.compile(
                r"""
                ^snmp-server(\sifindex\spersist(?P<ifindex>))
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server ifindex persist",
            "result": {
                "ifindex": "{{True if ifindex is defined}}",
            },
        },
        {
            "name": "ifmib.internal_cache_max_duration",
            "getval": re.compile(
                r"""
                ^snmp-server\sifmib
                (\sinternal\scache\smax-duration\s(?P<cache>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server ifmib internal cache max-duration {{ifmib.internal_cache_max_duration}}",
            "result": {
                "ifmib": {
                    "internal_cache_max_duration": "{{cache}}",
                },
            },
        },
        {
            "name": "ifmib.ipsubscriber",
            "getval": re.compile(
                r"""
                ^snmp-server\sifmib
                (\sipsubscriber(?P<ipsub>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server ifmib ipsubscriber",
            "result": {
                "ifmib": {
                    "internal_cache_max_duration": "{{cache}}",
                    "ipsubscriber": "{{True if ipsub is defined}}",
                    "stats": "{{True if s_cache is defined}}",
                    "ifalias_long": "{{True if long is defined}}",
                },
            },
        },
        {
            "name": "ifmib.stats",
            "getval": re.compile(
                r"""
                ^snmp-server\sifmib
                (\sstats\scache(?P<s_cache>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server ifmib stats cache",
            "result": {
                "ifmib": {
                    "stats": "{{True if s_cache is defined}}",
                },
            },
        },
        {
            "name": "ifmib.ifalias_long",
            "getval": re.compile(
                r"""
                ^snmp-server\sifmib
                (\sifalias\slong(?P<long>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server ifmib ifalias long",
            "result": {
                "ifmib": {
                    "ifalias_long": "{{True if long is defined}}",
                },
            },
        },
        {
            "name": "inform.pending",
            "getval": re.compile(
                r"""
                ^snmp-server\sinform
                (\spending\s(?P<pending>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server inform pending {{inform.pending}}",
            "result": {
                "inform": {
                    "pending": "{{pending}}",

                },
            },
        },
        {
            "name": "inform.retries",
            "getval": re.compile(
                r"""
                ^snmp-server\sinform
                (\sretries\s(?P<retries>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server inform retries {{inform.retries}}",
            "result": {
                "inform": {
                    "retries": "{{retries}}",
                },
            },
        },
        {
            "name": "inform.timeout",
            "getval": re.compile(
                r"""
                ^snmp-server\sinform
                (\stimeout\s(?P<timeout>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server inform pending {{inform.timeout}}",
            "result": {
                "inform": {
                    "timeout": "{{timeout}}",

                },
            },
        },
        {
            "name": "interfaces",
            "getval": re.compile(
                r"""
                ^snmp-server(\sinterface\s(?P<interface>\S+))
                (\snotification\slinkupdown\sdisable(?P<notification_linkupdown_disable>))?
                (\sindex\spersistence(?P<index_persistent>))?
                $""", re.VERBOSE,
            ),
            "setval": interfaces_tmplt,
            "result": {
                "interfaces": {
                    "{{interface}}": {
                        "name": "{{ interface }}",
                        "notification_linkupdown_disable": "{{True if notification_linkupdown_disable is defined}}",
                        "index_persistent": "{{True if index_persistent is defined}}",
                    },
                },
            },
        },
        {
            "name": "ipv4.dscp",
            "getval": re.compile(
                r"""
                ^snmp-server
                \sipv4\sdscp\s(?P<dscp>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server ipv4 dscp {{ipv4.dscp}}",
            "result": {
                "ipv4": {
                    "dscp": "{{dscp}}",
                },
            },
        },
        {
            "name": "ipv6.dscp",
            "getval": re.compile(
                r"""
                ^snmp-server
                (\sipv6\sdscp\s(?P<dscp>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server ipv6 dscp {{ipv6.dscp}}",
            "result": {
                "ipv6": {
                    "dscp": "{{dscp}}",
                },
            },
        },
        {
            "name": "ipv4.precedence",
            "getval": re.compile(
                r"""
                ^snmp-server
                (\sipv4\sprecedence\s(?P<precedence>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server ipv4 precedence {{ipv4.precedence}}",
            "result": {
                "ipv4": {"precedence": "{{precedence}}"},
            },
        },
        {
            "name": "ipv6.precedence",
            "getval": re.compile(
                r"""
                ^snmp-server
                (\sipv6\sprecedence\s(?P<precedence>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server ipv6 precedence {{ipv6.precedence}}",
            "result": {
                "ipv6": {"precedence": "{{precedence}}"},
            },
        },
        {
            "name": "location",
            "getval": re.compile(
                r"""
                ^snmp-server(\slocation\s(?P<loc>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server location {{location}}",
            "result": {
                "location": "{{ loc }}",
            },
        },
        {
            "name": "logging_threshold_oid_processing",
            "getval": re.compile(
                r"""
                ^snmp-server(\slogging\sthreshold\soid-processing\s(?P<loc>\d+))
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server logging threshold oid-processing {{logging_threshold_oid_processing}}",
            "result": {
                "logging_threshold_oid_processing": "{{ loc }}",
            },
        },
        {
            "name": "logging_threshold_pdu_processing",
            "getval": re.compile(
                r"""
                ^snmp-server(\slogging\sthreshold\spdu-processing\s(?P<loc>\d+))
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server logging threshold pdu-processing {{logging_threshold_pdu_processing}}",
            "result": {
                "logging_threshold_pdu_processing": "{{ loc }}",
            },
        },
        {
            "name": "mib_bulkstat_max_procmem_size",
            "getval": re.compile(
                r"""
                ^snmp-server(\smib\sbulkstat\smax-procmem-size\s(?P<loc>\d+))
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server mib bulkstat max-procmem-size {{mib_bulkstat_max_procmem_size}}",
            "result": {
                "mib_bulkstat_max_procmem_size": "{{ loc }}",
            },
        },
        {
            "name": "mib_object_lists",
            "getval": re.compile(
                r"""
                ^snmp-server(\smib\sbulkstat\sobject-list\s(?P<o_list>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server mib bulkstat object-list {{mib_object}}",
            "result": {
                "mib_object_lists": {
                    "{{o_list}}": "{{o_list}}",
                },
            },
        },
        {
            "name": "mib_schema",
            "getval": re.compile(
                r"""
                ^snmp-server(\smib\sbulkstat\sschema\s(?P<mib>\S+))
                (\sobject-list\s(?P<o_list>\S+))?
                (\spoll-interval\s(?P<p_interval>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": mib_schema_tmplt,
            "result": {
                "mib_schema": {
                    "{{mib}}": {
                        "name": "{{ mib }}",
                        "poll_interval": "{{p_interval}}",
                        "object_list": "{{o_list}}",
                    },
                },
            },
        },
        {
            "name": "mib_bulkstat_transfer_ids",
            "getval": re.compile(
                r"""
                ^snmp-server(\smib\sbulkstat\stransfer-id\s(?P<mib1>\S+))
                (\sretry\s(?P<retry>\S+))?
                (\sbuffer-size\s(?P<buffer_size>\S+))?
                (\senable(?P<enable>))?
                (\sformat\sschemaASCII(?P<format>))?
                (\sretain\s(?P<retain>\S+))?
                (\sschema\s(?P<schema>\S+))?
                (\stransfer-interval\s(?P<ti>\S+))?

                $""", re.VERBOSE,
            ),
            "setval": mib_bulkstat_transfer_ids_tmplt,
            "result": {
                "mib_bulkstat_transfer_ids": {
                    "{{mib1}}": {
                        "name": "{{ mib1 }}",
                        "buffer_size": "{{buffer_size}}",
                        "enable": "{{True if enable is defined}}",
                        "format_schemaASCI": "{{True if format is defined}}",
                        "retain": "{{retain}}",
                        "schema": "{{schema}}",
                        "retry": "{{retry}}",
                        "transfer_interval": "{{ti}}",
                    },
                },
            },
        },
        {
            "name": "mroutemib_send_all_vrf",
            "getval": re.compile(
                r"""
                ^snmp-server(\smroutemib\ssend-all-vrf(?P<send>))
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server mroutemib send-all-vrf",
            "result": {
                "mroutemib_send_all_vrf": "{{ True if send is defined }}",
            },
        },
        {
            "name": "notification_log_mib.size",
            "getval": re.compile(
                r"""
                ^snmp-server\snotification-log-mib
                (\ssize\s(?P<size>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server notification-log-mib size {{notification_log_mib.size}}",
            "result": {
                "notification_log_mib": {
                    "size": "{{size}}",
                },
            },
        },
        {
            "name": "notification_log_mib.default",
            "getval": re.compile(
                r"""
                ^snmp-server\snotification-log-mib
                (\sdefault(?P<default>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server notification-log-mib default",
            "result": {
                "notification_log_mib": {
                    "default": "{{True if default is defined}}",
                },
            },
        },
        {
            "name": "notification_log_mib.disable",
            "getval": re.compile(
                r"""
                ^snmp-server\snotification-log-mib
                (\sdisable(?P<disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server notification-log-mib disable",
            "result": {
                "notification_log_mib": {
                    "disable": "{{True if disable is defined}}",
                },
            },
        },
        {
            "name": "notification_log_mib.GlobalSize",
            "getval": re.compile(
                r"""
                ^snmp-server\snotification-log-mib
                (\sGlobalSize\s(?P<gsize>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server notification-log-mib GlobalSize {{notification_log_mib.GlobalSize}}",
            "result": {
                "notification_log_mib": {
                    "GlobalSize": "{{gsize}}",

                },
            },
        },
        {
            "name": "oid_poll_stats",
            "getval": re.compile(
                r"""
                ^snmp-server(\soid-poll-stats(?P<oid_stats>))
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server oid-poll-stats",
            "result": {
                "oid_poll_stats": "{{ True if oid_stats is defined }}",
            },
        },
        {
            "name": "overload_control",
            "getval": re.compile(
                r"""
                ^snmp-server\soverload-control
                (\s(?P<overload_drop_time>\d+))?
                (\s(?P<overload_throttle_rate>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": overload_control_tmplt,
            "result": {
                "overload_control": {
                    "overload_drop_time": "{{overload_drop_time}}",
                    "overload_throttle_rate": "{{overload_throttle_rate}}",
                },
            },
        },
        {
            "name": "packetsize",
            "getval": re.compile(
                r"""
                ^snmp-server(\spacketsize\s(?P<packetsize>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server packetsize {{packetsize}}",
            "result": {
                "packetsize": "{{ packetsize }}",
            },
        },
        {
            "name": "queue_length",
            "getval": re.compile(
                r"""
                ^snmp-server(\squeue-length\s(?P<queue_length>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server queue-length {{queue_length}}",
            "result": {
                "queue_length": "{{ queue_length }}",
            },
        },
        {
            "name": "targets",
            "getval": re.compile(
                r"""
                ^snmp-server(\starget\slist\s(?P<targets>\S+))
                (\shost\s(?P<host>\S+))?
                (\svrf\s(?P<vrf>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": targets_tmplt,
            "result": {
                "targets": [
                    {
                        "name": "{{ targets }}",
                        "host": "{{host}}",
                        "vrf": "{{vrf}}",
                    },
                ],
            },
        },
        {
            "name": "throttle_time",
            "getval": re.compile(
                r"""
                ^snmp-server(\sthrottle-time\s(?P<throttle_time>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server throttle-time {{throttle_time}}",
            "result": {
                "throttle_time": "{{ throttle_time }}",
            },
        },
        {
            "name": "timeouts.duplicate",
            "getval": re.compile(
                r"""
                ^snmp-server\stimeouts
                (\sduplicate\s(?P<duplicate>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server timeouts duplicate {{timeouts.duplicate}}",
            "result": {
                "timeouts": {
                    "duplicate": "{{duplicate}}",
                },
            },
        },
        {
            "name": "timeouts.inQdrop",
            "getval": re.compile(
                r"""
                ^snmp-server\stimeouts
                (\sinQdrop\s(?P<inQdrop>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server timeouts inQdrop {{timeouts.inQdrop}}",
            "result": {
                "timeouts": {
                    "inQdrop": "{{inQdrop}}",
                },
            },
        },
        {
            "name": "timeouts.subagent",
            "getval": re.compile(
                r"""
                ^snmp-server\stimeouts
                (\ssubagent\s(?P<subagent>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server timeouts subagent {{timeouts.subagent}}",
            "result": {
                "timeouts": {
                    "subagent": "{{subagent}}",

                },
            },
        },
        {
            "name": "timeouts.pdu_stats",
            "getval": re.compile(
                r"""
                ^snmp-server\stimeouts
                (\spdu\sstats\s(?P<pdu>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server timeouts pdu stats {{timeouts.pdu_stats}}",
            "result": {
                "timeouts": {
                    "pdu_stats": "{{pdu}}",

                },
            },
        },
        {
            "name": "timeouts.threshold",
            "getval": re.compile(
                r"""
                ^snmp-server\stimeouts
                (\sthreshold\s(?P<threshold>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server timeouts threshold {{timeouts.threshold}}",
            "result": {
                "timeouts": {
                    "threshold": "{{threshold}}",
                },
            },
        },
        {
            "name": "trap.throttle_time",
            "getval": re.compile(
                r"""
                ^snmp-server\strap
                (\sthrottle-time\s(?P<throttle_time>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server trap throttle-time {{trap.throttle_time}}",
            "result": {
                "trap": {
                    "throttle_time": "{{throttle_time}}",

                },
            },
        },
        {
            "name": "trap.authentication_vrf_disable",
            "getval": re.compile(
                r"""
                ^snmp-server\strap
                (\sauthentication\svrf\sdisable(?P<authentication_vrf_disable>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server trap authentication vrf disable",
            "result": {
                "trap": {
                    "authentication_vrf_disable": "{{True if authentication_vrf_disable is defined}}",
                },
            },
        },
        {
            "name": "trap.link_ietf",
            "getval": re.compile(
                r"""
                ^snmp-server\strap
                (\slink\sietf(?P<link_ietf>))?
                (\sthrottle-time\s(?P<throttle_time>\d+))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server trap link ietf",
            "result": {
                "trap": {
                    "link_ietf": "{{True if link_ietf is defined}}",
                },
            },
        },
        {
            "name": "trap_source",
            "getval": re.compile(
                r"""
                ^snmp-server(\strap-source\s(?P<trap_source>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server trap-source {{trap_source}}",
            "result": {
                "trap_source": "{{ trap_source }}",
            },
        },
        {
            "name": "trap_timeout",
            "getval": re.compile(
                r"""
                ^snmp-server(\strap-timeout\s(?P<trap_timeout>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server trap-timeout {{trap_timeout}}",
            "result": {
                "trap_timeout": "{{ trap_timeout }}",
            },
        },
        {
            "name": "traps.addrpool.low",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\saddrpool\slow(?P<addrpool_low>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps addrpool low",
            "result": {
                "traps": {
                    "addrpool": {
                        "low": "{{True if addrpool_low is defined}}",
                    },
                },

            },
        },
        {
            "name": "traps.addrpool.high",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\saddrpool\shigh(?P<addrpool_high>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps addrpool high",
            "result": {
                "traps": {
                    "addrpool": {
                        "high": "{{True if addrpool_high is defined}}",
                    },
                },

            },
        },
        {
            "name": "traps.bfd",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sbfd(?P<bfd>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps bfd",
            "result": {
                "traps": {
                    "bfd": "{{True if bfd is defined}}",
                },
            },
        },
        {
            "name": "traps.bgp.cbgp2",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sbgp\scbgp2(?P<bgp_cgp2>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps bgp cbgp2",
            "result": {
                "traps": {

                    "bgp": {
                        "cbgp2": "{{True if bgp_cgp2 is defined}}",
                    },
                },
            },
        },
        {
            "name": "traps.bgp.updown",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sbgp\supdown(?P<bgp_updown>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps bgp updown",
            "result": {
                "traps": {
                    "bgp": {
                        "updown": "{{True if updown is defined}}",
                    },
                },
            },
        },
        {
            "name": "traps.bulkstat_collection",
            "getval": re.compile(
                r"""
                ^snmp-server\straps

                (\sbulkstat\scollection(?P<bulkstat_collection>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps bulkstat collection",
            "result": {
                "traps": {

                    "bulkstat_collection": "{{True if bulkstat_collection is defined}}",

                },
            },
        },
        {
            "name": "traps.bulkstat_transfer",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sbulkstat\stransfer(?P<bulkstat_t>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps bulkstat transfer",
            "result": {
                "traps": {

                    "bulkstat_transfer": "{{True if bulkstat_t is defined}}",

                },
            },
        },
        {
            "name": "traps.bridgemib",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sbridgemib(?P<bridgemib>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps bridgemib",
            "result": {
                "traps": {

                    "bridgemib": "{{True if bridgemib is defined}}",

                },
            },
        },
        {
            "name": "traps.copy_complete",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\scopy-complete(?P<copy_complete>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps copy-complete",
            "result": {
                "traps": {

                    "copy_complete": "{{True if copy_complete is defined}}",

                },
            },
        },
        {
            "name": "traps.cisco_entity_ext",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\scisco-entity-ext(?P<cee>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps cisco-entity-ext",
            "result": {
                "traps": {

                    "cisco_entity_ext": "{{True if cee is defined}}",

                },
            },
        },
        {
            "name": "traps.config",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sconfig(?P<config>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps config",
            "result": {
                "traps": {

                    "config": "{{True if config is defined}}",

                },
            },
        },
        {
            "name": "traps.diameter.peerdown",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sdiameter\speerdown(?P<peerdown>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps diameter peerdown",
            "result": {
                "traps": {
                    "diameter": {
                        "peerdown": "{{True if peerdown is defined}}",
                    },

                },
            },
        },
        {
            "name": "traps.diameter.peerup",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sdiameter\speerup(?P<peerup>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps diameter peerup",
            "result": {
                "traps": {
                    "diameter": {
                        "peerup": "{{True if peerup is defined}}",
                    },

                },
            },
        },
        {
            "name": "traps.diameter.protocolerror",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sdiameter\sprotocolerror(?P<protocolerror>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps diameter protocolerror",
            "result": {
                "traps": {
                    "diameter": {
                        "protocolerror": "{{True if protocolerror is defined}}",
                    },

                },
            },
        },
        {
            "name": "traps.diameter.permanentfail",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sdiameter\spermanentfail(?P<permanentfail>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps diameter permanentfail",
            "result": {
                "traps": {
                    "diameter": {
                        "permanentfail": "{{True if permanentfail is defined}}",
                    },

                },
            },
        },
        {
            "name": "traps.diameter.transientfail",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sdiameter\stransientfail(?P<transientfail>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps diameter transientfail",
            "result": {
                "traps": {
                    "diameter": {
                        "transientfail": "{{True if transientfail is defined}}",
                    },

                },
            },
        },
        {
            "name": "traps.entity",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sentity(?P<entity>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps entity",
            "result": {
                "traps": {
                    "entity": "{{True if entity is defined}}",
                },
            },
        },
        {
            "name": "traps.entity_redundancy.all",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sentity-redundancy\sall(?P<all>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps entity-redundancy all",
            "result": {
                "traps": {
                    "entity_redundancy": {
                        "all": "{{True if all is defined }}",

                    },

                },
            },
        },
        {
            "name": "traps.entity_redundancy.status",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sentity-redundancy\sstatus(?P<status>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps entity-redundancy status",
            "result": {
                "traps": {
                    "entity_redundancy": {
                        "status": "{{True if status is defined }}",

                    },

                },
            },
        },
        {
            "name": "traps.entity_redundancy.switchover",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sentity-redundancy\sswitchover(?P<switchover>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps entity-redundancy switchover",
            "result": {
                "traps": {
                    "entity_redundancy": {
                        "switchover": "{{True if switchover is defined }}",

                    },

                },
            },
        },
        {
            "name": "traps.entity_state.operstatus",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sentity-state\soperstatus(?P<operstatus>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps entity-state operstatus",
            "result": {
                "traps": {
                    "entity_state": {
                        "operstatus": "{{True if operstatus is defined }}",

                    },

                },
            },
        },
        {
            "name": "traps.entity_state.switchover",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sentity-state\sswitchover(?P<switchover>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps entity-state switchover",
            "result": {
                "traps": {
                    "entity_state": {
                        "switchover": "{{True if switchover is defined }}",

                    },

                },
            },
        },
        {
            "name": "traps.flash.insertion",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                 (\sflash\sinsertion(?P<f_insertion>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps flash insertion",
            "result": {
                "traps": {
                    "flash": {
                        "insertion": "{{True if f_insertion is defined }}",

                    },

                },
            },
        },
        {
            "name": "traps.flash.removal",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                 (\sflash\sremoval(?P<f_removal>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps flash removal",
            "result": {
                "traps": {
                    "flash": {
                        "removal": "{{True if f_removal is defined }}",

                    },

                },
            },
        },
        {
            "name": "traps.fru_ctrl",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                 (\sfru-ctrl(?P<fru_ctrl>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps fru-ctrl",
            "result": {
                "traps": {
                    "fru_ctrl": "{{True if fru_ctrl is defined }}",
                },
            },
        },
        {
            "name": "traps.hsrp",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                 (\shsrp(?P<hsrp>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps hsrp",
            "result": {
                "traps": {
                    "hsrp": "{{True if hsrp is defined }}",
                },
            },
        },
        {
            "name": "traps.ipsla",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                 (\sipsla(?P<ipsla>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ipsla",
            "result": {
                "traps": {
                    "ipsla": "{{True if ipsla is defined }}",
                },
            },
        },
        {
            "name": "traps.ipsec.start",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                 (\sipsec\stunnel\sstart(?P<ipsec_start>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ipsec tunnel start",
            "result": {
                "traps": {
                    "ipsec": {
                        "start": "{{True if ipsec_start is defined}}",
                    },
                },
            },
        },
        {
            "name": "traps.ipsec.stop",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                 (\sipsec\stunnel\sstop(?P<ipsec_stop>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ipsec tunnel stop",
            "result": {
                "traps": {
                    "ipsec": {
                        "stop": "{{True if ipsec_stop is defined}}",
                    },
                },
            },
        },
        {
            "name": "traps.isakmp.start",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                 (\sisakmp\stunnel\sstart(?P<isakmp_start>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps isakmp tunnel start",
            "result": {
                "traps": {
                    "isakmp": {
                        "start": "{{True if isakmp_start is defined}}",
                    },

                },
            },
        },
        {
            "name": "traps.isakmp.stop",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                 (\sisakmp\stunnel\sstop(?P<isakmp_stop>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps isakmp tunnel stop",
            "result": {
                "traps": {
                    "isakmp": {
                        "stop": "{{True if isakmp_stop is defined}}",
                    },
                },
            },
        },
        {
            "name": "traps.isis",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sisis\sall(?P<isis_all>))?
                (\sisis(\sdatabase-overload(?P<database_overload>))?(\smanual-address-drops(?P<manual_address_drops>))?
                (\scorrupted-lsp-detected(?P<corrupted_lsp_detected>))?
                (\sattempt-to-exceed-max-sequence(?P<attempt_to_exceed_max_sequence>))?
                (\sid-len-mismatch(?P<id_len_mismatch>))?
                (\smax-area-addresses-mismatch(?P<max_area_addresses_mismatch>))?
                (\sown-lsp-purge(?P<own_lsp_purge>))?
                (\ssequence-number-skip(?P<sequence_number_skip>))?
                (\sauthentication-type-failure(?P<authentication_type_failure>))?
                (\sauthentication-failure(?P<authentication_failure>))?
                (\sversion-skew(?P<version_skew>))?
                (\sarea-mismatch(?P<area_mismatch>))?
                (\srejected-adjacency(?P<rejected_adjacency>))?
                (\slsp-too-large-to-propagate(?P<lsp_too_large_to_propagate>))?
                (\sorig-lsp-buff-size-mismatch(?P<orig_lsp_buff_size_mismatch>))?
                (\sprotocols-supported-mismatch(?P<protocols_supported_mismatch>))?
                (\sadjacency-change(?P<adjacency_change>))?
                (\slsp-error-detected(?P<lsp_error_detected>))?)?
                $""", re.VERBOSE,
            ),
            "setval": tmplt_traps_isis,
            "result": {
                "traps": {

                    "isis": {
                        "all": "{{True if isis_all is defined}}",
                        "id_len_mismatch": "{{True if id_len_mismatch is defined}}",
                        "database_overload": "{{True if database_overload is defined}}",
                        "manual_address_drops": "{{True if manual_address_drops is defined}}",
                        "corrupted_lsp_detected": "{{True if corrupted_lsp_detected is defined}}",
                        "attempt_to_exceed_max_sequence": "{{True if attempt_to_exceed_max_sequence is defined}}",
                        "max_area_addresses_mismatch": "{{True if max_area_addresses_mismatch is defined}}",
                        "own_lsp_purge": "{{True if own_lsp_purge is defined}}",
                        "sequence_number_skip": "{{True if sequence_number_skip is defined}}",
                        "authentication_type_failure": "{{True if authentication_type_failure is defined}}",
                        "authentication_failure": "{{True if authentication_failure is defined}}",
                        "version_skew": "{{True if version_skew is defined}}",
                        "area_mismatch": "{{True if area_mismatch is defined}}",
                        "rejected_adjacency": "{{True if rejected_adjacency is defined}}",
                        "lsp_too_large_to_propagate": "{{True if lsp_too_large_to_propagate is defined}}",
                        "orig_lsp_buff_size_mismatch": "{{True if orig_lsp_buff_size_mismatch is defined}}",
                        "protocols_supported_mismatch": "{{True if protocols_supported_mismatch is defined}}",
                        "adjacency_change": "{{True if adjacency_change is defined}}",
                        "lsp_error_detected": "{{True if lsp_error_detected is defined}}",

                    },

                },
            },
        },
        {
            "name": "traps.l2tun.pseudowire_status",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sl2tun\spseudowire-status(?P<pseudowire_status>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps l2tun pseudowire-status",
            "result": {
                "traps": {

                    "l2tun": {
                        "pseudowire_status": "{{True if pseudowire_status is defined}}",

                    },

                },
            },
        },
        {
            "name": "traps.l2tun.sessions",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sl2tun\ssessions(?P<sessions>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps l2tun sessions",
            "result": {
                "traps": {

                    "l2tun": {
                        "sessions": "{{True if sessions is defined}}",

                    },

                },
            },
        },
        {
            "name": "traps.l2tun.tunnel_down",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sl2tun\stunnel-down(?P<tunnel_down>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps l2tun tunnel-down",
            "result": {
                "traps": {

                    "l2tun": {
                        "tunnel_down": "{{True if tunnel_down is defined}}",

                    },

                },
            },
        },
        {
            "name": "traps.l2tun.tunnel_up",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sl2tun\stunnel-up(?P<tunnel_up>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps l2tun tunnel-up",
            "result": {
                "traps": {

                    "l2tun": {
                        "tunnel_up": "{{True if tunnel_up is defined}}",

                    },

                },
            },
        },
        {
            "name": "traps.l2vpn.all",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sl2vpn\sall(?P<vpnall>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps l2vpn all",
            "result": {
                "traps": {

                    "l2vpn": {
                        "all": "{{True if vpnall is defined}}",

                    },

                },
            },
        },
        {
            "name": "traps.l2vpn.cisco",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sl2vpn\scisco(?P<cisco>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps l2vpn cisco",
            "result": {
                "traps": {

                    "l2vpn": {
                        "cisco": "{{True if cisco is defined}}",

                    },

                },
            },
        },
        {
            "name": "traps.l2vpn.vc_up",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sl2vpn\svc-up(?P<vc_up>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps l2vpn vc-up",
            "result": {
                "traps": {

                    "l2vpn": {
                        "vc_up": "{{True if vc_up is defined}}",

                    },

                },
            },
        },
        {
            "name": "traps.l2vpn.vc_down",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sl2vpn\svc-down(?P<vc_down>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps l2vpn vc-down",
            "result": {
                "traps": {

                    "l2vpn": {
                        "vc_down": "{{True if vc_down is defined}}",

                    },

                },
            },
        },
        {
            "name": "traps.msdp_peer_state_change",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                 (\smsdp\speer-state-change(?P<msdp>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps msdp peer-state-change",
            "result": {
                "traps": {

                    "msdp_peer_state_change": "{{True if msdp is defined }}",

                },
            },
        },
        {
            "name": "traps.ospf.retransmit.packets",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospf\sretransmit\spackets(?P<packets>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospf retransmit packets",
            "result": {
                "traps": {

                    "ospf": {

                        "retransmit": {
                            "packets": "{{True if packets is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospf.retransmit.virt_packets",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospf\sretransmit\svirt-packets(?P<virt_packets>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospf retransmit virt-packets",
            "result": {
                "traps": {

                    "ospf": {
                        "retransmit": {
                            "virt_packets": "{{True if virt_packets is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospf.lsa.lsa_maxage",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospf\slsa\slsa-maxage(?P<lsa_maxage>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospf lsa lsa-maxage",
            "result": {
                "traps": {

                    "ospf": {

                        "lsa": {
                            "lsa_maxage": "{{True if lsa_maxage is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospf.lsa.lsa_originate",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospf\slsa\slsa-originate(?P<lsa_originate>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospf lsa lsa-originate",
            "result": {
                "traps": {

                    "ospf": {

                        "lsa": {
                            "lsa_originate": "{{True if lsa_originate is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospf.errors.bad_packet",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospf\serrors\sbad-packet(?P<bad_packet>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospf errors bad-packet",
            "result": {
                "traps": {

                    "ospf": {

                        "errors": {
                            "bad_packet": "{{True if bad_packet is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospf.errors.authentication_failure",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospf\serrors\sauthentication-failure(?P<authentication_failure_ospf>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospf errors authentication-failure",
            "result": {
                "traps": {

                    "ospf": {

                        "errors": {
                            "authentication_failure": "{{True if authentication_failure_ospf is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospf.errors.config_error",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospf\serrors\sconfig-error(?P<config_error>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospf errors config-error",
            "result": {
                "traps": {

                    "ospf": {

                        "errors": {
                            "config_error": "{{True if config_error is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospf.errors.virt_bad_packet",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospf\serrors\svirt-bad-packet(?P<virt_bad_packet>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospf errors virt-bad-packet",
            "result": {
                "traps": {

                    "ospf": {

                        "errors": {
                            "virt_bad_packet": "{{True if virt_bad_packet is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospf.errors.virt_authentication_failure",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospf\serrors\svirt-authentication-failure(?P<virt_authentication_failure>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospf errors virt-authentication-failure",
            "result": {
                "traps": {

                    "ospf": {

                        "errors": {
                            "virt_authentication_failure": "{{True if virt_authentication_failure is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospf.errors.virt_config_error",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospf\serrors\svirt-config-error(?P<virt_config_error>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospf errors virt-config-error",
            "result": {
                "traps": {

                    "ospf": {

                        "errors": {
                            "virt_config_error": "{{True if virt_config_error is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospf.state_change.if_state_change",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospf\sstate-change\sif-state-change(?P<if_state_change>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospf state-change if-state-change",
            "result": {
                "traps": {

                    "ospf": {

                        "state_change": {
                            "if_state_change": "{{True if if_state_change is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospf.state_change.neighbor_state_change",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospf\sstate-change\sneighbor-state-change(?P<neighbor_state_change>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospf state-change neighbor-state-change",
            "result": {
                "traps": {

                    "ospf": {

                        "state_change": {
                            "neighbor_state_change": "{{True if neighbor_state_change is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospf.state_change.virtif_state_change",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospf\sstate-change\svirtif-state-change(?P<virtif_state_change>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospf state-change virtif-state-change",
            "result": {
                "traps": {

                    "ospf": {

                        "state_change": {
                            "virtif_state_change": "{{True if virtif_state_change is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospf.state_change.virtneighbor_state_change",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospf\sstate-change\svirtneighbor-state-change(?P<virtneighbor_state_change>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospf state-change virtneighbor-state-change",
            "result": {
                "traps": {

                    "ospf": {

                        "state_change": {
                            "virtneighbor_state_change": "{{True if virtneighbor_state_change is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospfv3.errors.bad_packet",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospfv3\serrors\sbad-packet(?P<bad_packet>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospfv3 errors bad-packet",
            "result": {
                "traps": {

                    "ospfv3": {

                        "errors": {
                            "bad_packet": "{{True if bad_packet is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospfv3.errors.authentication_failure",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospfv3\serrors\sauthentication-failure(?P<authentication_failure_ospf>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospfv3 errors authentication-failure",
            "result": {
                "traps": {

                    "ospfv3": {

                        "errors": {
                            "authentication_failure": "{{True if authentication_failure_ospf is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospfv3.errors.config_error",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospfv3\serrors\sconfig-error(?P<config_error>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospfv3 errors config-error",
            "result": {
                "traps": {

                    "ospfv3": {

                        "errors": {
                            "config_error": "{{True if config_error is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospfv3.errors.virt_config_error",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospfv3\serrors\svirt-config-error(?P<virt_config_error>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospfv3 errors virt-config-error",
            "result": {
                "traps": {

                    "ospfv3": {

                        "errors": {
                            "virt_config_error": "{{True if virt_config_error is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospfv3.errors.virt_bad_packet",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospfv3\serrors\svirt-bad-packet(?P<virt_bad_packet>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospfv3 errors virt-bad-packet",
            "result": {
                "traps": {

                    "ospfv3": {

                        "errors": {
                            "virt_bad_packet": "{{True if virt_bad_packet is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospfv3.state_change.if_state_change",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospfv3\sstate-change\sif-state-change(?P<if_state_change>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospfv3 state-change if-state-change",
            "result": {
                "traps": {

                    "ospfv3": {

                        "state_change": {
                            "if_state_change": "{{True if if_state_change is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospfv3.state_change.neighbor_state_change",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospfv3\sstate-change\sneighbor-state-change(?P<neighbor_state_change>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospfv3 state-change neighbor-state-change",
            "result": {
                "traps": {

                    "ospfv3": {

                        "state_change": {
                            "neighbor_state_change": "{{True if neighbor_state_change is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospfv3.state_change.virtif_state_change",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospfv3\sstate-change\svirtif-state-change(?P<virtif_state_change>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospfv3 state-change virtif-state-change",
            "result": {
                "traps": {

                    "ospfv3": {

                        "state_change": {
                            "virtif_state_change": "{{True if virtif_state_change is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospfv3.state_change.virtneighbor_state_change",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospfv3\sstate-change\svirtneighbor-state-change(?P<virtneighbor_state_change>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospfv3 state-change virtneighbor-state-change",
            "result": {
                "traps": {

                    "ospfv3": {

                        "state_change": {
                            "virtneighbor_state_change": "{{True if virtneighbor_state_change is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospfv3.state_change.restart_status_change",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospfv3\sstate-change\srestart-status-change(?P<restart_status_change>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospfv3 state-change restart-status-change",
            "result": {
                "traps": {

                    "ospfv3": {

                        "state_change": {
                            "restart_status_change": "{{True if restart_status_change is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospfv3.state_change.restart_helper_status_change",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospfv3\sstate-change\srestart-helper-status-change(?P<restart_helper_status_change>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospfv3 state-change restart-helper-status-change",
            "result": {
                "traps": {

                    "ospfv3": {

                        "state_change": {
                            "restart_helper_status_change": "{{True if restart_helper_status_change is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospfv3.state_change.restart_virtual_helper_status_change",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospfv3\sstate-change\srestart-virtual-helper-status-change(?P<restart_virtual_helper_status_change>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospfv3 state-change restart-virtual-helper-status-change",
            "result": {
                "traps": {

                    "ospfv3": {

                        "state_change": {
                            "restart_virtual_helper_status_change": "{{True if restart_virtual_helper_status_change is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.ospfv3.state_change.nssa_state_change",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sospfv3\sstate-change\snssa-state-change(?P<nssa_state_change>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps ospfv3 state-change nssa-state-change",
            "result": {
                "traps": {

                    "ospfv3": {

                        "state_change": {
                            "nssa_state_change": "{{True if nssa_state_change is defined}}",

                        },

                    },

                },
            },
        },
        {
            "name": "traps.power",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\spower(?P<power>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps power",
            "result": {
                "traps": {
                    "power": "{{True if power is defined }}",

                },
            },
        },
        {
            "name": "traps.rf",
            "getval": re.compile(
                r"""
                ^snmp-server\straps


                (\spower(?P<power>))?
                (\srf(?P<rf>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps rf",
            "result": {
                "traps": {
                    "rf": "{{True if rf is defined}}",

                },
            },
        },
        {
            "name": "traps.pim.neighbor_change",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\spim\sneighbor-change(?P<neighbor_change>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps pim neighbor-change",
            "result": {
                "traps": {

                    "pim": {

                        "neighbor_change": "{{True if neighbor_change is defined}}",

                    },

                },
            },
        },
        {
            "name": "traps.pim.invalid_message_received",
            "getval": re.compile(
                r"""
                ^snmp-server\straps



                (\spim\sinvalid-message-received(?P<invalid_message_received>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps pim invalid-message-received",
            "result": {
                "traps": {

                    "pim": {

                        "invalid_message_received": "{{True if invalid_message_received is defined}}",

                    },

                },
            },
        },
        {
            "name": "traps.pim.rp_mapping_change",
            "getval": re.compile(
                r"""
                ^snmp-server\straps



                (\spim\srp-mapping-change(?P<rp_mapping_change>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps pim rp-mapping-change",
            "result": {
                "traps": {

                    "pim": {

                        "rp_mapping_change": "{{True if rp_mapping_change is defined}}",

                    },

                },
            },
        },
        {
            "name": "traps.pim.interface_state_change",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\spim\sinterface-state-change(?P<interface_state_change>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps pim interface-state-change",
            "result": {
                "traps": {
                    "pim": {
                        "interface_state_change": "{{True if interface_state_change is defined}}",
                    },

                },
            },
        },
        {
            "name": "traps.rsvp.lost_flow",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\srsvp\slost-flow(?P<lost_flow>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps rsvp lost-flow",
            "result": {
                "traps": {
                    "rsvp": {
                        "lost_flow": "{{True if lost_flow is defined}}",
                    },
                },
            },
        },
        {
            "name": "traps.rsvp.new_flow",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\srsvp\snew-flow(?P<new_flow>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps rsvp new-flow",
            "result": {
                "traps": {
                    "rsvp": {
                        "new_flow": "{{True if new_flow is defined}}",
                    },

                },

            },
        },
        {
            "name": "traps.rsvp.all",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\srsvp\sall(?P<all>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps rsvp all",
            "result": {
                "traps": {
                    "rsvp": {
                        "all": "{{True if all is defined}}",
                    },

                },

            },
        },
        {
            "name": "traps.selective_vrf_download_role_change",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\sselective-vrf-download\srole-change(?P<selective_vrf_download_role_change>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps selective-vrf-download role-change",
            "result": {
                "traps": {
                    "selective_vrf_download_role_change": "{{True if selective_vrf_download_role_change is defined}}",
                },
            },
        },
        {
            "name": "traps.sensor",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\ssensor(?P<sensor>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps sensor",
            "result": {
                "traps": {"sensor": "{{True if sensor is defined}}"},
            },
        },
        {
            "name": "traps.vrrp_events",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\svrrp\sevents(?P<vrrp_events>))?


                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps vrrp events",
            "result": {

                "traps": {
                    "vrrp_events": "{{True if vrrp_events is defined}}",
                },
            },
        },
        {
            "name": "traps.syslog",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\ssyslog(?P<syslog>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps syslog",
            "result": {
                "traps": {"syslog": "{{True if syslog is defined}}"},

            },
        },
        {
            "name": "traps.system",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\ssystem(?P<system>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps system",
            "result": {
                "traps": {"system": "{{True if system is defined}}"},

            },
        },
        {
            "name": "traps.subscriber.session_agg_access_interface",
            "getval": re.compile(
                r"""
                ^snmp-server\straps

                (\ssubscriber\ssession-agg\saccess-interface(?P<session_agg_access_interface>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps subscriber session-agg access-interface",
            "result": {
                "traps": {
                    "subscriber": {
                        "session_agg_access_interface": "{{True if session_agg_access_interface is defined}}",
                    },
                },
            },
        },
        {
            "name": "traps.subscriber.session_agg_node",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\ssubscriber\ssession-agg\snode(?P<session_agg_node>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps subscriber session-agg node",
            "result": {
                "traps": {
                    "subscriber": {
                        "session_agg_node": "{{True if session_agg_node is defined}}",
                    },

                },
            },

        },
        {
            "name": "traps.vpls.all",
            "getval": re.compile(
                r"""
                ^snmp-server\straps

                (\svpls\sall(?P<vpls_all>))?


                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps vpls all",
            "result": {
                "traps": {

                    "vpls": {
                        "all": "{{True if vpls_all is defined}}",

                    },

                },
            },
        },
        {
            "name": "traps.vpls.full_clear",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\svpls\sfull-clear(?P<full_clear>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps vpls full-clear",
            "result": {
                "traps": {
                    "vpls": {
                        "full_clear": "{{True if full_clear is defined}}",
                    },

                },
            },
        },
        {
            "name": "traps.vpls.full_raise",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\svpls\sfull-raise(?P<full_raise>))?

                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps vpls full-raise",
            "result": {
                "traps": {
                    "vpls": {
                        "full_raise": "{{True if full_raise is defined}}",
                    },

                },
            },
        },
        {
            "name": "traps.vpls.status",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\svpls\sstatus(?P<vpls_status>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps vpls status",
            "result": {
                "traps": {
                    "vpls": {
                        "status": "{{True if vpls_status is defined}}",
                    },

                },
            },
        },
        {
            "name": "traps.snmp.linkup",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\ssnmp\slinkup(?P<linkup>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps snmp linkup",
            "result": {
                "traps": {
                    "snmp": {
                        "linkup": "{{True if linkup is defined}}",
                    },
                },
            },
        },
        {
            "name": "traps.snmp.linkdown",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\ssnmp\slinkdown(?P<linkdown>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps snmp linkdown",
            "result": {
                "traps": {

                    "snmp": {
                        "linkdown": "{{True if linkdown is defined}}",
                    },
                },
            },
        },
        {
            "name": "traps.snmp.coldstart",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\ssnmp\scoldstart(?P<coldstart>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps snmp coldstart",
            "result": {
                "traps": {

                    "snmp": {

                        "coldstart": "{{True if coldstart is defined}}",

                    },
                },
            },
        },
        {
            "name": "traps.snmp.warmstart",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\ssnmp\swarmstart(?P<warmstart>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps snmp warmstart",
            "result": {
                "traps": {

                    "snmp": {
                        "warmstart": "{{True if warmstart is defined}}",
                    },
                },
            },
        },
        {
            "name": "traps.snmp.authentication",
            "getval": re.compile(
                r"""
                ^snmp-server\straps
                (\ssnmp\sauthentication(?P<authentication>))?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server traps snmp authentication",
            "result": {
                "traps": {

                    "snmp": {
                        "authentication": "{{True if authentication is defined}}",
                    },
                },
            },
        },
        {
            "name": "users",
            "getval": re.compile(
                r"""
                ^snmp-server\suser
                (\s(?P<name>\S+))
                (\s(?P<group>\S+))
                (\s(?P<version>v1|v2c|v3))
                (\sIPv4\s(?P<ipv4>\S+))?
                (\sIPv6\s(?P<ipv6>\S+))?
                (\s(?P<v4acl>\S+))?
                (\sSDROwner\s(?P<sdrowner>))?
                (\sSystemOwner\s(?P<systemowner>))?
                $""", re.VERBOSE,
            ),
            "setval": user_tmplt,
            "result": {
                "users": [
                    {
                        "user": "{{ name }}",
                        "group": "{{ group }}",
                        "acl_v4": "{{ipv4}}",
                        "acl_v6": "{{ipv6}}",
                        "SDROwner": "{{True if sdowner is defined}}",
                        "SystemOwner": "{{True if systemowner is defined }}",
                        "v4_acl": "{{v4acl}}",
                        "version": "{{version}}",
                    },
                ],
            },
        },
        {
            "name": "vrfs",
            "getval": re.compile(
                r"""
                ^snmp-server\svrf
                (\s(?P<vrf>\S+))
                (\scontext\s(?P<context>\S+))?
                ((\shost\s(?P<host>\S+))?
                (\s(?P<traps>traps))?
                (\s(?P<informs>informs))?
                (\sversion\s(?P<version>1|2c|3))?
                (\s(?P<community>\S+))?
                (\sudp-port\s(?P<port>\d+))?)?
                $""", re.VERBOSE,
            ),
            "setval": "snmp-server vrf {{vrf}}",
            "result": {
                "vrfs": {
                    "{{vrf}}": {
                        "vrf": "{{vrf}}",
                        "context": {
                            "name_{{context|d()}}": "{{context}}",
                        },
                        "hosts": [
                            {
                                "host": "{{ host }}",
                                "traps": "{{True if traps is defined}}",
                                "informs": "{{True if informs is defined}}",
                                "community": "{{community}}",
                                "udp_port": "{{port}}",
                                "version": "{{version}}",
                            },
                        ],
                    },
                },
            },
        },
    ]
    # fmt: on
