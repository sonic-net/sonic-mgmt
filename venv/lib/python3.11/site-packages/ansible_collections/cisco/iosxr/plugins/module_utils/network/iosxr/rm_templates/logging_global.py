# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The Logging_global parser templates file. This contains
a list of parser definitions and associated functions that
facilitates both facts gathering and native command generation for
the given network resource.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


def tmplt_host(config_data):
    command = "logging"
    if config_data.get("host"):
        command += " {host}".format(host=config_data["host"])
    if config_data.get("vrf"):
        command += " vrf {vrf}".format(vrf=config_data["vrf"])
    if config_data.get("severity"):
        command += " severity {severity}".format(
            severity=config_data["severity"],
        )
    if config_data.get("port"):
        command += " port {port}".format(port=config_data["port"])
    return command


def tmplt_correlator_rule(config_data):
    commands = []
    rule_name = config_data.get("rule_name")
    rule_type = config_data.get("rule_type")
    base_command = "logging correlator rule {rule_name} type {rule_type}".format(
        rule_type=rule_type,
        rule_name=rule_name,
    )
    if config_data.get("timeout"):
        commands.append(
            "{base_command} timeout {timeout}".format(
                timeout=config_data["timeout"],
                base_command=base_command,
            ),
        )
    if config_data.get("timeout_rootcause"):
        commands.append(
            "{base_command} timeout-rootcause {timeout}".format(
                timeout=config_data["timeout_rootcause"],
                base_command=base_command,
            ),
        )
    if config_data.get("reissue_nonbistate"):
        commands.append(
            "{base_command} reissue-nonbistate".format(
                base_command=base_command,
            ),
        )
    if config_data.get("reparent"):
        commands.append(
            "{base_command} reparent".format(base_command=base_command),
        )
    if config_data.get("context_correlation"):
        commands.append(
            "{base_command} context-correlation".format(
                base_command=base_command,
            ),
        )
    return commands


def tmplt_correlator_ruleset(config_data):
    command = "logging correlator ruleset"
    if config_data.get("name"):
        command += "  {name}".format(name=config_data["name"])
    if config_data.get("rulename"):
        command += "  rulename {rulename}".format(
            rulename=config_data["rulename"],
        )
    return command


def tmplt_files(config_data):
    command = "logging"
    if config_data.get("name"):
        command += " file {name}".format(name=config_data["name"])
    if config_data.get("path"):
        command += " path {path}".format(path=config_data["path"])
    if config_data.get("maxfilesize"):
        command += " maxfilesize {maxfilesize}".format(
            maxfilesize=config_data["maxfilesize"],
        )
    if config_data.get("severity"):
        command += " severity {severity}".format(
            severity=config_data["severity"],
        )
    return command


def tmplt_source_interface(config_data):
    command = "logging source-interface"
    if config_data.get("interface"):
        command += " {interface}".format(interface=config_data["interface"])
    if config_data.get("vrf"):
        command += " vrf {vrf}".format(vrf=config_data["vrf"])
    return command


def tmplt_tls_servers(config_data):
    commands = []
    name = config_data.get("name")
    base_command = "logging tls-server {name}".format(name=name)
    if config_data.get("tls_hostname"):
        commands.append(
            "{base_command} tls-hostname {tls}".format(
                tls=config_data["tls_hostname"],
                base_command=base_command,
            ),
        )
    if config_data.get("trustpoint"):
        commands.append(
            "{base_command} trustpoint {trustpoint}".format(
                trustpoint=config_data["trustpoint"],
                base_command=base_command,
            ),
        )
    if config_data.get("vrf"):
        commands.append(
            "{base_command} vrf {vrf}".format(
                vrf=config_data["vrf"],
                base_command=base_command,
            ),
        )
    if config_data.get("severity"):
        commands.append(
            "{base_command} severity {severity}".format(
                severity=config_data["severity"],
                base_command=base_command,
            ),
        )
    if len(commands) == 0:
        commands.append(base_command)
    return commands


def rem_tmplt_tls_servers(config_data):
    command = "logging tls-server"
    if config_data.get("name"):
        command += " {name}".format(name=config_data["name"])
    return command


class Logging_globalTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(Logging_globalTemplate, self).__init__(
            lines=lines,
            tmplt=self,
            module=module,
        )

    # fmt: off
    PARSERS = [
        {
            "name": "archive.device",
            "getval": re.compile(
                r"""
                ^logging\sarchive
                (\s+device\s(?P<device>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "logging archive device {{archive.device}}",
            "result": {
                "archive": {
                    "device": "{{ device }}",
                },
            },
        },
        {
            "name": "archive.severity",
            "getval": re.compile(
                r"""
                ^logging\sarchive
                (\s+severity\s(?P<severity>alerts|critical|debugging|emergencies|errors|informational|notifications|warnings))
                $""", re.VERBOSE,
            ),
            "setval": "logging archive severity {{archive.severity}}",
            "result": {
                "archive": {
                    "severity": "{{severity}}",
                },
            },
        },
        {
            "name": "archive.file_size",
            "getval": re.compile(
                r"""
                ^logging\sarchive
                (\s+file-size\s(?P<file_size>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "logging archive file-size {{archive.file_size}}",
            "result": {
                "archive": {
                    "file_size": "{{ file_size }}",
                },
            },
        },
        {
            "name": "archive.frequency",
            "getval": re.compile(
                r"""
                ^logging\sarchive
                (\s+frequency\s(?P<frequency>daily|weekly))?
                $""", re.VERBOSE,
            ),
            "setval": "logging archive frequency {{archive.frequency}}",
            "result": {
                "archive": {
                    "frequency": "{{ frequency }}",
                },
            },
        },
        {
            "name": "archive.archive_size",
            "getval": re.compile(
                r"""
                ^logging\sarchive
                (\s+archive-size\s(?P<archive_size>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "logging archive archive-size {{archive.archive_size}}",
            "result": {
                "archive": {
                    "archive_size": "{{ archive_size }}",
                },
            },
        },
        {
            "name": "archive.archive_length",
            "getval": re.compile(
                r"""
                ^logging\sarchive
                (\s+archive-length\s(?P<archive_length>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "logging archive archive-length {{archive.archive_length}}",
            "result": {
                "archive": {
                    "archive_length": "{{ archive_length}}",
                },
            },
        },
        {
            "name": "hosts",
            "getval": re.compile(
                r"""
                ^logging
                (\s(?P<host>\S+))?
                (\svrf\s(?P<vrf>\w+))?
                (\sseverity\s(?P<severity>alerts|critical|debugging|emergencies|error|informational|notifications|warnings))?
                (\sport\s(?P<port>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": tmplt_host,
            "result": {
                "hosts": [{
                    "host": "{{ host }}",
                    "port": "{{ port }}",
                    "vrf": "{{ vrf }}",
                    "severity": "{{severity}}",
                }],
            },

        },
        {
            "name": "buffered.size",
            "getval": re.compile(
                r"""
                ^logging\sbuffered
                (\s(?P<size>[1-9][0-9]*))?
                $""", re.VERBOSE,
            ),
            "setval": "logging buffered {{buffered.size}}",
            "result": {
                "buffered": {
                    "size": "{{ size }}",
                },

            },
        },
        {
            "name": "buffered.severity",
            "getval": re.compile(
                r"""
                ^logging\sbuffered
                (\s(?P<severity>alerts|critical|debugging|emergencies|errors|informational|notifications|warnings))?
                $""", re.VERBOSE,
            ),
            "setval": "logging buffered {{buffered.severity}}",
            "result": {

                "buffered": {
                    "severity": "{{ severity }}",
                },
            },

        },
        {
            "name": "buffered.discriminator",
            "getval": re.compile(
                r"""
                ^logging\sbuffered\sdiscriminator
                \s+(?P<match_nomatch>\S+)\s(?P<name>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "logging buffered discriminator {{match_params}} {{name}}",
            "result": {
                "buffered": {
                    "discriminator": [
                        {
                            "match_params": "{{ match_nomatch }}",
                            "name": "{{name}}",
                        },
                    ],
                },

            },
        },
        {
            "name": "console.severity",
            "getval": re.compile(
                r"""
                ^logging\sconsole
                (\s(?P<severity>alerts|critical|debugging|emergencies|errors|informational|notifications|warning$))?
                $""", re.VERBOSE,
            ),
            "setval": "logging console {{console.severity}}",
            "result": {
                "console": {
                    "severity": "{{ severity }}",
                },
            },
        },
        {
            "name": "console.state",
            "getval": re.compile(
                r"""
                ^logging\sconsole
                \s(?P<disable>disable)
                $""", re.VERBOSE,
            ),
            "setval": "{{ 'logging console disable' if console.state =='disabled' else 'no logging console disable' }}",
            "result": {
                "console": {
                    "state": "{{ 'disabled' if disable is defined }}",
                },
            },
        },
        {
            "name": "console.discriminator",
            "getval": re.compile(
                r"""
                ^logging\sconsole\sdiscriminator
                \s+(?P<match_nomatch>\S+)\s(?P<name>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "logging console discriminator {{match_params}} {{name}}",
            "result": {
                "console": {
                    "discriminator": [
                        {
                            "match_params": "{{ match_nomatch }}",
                            "name": "{{name}}",
                        },
                    ],
                },
            },
        },
        {
            "name": "correlator.buffer_size",
            "getval": re.compile(
                r"""
                ^logging\scorrelator
                (\sbuffer-size\s(?P<buffer_size>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "logging correlator buffer-size {{correlator.buffer_size }}",
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
                ^logging\scorrelator
                (\srule\s(?P<name>\S+))?
                (\stype\s(?P<rule_type>\S+))?
                (\s+reissue-nonbistate(?P<reissue_nonbistate>))?
                (\s+timeout\s(?P<timeout>\S+))?
                (\s+reparent(?P<reparent>))?
                (\s+context-correlation(?P<context_correlation>))?
                (\s+timeout-rootcause\s(?P<timeout_rootcause>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": tmplt_correlator_rule,
            "result": {
                "correlator": {
                    "rules": {
                        "{{name}}": {
                            "rule_name": "{{ name }}",
                            "rule_type": "{{ rule_type }}",
                            "reissue_nonbistate": "{{ True if reissue_nonbistate is defined }}",
                            "timeout": "{{ timeout }}",
                            "reparent": "{{ True if reparent is defined }}",
                            "context_correlation": "{{ True if context_correlation is defined }}",
                            "timeout_rootcause": "{{ timeout_rootcause }}",

                        },
                    },
                },
            },
        },
        {
            "name": "correlator.rule_sets",
            "getval": re.compile(
                r"""
                ^logging\scorrelator\sruleset\s(?P<name>\S+)
                (\srulename\s(?P<rulename>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": tmplt_correlator_ruleset,
            "result": {
                "correlator": {
                    "rule_sets": {
                        "{{name}}": {
                            "name": "{{ name }}",
                            "rulename": ["{{ rulename }}"],

                        },
                    },
                },
            },
        },
        {
            "name": "events.threshold",
            "getval": re.compile(
                r"""
                ^logging\sevents
                (\sthreshold\s(?P<threshold>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "logging events threshold {{events.threshold}}",
            "result": {
                "events":
                    {"threshold": "{{ threshold }}"},
            },

        },
        {
            "name": "events.buffer_size",
            "getval": re.compile(
                r"""
                ^logging\sevents
                (\sbuffer-size\s(?P<buffer_size>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "logging events buffer-size {{events.buffer_size}}",
            "result": {
                "events": {"buffer_size": "{{ buffer_size }}"},
            },

        },
        {
            "name": "events.display_location",
            "getval": re.compile(
                r"""
                ^logging\sevents
                (\sdisplay-location(?P<display_location>))?
                $""", re.VERBOSE,
            ),
            "setval": "logging events display-location",
            "result": {
                "events":
                    {
                        "display_location": "{{ True if display_location is defined }}",

                    },

            },
        },
        {
            "name": "events.filter_match",
            "getval": re.compile(
                r"""
                ^logging\sevents\sfilter
                (\s+match\s(?P<match>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "logging events filter match {{match}}",
            "result": {
                "events": {
                    "filter_match": [
                        "{{ match }}",
                    ],
                },
            },
        },
        {
            "name": "events.severity",
            "getval": re.compile(
                r"""
                ^logging\sevents
                (\slevel\s(?P<severity>alerts|critical|debugging|emergencies|errors|informational|notifications|warnings))?
                $""", re.VERBOSE,
            ),
            "setval": "logging events level {{events.severity}}",
            "result": {
                "events":
                    {
                        "severity": "{{ severity }}",

                    },
            },
        },
        {
            "name": "files",
            "getval": re.compile(
                r"""
                ^logging
                (\sfile\s(?P<file>\S+))?
                (\spath\s(?P<path>\S+))?
                (\smaxfilesize\s(?P<maxfilesize>\S+))?
                (\sseverity\s(?P<severity>alerts|critical|debugging|emergencies|errors|info|notifications|warning))?
                $""", re.VERBOSE,
            ),
            "setval": tmplt_files,
            "result": {
                "files": [
                    {
                        "name": "{{file}}",
                        "path": "{{path}}",
                        "maxfilesize": "{{maxfilesize}}",
                        "severity": "{{ severity  }}",

                    },
                ],
            },
        },
        {
            "name": "facility",
            "getval": re.compile(
                r"""
                ^logging\sfacility
                \s(?P<facility>auth|cron|daemon|kern|local0|local1|local2|local3|local4|local5|local6|local7|lpr|mail|news|sys10|sys11|sys12|sys13|sys14|sys9|syslog|user|uucp)
                $""", re.VERBOSE,
            ),
            "setval": "logging facility {{ facility }}",
            "result": {
                "facility": "{{ facility }}",
            },
        },
        {
            "name": "format",
            "getval": re.compile(
                r"""
                ^logging\sformat
                (\srfc5424(?P<format>))
                $""", re.VERBOSE,
            ),
            "setval": "logging format rfc5424",
            "result": {
                "format": "{{True if format is defined}}",
            },
        },
        {
            "name": "hostnameprefix",
            "getval": re.compile(
                r"""
                ^logging
                (\shostnameprefix\s(?P<hostnameprefix>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "logging hostnameprefix {{hostnameprefix}}",
            "result": {
                "hostnameprefix": "{{hostnameprefix}}",
            },
        },
        {
            "name": "ipv4.dscp",
            "getval": re.compile(
                r"""
                ^logging
                \sipv4\sdscp\s(?P<dscp>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "logging ipv4 dscp {{ipv4.dscp}}",
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
                ^logging
                (\sipv6\sdscp\s(?P<dscp>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "logging ipv6 dscp {{ipv6.dscp}}",
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
                ^logging
                (\sipv4\sprecedence\s(?P<precedence>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "logging ipv4 precedence {{ipv4.precedence}}",
            "result": {
                "ipv4": {"precedence": "{{precedence}}"},
            },
        },
        {
            "name": "ipv6.precedence",
            "getval": re.compile(
                r"""
                ^logging
                (\sipv6\sprecedence\s(?P<precedence>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "logging ipv6 precedence {{ipv6.precedence}}",
            "result": {
                "ipv6": {"precedence": "{{precedence}}"},
            },
        },
        {
            "name": "localfilesize",
            "getval": re.compile(
                r"""
                ^logging
                (\slocalfilesize\s(?P<localfilesize>\S+))
                $""", re.VERBOSE,
            ),
            "setval": "logging localfilesize {{localfilesize}}",
            "result": {
                "localfilesize": "{{localfilesize}}",
            },
        },
        {
            "name": "suppress.duplicates",
            "getval": re.compile(
                r"""
                ^logging
                (\ssuppress\sduplicates(?P<suppress_duplicates>))
                $""", re.VERBOSE,
            ),
            "setval": "logging suppress duplicates",
            "result": {
                "suppress":
                    {"duplicates": "{{True if suppress_duplicates is defined}}"},
            },
        },
        {
            "name": "suppress.apply_rule",
            "getval": re.compile(
                r"""
                ^logging\ssuppress\sapply\srule\s(?P<apply_rules>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "logging suppress apply rule {{suppress.apply_rule}}",
            "result": {
                "suppress": {"apply_rule": "{{apply_rules}}"},
            },
        },
        {
            "name": "history.size",
            "getval": re.compile(
                r"""
                ^logging\shistory
                (\ssize\s(?P<size>\d+))
                $""", re.VERBOSE,
            ),
            "setval": "logging history size {{history.size}}",
            "result": {
                "history": {
                    "severity": "{{ severity }}",
                    "size": "{{ size }}",
                },
            },
        },
        {
            "name": "history.severity",
            "getval": re.compile(
                r"""
                ^logging\shistory
                (\s(?P<severity>alerts|critical|debugging|emergencies|errors|informational|notifications|warning))
                $""", re.VERBOSE,
            ),
            "setval": "logging history {{history.severity}}",
            "result": {
                "history": {
                    "severity": "{{ severity }}",
                },
            },
        },
        {
            "name": "history.state",
            "getval": re.compile(
                r"""
                ^logging\shistory
                \s(?P<disable>disable)
                $""", re.VERBOSE,
            ),
            "setval": "{{ 'logging history disable' if history.state =='disabled' else 'no logging history disable' }}",
            "result": {
                "history": {
                    "state": "{{ 'disabled' if disable is defined }}",
                },
            },
        },
        {
            "name": "monitor.severity",
            "getval": re.compile(
                r"""
                ^logging\smonitor
                (\s(?P<severity>alerts|critical|debugging|emergencies|errors|informational|notifications|warning))?
                $""", re.VERBOSE,
            ),
            "setval": "logging monitor {{monitor.severity}}",
            "result": {
                "monitor": {
                    "severity": "{{ severity }}",
                },
            },
        },
        {
            "name": "monitor.state",
            "getval": re.compile(
                r"""
                ^logging\smonitor\s(?P<disable>disable)
                $""", re.VERBOSE,
            ),
            "setval": "{{ 'logging monitor disable' if monitor.state =='disabled' else 'no logging monitor disable' }}",
            "result": {
                "monitor": {
                    "state": "{{ 'disabled' if disable is defined }}",
                },
            },
        },
        {
            "name": "monitor.discriminator",
            "getval": re.compile(
                r"""
                ^logging\smonitor\sdiscriminator
                \s+(?P<match_nomatch>\S+)\s(?P<name>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "logging monitor discriminator {{match_params}} {{name}}",
            "result": {
                "monitor": {
                    "discriminator": [
                        {
                            "match_params": "{{ match_nomatch }}",
                            "name": "{{name}}",
                        },
                    ],
                },

            },
        },
        {
            "name": "source_interfaces",
            "getval": re.compile(
                r"""
                ^logging\ssource-interface
                (\s(?P<interface>\S+))?
                (\svrf\s(?P<vrf>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": tmplt_source_interface,
            "result": {
                "source_interfaces": [
                    {
                        "interface": "{{ interface }}",
                        "vrf": "{{ vrf }}",
                    },
                ],
            },
        },
        {
            "name": "trap.severity",
            "getval": re.compile(
                r"""
                ^logging\strap
                \s(?P<severity>alerts|critical|debugging|emergencies|errors|informational|notifications|warning)
                $""", re.VERBOSE,
            ),
            "setval": "logging trap {{ trap.severity }}",
            "result": {
                "trap": {
                    "severity": "{{ severity }}",
                },
            },
        },
        {
            "name": "trap.state",
            "getval": re.compile(
                r"""
                ^logging\strap
                \s(?P<disable>disable)
                $""", re.VERBOSE,
            ),
            "setval": "{{ 'logging trap disable' if trap.state =='disabled' else 'no logging trap disable' }}",
            "result": {
                "trap": {
                    "state": "{{ 'disabled' if disable is defined }}",
                },
            },
        },
        {
            "name": "tls_servers",
            "getval": re.compile(
                r"""
                ^logging\stls-server\s(?P<name>\S+)
                (\s+vrf\s(?P<vrf>\S+))?
                (\s+trustpoint\s(?P<trustpoint>\S+))?
                (\s+tls-hostname\s(?P<tls_hostname>\S+))?
                (\s(?P<severity>alerts|critical|debugging|emergencies|errors|informational|notifications|warnings))?
                $""", re.VERBOSE,
            ),
            "setval": tmplt_tls_servers,
            "remval": rem_tmplt_tls_servers,
            "result": {
                "tls_servers": {
                    "{{name}}": {
                        "name": "{{ name }}",
                        "trustpoint": "{{trustpoint}}",
                        "vrf": "{{vrf}}",
                        "severity": "{{severity}}",
                        "tls_hostname": "{{tls_hostname}}",
                    },
                },
            },
        },
    ]
    # fmt: on
