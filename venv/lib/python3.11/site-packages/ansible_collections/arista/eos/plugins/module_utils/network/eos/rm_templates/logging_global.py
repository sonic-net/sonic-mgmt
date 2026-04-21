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


def _tmplt_logging_format(config_data):
    command = ""
    if "hostname" in config_data["format"]:
        command = "logging format hostname " + config_data["format"]["hostname"]
    if "sequence_numbers" in config_data["format"]:
        command = "logging format sequence-numbers"
    return command


def _tmplt_logging_synchronous(config_data):
    command = "logging synchronous"
    if "level" in config_data["synchronous"]:
        command += " level " + config_data["synchronous"]["level"]
    return command


def _tmplt_logging_trap(config_data):
    command = "logging trap"
    if "severity" in config_data["trap"]:
        command += " " + config_data["trap"]["severity"]
    return command


def _tmplt_logging_global_hosts(config_data):
    el = config_data["hosts"]
    command = "logging host " + el["name"]
    if el.get("add"):
        command += " add"
    if el.get("remove"):
        command += " remove"
    if el.get("port", 514):
        command += " " + str(el["port"])
    if el.get("protocol"):
        command += " protocol " + el["protocol"]
    return command


def _tmplt_logging_global_vrf_hosts(config_data):
    el = config_data["vrfs"]
    command = "logging vrf " + el["name"] + " host "
    el = el["hosts"]
    command += el["name"]
    if el.get("add"):
        command += " add"
    if el.get("remove"):
        command += " remove"
    if el.get("port", 514):
        command += " " + str(el["port"])
    if el.get("protocol"):
        command += " protocol " + el["protocol"]
    return command


def _tmplt_logging_global_format_timestamp(config_data):
    command = ""
    el = config_data["format"]["timestamp"]
    if el.get("traditional"):
        command = "logging format timestamp traditional"
        if el["traditional"].get("year"):
            if el["traditional"]["year"]:
                command += " year"
        if el["traditional"].get("timezone"):
            if el["traditional"]["timezone"]:
                command += " timezone"
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
            "name": "buffered",
            "getval": re.compile(
                r"""
                \s*logging\sbuffered
                \s*(?P<size>\d{2,})*
                \s*(?P<sev>[0-7]|\w+)*
                $""",
                re.VERBOSE,
            ),
            "setval": 'logging buffered {{ buffered.buffer_size if buffered.buffer_size is defined }}'
                      ' {{ buffered.severity if buffered.severity is defined }}',
            "result": {
                "buffered": {
                    "buffer_size": "{{ size }}",
                    "severity": "{{ sev }}",
                },
            },
        },
        {
            "name": "console",
            "getval": re.compile(
                r"""
                \s*logging\sconsole
                \s*(?P<sev>[0-7]|\w+)*
                $""",
                re.VERBOSE,
            ),
            "setval": "logging console {{ console.severity|string if console.severity is defined else ''}}",
            "result": {
                "console": {
                    "severity": "{{ sev }}",
                },
            },
        },
        {
            "name": "event",
            "getval": re.compile(
                r"""
                \s*logging\sevent
                \s+(?P<event>link-status|port-channel|spanning-tree)
                \s*(member-status)*
                \s*global
                *$""",
                re.VERBOSE,
            ),
            "setval": "logging event {{ event }} {{ 'member-status' if event == 'port-channel' else '' }} global",
            "result": {
                "event": "{{ event }}",
            },
        },
        {
            "name": "facility",
            "getval": re.compile(
                r"""
                \s*logging\sfacility
                \s(?P<facility>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": 'logging facility {{ facility }}',
            "result": {
                "facility": "{{ facility }}",
            },
        },
        {
            "name": "format",
            "getval": re.compile(
                r"""
                \s*logging\sformat
                \s*(?P<param>hostname\s\S+|sequence-numbers)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_logging_format,
            "shared": True,
            "result": {
                "format": {
                    "hostname": '{{ param.split(" ")[1] if "hostname" in param }}',
                    "sequence_numbers": '{{ True if "sequence-numbers" in param }}',
                },
            },
        },
        {
            "name": "format.timestamp.highresolution",
            "getval": re.compile(
                r"""
                \s*logging\sformat\stimestamp\shigh-resolution
                *$""",
                re.VERBOSE,
            ),
            "setval": 'logging format timestamp high-resolution',
            "shared": True,
            "compval": "format.timestamp.high_resolution",
            "result": {
                "format": {
                    "timestamp": {
                        "high_resolution": "{{ True }}",
                    },
                },
            },
        },
        {
            "name": "format.timestamp.traditional",
            "getval": re.compile(
                r"""
                \s*logging\sformat\stimestamp\straditional
                \s*(?P<year>year)*
                \s*(?P<zone>timezone)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_logging_global_format_timestamp,
            "compval": "format.timestamp.traditional",
            "shared": True,
            "result": {
                "format": {
                    "timestamp": {
                        "traditional": {
                            "year": "{{ True if year is defined}}",
                            "timezone": "{{ True if zone is defined}}",
                            "state": "{{ enabled if year and zone is undefined}}",
                        },
                    },
                },
            },
        },
        {
            "name": "host",
            "getval": re.compile(
                r"""
                \s*logging\shost
                \s*(?P<name>\S+)
                \s*(?P<oper>add|remove)*
                \s*(?P<port>\d+)*
                \s*(protocol)*
                \s*(?P<proto>tcp|udp)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_logging_global_hosts,
            "compval": "hosts",
            "result": {
                "hosts": {
                    "{{ name }}": {
                        "name": "{{ name }}",
                        "add": '{{ True if oper == "add" }}',
                        "remove": '{{ True if oper == "remove" }}',
                        "port": "{{ port  or 514 }}",
                        "protocol": "{{ proto }}",
                    },
                },
            },
        },
        {
            "name": "level",
            "getval": re.compile(
                r"""
                \s*logging\slevel
                \s(?P<level>\S+)
                \s(?P<sev>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": 'logging level {{ level.facility }} {{ level.severity }}',
            "result": {
                "level": {
                    "facility": "{{ level }}",
                    "severity": "{{ sev }}",
                },
            },
        },
        {
            "name": "monitor",
            "getval": re.compile(
                r"""
                \s*logging\smonitor
                \s(?P<val>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": 'logging monitor {{ val }}',
            "result": {
                "monitor": "{{ val }}",
            },
        },
        {
            "name": "on",
            "getval": re.compile(
                r"""
                \s*logging\son
                *$""",
                re.VERBOSE,
            ),
            "setval": 'logging on',
            "compval": 'turn_on',
            "result": {
                "turn_on": "{{ True }}",
            },
        },
        {
            "name": "persistent",
            "getval": re.compile(
                r"""
                \s*logging\spersistent
                \s*(?P<size>\d+)*
                $""",
                re.VERBOSE,
            ),
            "setval": "logging persistent{{ ' ' + persistent.size|string if persistent.size is defined }}",
            "result": {
                "persistent": {
                    "size": "{{ size }}",
                    "set": '{{ True if size is not defined }}',
                },
            },
        },
        {
            "name": "policy",
            "getval": re.compile(
                r"""
                \s*logging\spolicy\smatch
                \s*(?P<inv>inverse-result)*
                \s+match-list
                \s+(?P<match>\S+)
                \s+discard
                $""",
                re.VERBOSE,
            ),
            "setval": "logging policy match {{ 'invert-result' if policy.invert_result is defined }} match-list {{ policy.match_list }} discard",
            "result": {
                "policy": {
                    "invert_result": "{{ True if inv is defined }}",
                    "match_list": '{{ match }}',
                },
            },
        },
        {
            "name": "relogging_interval",
            "getval": re.compile(
                r"""
                \s*logging\srelogging-interval
                \s(?P<val>\d+)
                *$""",
                re.VERBOSE,
            ),
            "setval": 'logging relogging-interval {{ relogging_interval }}',
            "result": {
                "relogging_interval": "{{ val }}",
            },
        },
        {
            "name": "repeat_messages",
            "getval": re.compile(
                r"""
                \s*logging\srepeat-messages
                *$""",
                re.VERBOSE,
            ),
            "setval": 'logging repeat-messages',
            "result": {
                "repeat_messages": "{{ True }}",
            },
        },
        {
            "name": "src_interface",
            "getval": re.compile(
                r"""
                \s*logging\ssource-interface
                \s(?P<val>.+)
                *$""",
                re.VERBOSE,
            ),
            "setval": 'logging source-interface {{ source_interface }}',
            "compval": "source_interface",
            "result": {
                "source_interface": "{{ val }}",
            },
        },
        {
            "name": "synchronous",
            "getval": re.compile(
                r"""
                \s*logging\ssynchronous
                \s*(?P<level>level\s\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_logging_synchronous,
            "result": {
                "synchronous": {
                    "set": "{{ True if level is not defined }}",
                    "level": '{{ level.split(" ")[1] if level is defined }}',
                },
            },
        },
        {
            "name": "trap",
            "getval": re.compile(
                r"""
                \s*logging\strap
                \s*(?P<level>\S+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_logging_trap,
            "result": {
                "trap": {
                    "set": "{{ True if level is not defined }}",
                    "severity": "{{ level }}",
                },
            },
        },
        {
            "name": "vrf.host",
            "getval": re.compile(
                r"""
                \s*logging\svrf
                \s+(?P<vrf>\S+)
                \s+host
                \s(?P<name>\S+)
                \s*(?P<oper>add|remove)*
                \s*(?P<port>\d+)*
                \s*(protocol)*
                \s*(?P<proto>tcp|udp)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_logging_global_vrf_hosts,
            "compval": "vrfs.hosts",
            "shared": True,
            "result": {
                "vrfs": {
                    "{{ vrf }}": {
                        "name": "{{ vrf }}",
                        "hosts": {
                            "{{ name }}": {
                                "name": "{{ name }}",
                                "add": '{{ True if oper == "add" }}',
                                "remove": '{{ True if oper == "remove" }}',
                                "port": "{{ port or 514 }}",
                                "protocol": "{{ proto }}",
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "vrf.source_interface",
            "getval": re.compile(
                r"""
                \s*logging\svrf
                \s+(?P<vrf>\S+)
                \s+source-interface
                \s(?P<val>.+)
                *$""",
                re.VERBOSE,
            ),
            "setval": 'logging vrf {{ vrfs.name }} source-interface {{ vrfs.source_interface }}',
            "compval": "vrfs.source_interface",
            "shared": True,
            "result": {
                "vrfs": {
                    "{{ vrf }}": {
                        "name": "{{ vrf }}",
                        "source_interface": "{{ val }}",
                    },
                },
            },
        },
    ]
    # fmt: on
