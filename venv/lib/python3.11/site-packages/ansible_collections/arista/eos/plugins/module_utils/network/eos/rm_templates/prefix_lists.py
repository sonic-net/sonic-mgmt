# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The Prefix_lists parser templates file. This contains
a list of parser definitions and associated functions that
facilitates both facts gathering and native command generation for
the given network resource.
"""

import re

from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


# diable no-self-use
# pylint: disable=R0201
# pylint: disable=W0642
# pylint: disable=no-self-argument


class Prefix_listsTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(Prefix_listsTemplate, self).__init__(
            lines=lines,
            tmplt=self,
            module=module,
        )

    def _tmplt_prefix_list_ip(config_data):
        command_set = []
        config_data = config_data["prefix_lists"].get("entries", {})
        for k, v in iteritems(config_data):
            command = ""
            if k != "seq":
                command = "seq " + str(k) + " {action} {address}".format(**v)
            else:
                command = "{action} {address}".format(**v)
            if "match" in v:
                command += " {operator} {masklen}".format(**v["match"])
            if command:
                command_set.append(command)

        return command_set

    def _tmplt_prefix_list_ip_del(config_data):
        command_set = []
        config_data = config_data["prefix_lists"].get("entries", {})
        for k, v in iteritems(config_data):
            command_set.append("seq " + str(k))

        return command_set

    def _tmplt_prefix_list_resequence(config_data):
        command = "resequence"
        config_data = config_data["prefix_lists"].get("entries", {})
        for k, v in iteritems(config_data):
            if v["resequence"].get("start_seq"):
                command += " " + str(v["resequence"]["start_seq"])
            if v["resequence"].get("step"):
                command += " " + str(v["resequence"]["step"])

        return command

    # fmt: off
    PARSERS = [
        {
            "name": "prefixlist.name",
            "getval": re.compile(
                r"""
                ^(?P<afi>ip|ipv6)\sprefix-list\s(?P<name>\S+)
                *$""",
                re.VERBOSE,
            ),
            "setval": '{{ "ip" if afi == "ipv4" else afi }} prefix-list {{ prefix_lists.name }}',
            "compval": "prefix_lists",
            "result": {
                '{{ afi  }}': {
                    "afi": '{{ "ipv4" if afi == "ip" else afi }}',
                    "prefix_lists": {
                        "{{ name }}": {
                            "name": "{{ name }}",
                        },
                    },
                },
            },
            "shared": True,
        },
        {
            "name": "prefixlist.entry",
            "getval": re.compile(
                r"""
                \s*seq
                \s(?P<num>\d+)
                \s+(?P<action>permit|deny)
                \s+(?P<ip>\S+)
                \s*(?P<oper>eq|ge|le)*
                \s*(?P<len>\d+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_prefix_list_ip,
            "remval": _tmplt_prefix_list_ip_del,
            "compval": "prefix_lists",
            "result": {
                "{{ afi }}": {
                    "prefix_lists": {
                        "{{ name }}": {
                            "entries": {
                                '{{ num|d("seq") }}': {
                                    "sequence": "{{ num }}",
                                    "action": "{{ action }}",
                                    "address": "{{ ip }}",
                                    "match": {
                                        "operator": "{{ oper }}",
                                        "masklen": "{{ len }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        {
            "name": "prefixlist.resequence",
            "getval": re.compile(
                r"""
                \s*resequence
                \s*(?P<start>\d+)*
                \*(?P<step>\d+)*
                $""",
                re.VERBOSE,
            ),
            "setval": _tmplt_prefix_list_resequence,
            "compval": "prefix_lists",
            "result": {
                "{{ afi }}": {
                    "prefix_lists": {
                        "{{ name }}": {
                            "entries": {
                                '{{ num|d("seq") }}': {
                                    "resequence": {
                                        "default": "{{ True if start_seq is undefined and step is undefined }}",
                                        "start_seq": "{{ start }}",
                                        "step": "{{ step }}",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    ]
    # fmt: on
