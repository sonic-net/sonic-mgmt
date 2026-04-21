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

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


class Prefix_listsTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(Prefix_listsTemplate, self).__init__(
            lines=lines,
            tmplt=self,
            module=module,
        )

    # fmt: off
    PARSERS = [
        {
            "name": "prefix_list",
            "getval": re.compile(
                r"""
                        (?P<afi>^(ipv4|ipv6))
                        \sprefix-list\s(?P<name>\S+)
                        $""",
                re.VERBOSE,
            ),
            "setval": "{{afi}} prefix-list {{name}}",
            "result": {
                "{{ afi }}": {
                    "afi": "{{ afi }}",
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
            "name": "prefix",
            "getval": re.compile(
                r"""
                        \s(?P<sequence>\d+)
                        \s(?P<action>deny|permit)
                        \s(?P<prefix>\S+)
                        (\seq\s(?P<eq>\d+))?
                        (\sge\s(?P<ge>\d+))?
                        (\sle\s(?P<le>\d+))?
                        $""",
                re.VERBOSE,
            ),
            "setval": "{{afi}} prefix-list {{name}} {{sequence}} {{action}} {{prefix}}"
                      "{{ (' eq ' + eq|string) if eq|d('') else '' }}"
                      "{{ (' ge ' + ge|string) if ge|d('') else '' }}"
                      "{{ (' le ' + le|string) if le|d('') else '' }}",
            "result": {
                "{{ afi |d()}}": {
                    "afi": "{{ afi|d() }}",
                    "prefix_lists": {
                        "{{ name|d() }}": {
                            "name": "{{ name|d()}}",
                            "entries": [
                                {
                                    "sequence": "{{ sequence|d(None) }}",
                                    "action": "{{ action }}",
                                    "prefix": "{{ prefix }}",
                                    "eq": "{{ eq }}",
                                    "ge": "{{ ge }}",
                                    "le": "{{ le }}",
                                },
                            ],
                        },
                    },
                },
            },
        },
        {
            "name": "description",
            "getval": re.compile(
                r"""
                        \s(?P<sequence>\d+)
                        \s(?P<action>remark)
                        \s(?P<desc>\S+)
                        $""",
                re.VERBOSE,
            ),
            "setval": "{{afi}} prefix-list {{name}} {{sequence}} {{action}} {{description}}",
            "result": {
                "{{ afi|d() }}": {
                    "afi": "{{ afi|d() }}",
                    "prefix_lists": {
                        "{{ name|d() }}": {
                            "name": "{{ name|d() }}",
                            "entries": [
                                {
                                    "sequence": "{{ sequence|d(None) }}",
                                    "action": "{{ action }}",
                                    "description": "{{ desc }}",
                                },
                            ],
                        },
                    },
                },
            },
        },

    ]
    # fmt: on
