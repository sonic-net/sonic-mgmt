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
        super(Prefix_listsTemplate, self).__init__(lines=lines, tmplt=self, module=module)

    # fmt: off
    PARSERS = [
        {
            "name": "entry",
            "getval": re.compile(
                r"""
                ^(?P<afi>ip|ipv6)
                \sprefix-list
                \s(?P<name>\S+)
                \sseq\s(?P<sequence>\d+)
                \s(?P<action>permit|deny)
                \s(?P<prefix>\S+)
                (\seq\s(?P<eq>\d+))?
                (\sge\s(?P<ge>\d+))?
                (\sle\s(?P<le>\d+))?
                (\smask\s(?P<mask>\S+))?
                \s*
                $""", re.VERBOSE,
            ),
            "setval": "{{ 'ip' if afi == 'ipv4' else afi }} prefix-list {{ name }}"
                      "{{ (' seq ' + sequence|string) if sequence|d('') else '' }}"
                      " {{ action }}"
                      " {{ prefix }}"
                      "{{ (' eq ' + eq|string) if eq|d('') else '' }}"
                      "{{ (' ge ' + ge|string) if ge|d('') else '' }}"
                      "{{ (' le ' + le|string) if le|d('') else '' }}"
                      "{{ (' mask ' + mask) if mask|d('') else '' }}",
            "result": {
                "{{ 'ipv4' if afi == 'ip' else 'ipv6' }}": {
                    "afi": "{{ 'ipv4' if afi == 'ip' else 'ipv6' }}",
                    "prefix_lists": {
                        "{{ name }}": {
                            "name": "{{ name }}",
                            "entries": [
                                {
                                    "sequence": "{{ sequence|d(None) }}",
                                    "action": "{{ action }}",
                                    "prefix": "{{ prefix }}",
                                    "eq": "{{ eq }}",
                                    "ge": "{{ ge }}",
                                    "le": "{{ le }}",
                                    "mask": "{{ mask }}",
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
                ^(?P<afi>ip|ipv6)
                \sprefix-list
                \s(?P<name>\S+)
                \sdescription\s(?P<description>.+)\s*
                $""", re.VERBOSE,
            ),
            "setval": "{{ 'ip' if afi == 'ipv4' else afi }} prefix-list {{ name }} description {{ description }}",
            "result": {
                "{{ 'ipv4' if afi == 'ip' else 'ipv6' }}": {
                    "afi": "{{ 'ipv4' if afi == 'ip' else 'ipv6' }}",
                    "prefix_lists": {
                        "{{ name }}": {
                            "name": "{{ name }}",
                            "description": "{{ description }}",
                        },
                    },
                },
            },
        },
    ]
    # fmt: on
