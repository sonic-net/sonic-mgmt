# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The Vrf_global parser templates file. This contains
a list of parser definitions and associated functions that
facilitates both facts gathering and native command generation for
the given network resource.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


class Vrf_globalTemplate(NetworkTemplate):
    def __init__(self, lines=None, module=None):
        super(Vrf_globalTemplate, self).__init__(lines=lines, tmplt=self, module=module)

    # fmt: off
    PARSERS = [
        {
            "name": "name",
            "getval": re.compile(
                r"""
                ^vrf\sinstance
                (\s(?P<name>\S+))?
                $""", re.VERBOSE,
            ),
            "setval": "vrf instance {{ name }}",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                },
            },
            "shared": True,
        },
        {
            "name": "description",
            "getval": re.compile(
                r"""
                \s+description\s(?P<description>.+$)
                $""", re.VERBOSE,
            ),
            "setval": "description {{ description }}",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                    'description': '{{ description }}',
                },
            },
        },
        {
            "name": "rd",
            "getval": re.compile(
                r"""
                \s+rd\s(?P<rd>\S+)
                $""", re.VERBOSE,
            ),
            "setval": "rd {{ rd }}",
            "compval": "rd",
            "result": {
                '{{ name }}': {
                    'name': '{{ name }}',
                    "rd": "{{ rd }}",
                },
            },
        },
    ]
    # fmt: on
